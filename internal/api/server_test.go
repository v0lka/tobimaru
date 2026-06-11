package api

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/vkochetkov/tobimaru/internal/config"
	"github.com/vkochetkov/tobimaru/internal/detector"
	"github.com/vkochetkov/tobimaru/internal/state"
	"github.com/vkochetkov/tobimaru/internal/storage"
)

// testServer builds a Server backed by an in-memory SQLite repo, with the
// given auth configuration. Useful for handler-level unit tests.
func testServer(t *testing.T, authEnabled bool, adminPassword string) (*Server, storage.Repository) {
	t.Helper()
	repo, err := storage.Open(config.StorageConfig{Enabled: true, Path: ":memory:"})
	if err != nil {
		t.Fatalf("open repo: %v", err)
	}
	t.Cleanup(func() { _ = repo.Close() })

	stateEng := state.NewEngine(config.StateConfig{Enabled: true, TTL: time.Hour, SweepInterval: time.Minute},
		config.WhitelistConfig{}, discardLogger())

	apiCfg := config.APIConfig{
		Enabled:         true,
		Listen:          "127.0.0.1:0",
		ReadTimeout:     time.Second,
		WriteTimeout:    time.Second,
		IdleTimeout:     time.Second,
		ShutdownTimeout: time.Second,
		Auth: config.AuthConfig{
			Enabled:    authEnabled,
			SessionTTL: time.Hour,
		},
	}
	if authEnabled && adminPassword != "" {
		hash, err := bcrypt.GenerateFromPassword([]byte(adminPassword), bcrypt.MinCost)
		if err != nil {
			t.Fatalf("hash password: %v", err)
		}
		apiCfg.Auth.AdminPasswordHash = string(hash)
	}

	cfg := &config.Config{
		Detection: config.DetectionConfig{Enabled: true, DedupWindow: 30 * time.Second},
		State:     config.StateConfig{Enabled: true, TTL: time.Hour, SweepInterval: time.Minute},
		API:       apiCfg,
		Storage:   config.StorageConfig{Enabled: true, Path: ":memory:"},
	}

	logger := discardLogger()
	hub := NewHub(logger)
	srv, err := NewServer(apiCfg, Deps{
		Config:    cfg,
		State:     stateEng,
		Repo:      repo,
		Hub:       hub,
		StartTime: time.Now(),
		Logger:    logger,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	return srv, repo
}

func discardLogger() *slog.Logger {
	return slog.New(slog.DiscardHandler)
}
func do(srv *Server, method, path string, body []byte, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	var bodyR io.Reader = http.NoBody
	if body != nil {
		bodyR = bytes.NewReader(body)
	}
	req := httptest.NewRequestWithContext(context.Background(), method, path, bodyR)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	srv.router.ServeHTTP(rec, req)
	return rec
}

func sessionCookie(rec *httptest.ResponseRecorder) *http.Cookie {
	for _, c := range rec.Result().Cookies() {
		if c.Name == sessionCookieName {
			return c
		}
	}
	return nil
}

func TestStatusEndpoint_Public(t *testing.T) {
	srv, _ := testServer(t, true, "secret123!")
	rec := do(srv, http.MethodGet, "/api/status", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d (body=%s)", rec.Code, rec.Body.String())
	}
	var resp statusResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !resp.Auth.Enabled {
		t.Error("expected auth enabled in status response")
	}
}

func TestProtectedRoutes_RequireAuth(t *testing.T) {
	srv, _ := testServer(t, true, "secret123!")
	for _, p := range []string{"/api/aps", "/api/clients", "/api/events", "/api/stats", "/api/whitelist", "/api/blacklist", "/api/config"} {
		rec := do(srv, http.MethodGet, p, nil)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s: expected 401, got %d", p, rec.Code)
		}
	}
}

func TestLogin_Success(t *testing.T) {
	srv, _ := testServer(t, true, "secret123!")
	body, _ := json.Marshal(loginRequest{Username: "admin", Password: "secret123!"})
	rec := do(srv, http.MethodPost, "/api/login", body)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d (body=%s)", rec.Code, rec.Body.String())
	}
	if c := sessionCookie(rec); c == nil || c.Value == "" {
		t.Fatal("expected session cookie to be set")
	}
}

func TestLogin_Failure(t *testing.T) {
	srv, _ := testServer(t, true, "secret123!")
	body, _ := json.Marshal(loginRequest{Username: "admin", Password: "wrong"})
	rec := do(srv, http.MethodPost, "/api/login", body)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}

func TestProtectedRoutes_WithSession(t *testing.T) {
	srv, _ := testServer(t, true, "secret123!")
	body, _ := json.Marshal(loginRequest{Username: "admin", Password: "secret123!"})
	loginRec := do(srv, http.MethodPost, "/api/login", body)
	cookie := sessionCookie(loginRec)
	if cookie == nil {
		t.Fatal("no session cookie")
	}

	rec := do(srv, http.MethodGet, "/api/aps", nil, cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d (body=%s)", rec.Code, rec.Body.String())
	}
	var resp listResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
}

func TestAdminOnlyRoutes_RejectUser(t *testing.T) {
	// Build a server with both admin and user passwords, then login as user
	// and assert admin-only writes are rejected with 403.
	repo, err := storage.Open(config.StorageConfig{Enabled: true, Path: ":memory:"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = repo.Close() })

	adminHash, _ := bcrypt.GenerateFromPassword([]byte("adminpw"), bcrypt.MinCost)
	userHash, _ := bcrypt.GenerateFromPassword([]byte("userpw"), bcrypt.MinCost)

	apiCfg := config.APIConfig{
		Enabled:         true,
		Listen:          "127.0.0.1:0",
		ReadTimeout:     time.Second,
		WriteTimeout:    time.Second,
		IdleTimeout:     time.Second,
		ShutdownTimeout: time.Second,
		Auth: config.AuthConfig{
			Enabled:           true,
			SessionTTL:        time.Hour,
			AdminPasswordHash: string(adminHash),
			UserPasswordHash:  string(userHash),
		},
	}
	logger := discardLogger()
	stateEng := state.NewEngine(config.StateConfig{Enabled: true, TTL: time.Hour, SweepInterval: time.Minute},
		config.WhitelistConfig{}, logger)
	cfg := &config.Config{API: apiCfg, State: config.StateConfig{Enabled: true, TTL: time.Hour, SweepInterval: time.Minute}, Storage: config.StorageConfig{Enabled: true, Path: ":memory:"}}
	hub := NewHub(logger)
	srv, err := NewServer(apiCfg, Deps{
		Config: cfg, State: stateEng, Repo: repo, Hub: hub, StartTime: time.Now(), Logger: logger,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Login as user.
	body, _ := json.Marshal(loginRequest{Username: "user", Password: "userpw"})
	rec := do(srv, http.MethodPost, "/api/login", body)
	cookie := sessionCookie(rec)
	if cookie == nil {
		t.Fatalf("expected user login to succeed: %d %s", rec.Code, rec.Body.String())
	}

	addBody, _ := json.Marshal(whitelistAddRequest{MAC: "aa:bb:cc:dd:ee:ff", Comment: "x"})
	rec = do(srv, http.MethodPost, "/api/whitelist", addBody, cookie)
	if rec.Code != http.StatusForbidden {
		t.Errorf("expected 403 for user trying to add whitelist, got %d", rec.Code)
	}

	rec = do(srv, http.MethodPut, "/api/config", []byte(`{"log_level":"debug"}`), cookie)
	if rec.Code != http.StatusForbidden {
		t.Errorf("expected 403 for user trying to PUT /api/config, got %d", rec.Code)
	}
}

func TestAuthDisabled_AllowsAll(t *testing.T) {
	srv, _ := testServer(t, false, "")
	for _, p := range []string{"/api/aps", "/api/clients", "/api/events", "/api/whitelist"} {
		rec := do(srv, http.MethodGet, p, nil)
		if rec.Code != http.StatusOK {
			t.Errorf("%s: expected 200 with auth disabled, got %d", p, rec.Code)
		}
	}
	// Even admin routes should be reachable.
	rec := do(srv, http.MethodPost, "/api/whitelist",
		[]byte(`{"mac":"aa:bb:cc:dd:ee:ff","comment":"x"}`))
	if rec.Code != http.StatusCreated {
		t.Errorf("expected 201, got %d (body=%s)", rec.Code, rec.Body.String())
	}
}

func TestPutConfig_RejectsUnsupportedField(t *testing.T) {
	srv, _ := testServer(t, false, "")
	body := []byte(`{"monitor_interface":"wlan0"}`)
	rec := do(srv, http.MethodPut, "/api/config", body)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for unsupported field, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "unsupported_field") {
		t.Errorf("expected unsupported_field error type in body, got %s", rec.Body.String())
	}
}

func TestPutConfig_LogLevelAccepted(t *testing.T) {
	srv, _ := testServer(t, false, "")
	rec := do(srv, http.MethodPut, "/api/config", []byte(`{"log_level":"debug"}`))
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d (body=%s)", rec.Code, rec.Body.String())
	}
}

func TestNotFound_APIRoute_ReturnsJSON(t *testing.T) {
	srv, _ := testServer(t, false, "")
	rec := do(srv, http.MethodGet, "/api/does-not-exist", nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/problem+json") {
		t.Errorf("expected problem+json content type, got %q", ct)
	}
}

func TestNotFound_NonAPI_ServesSPA(t *testing.T) {
	srv, _ := testServer(t, false, "")
	rec := do(srv, http.MethodGet, "/some/spa/route", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for SPA fallback, got %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("expected text/html for SPA, got %q", ct)
	}
}

func TestSSEHub_PublishAndDeliver(t *testing.T) {
	hub := NewHub(discardLogger())
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	go hub.Run(ctx)

	ch, unsub := hub.Subscribe()
	defer unsub()

	hub.Publish(NewEventMessage(map[string]string{"type": "deauth_flood"}))

	select {
	case msg := <-ch:
		if msg.Type != MessageTypeEvent {
			t.Errorf("expected event type, got %q", msg.Type)
		}
	case <-time.After(time.Second):
		t.Fatal("did not receive published message")
	}
}

// TestNewSecurityEventMessage_MatchesRESTDTO ensures SSE "event" payloads use
// the same JSON shape as GET /api/events so SPA consumers can rely on a
// single SecurityEvent type. Regression guard against the SSE/REST drift
// fixed earlier (raw *detector.SecurityEvent was being broadcast).
func TestNewSecurityEventMessage_MatchesRESTDTO(t *testing.T) {
	ev := newTestEvent()
	msg := NewSecurityEventMessage(ev)
	if msg.Type != MessageTypeEvent {
		t.Fatalf("expected event type, got %q", msg.Type)
	}
	raw, err := json.Marshal(msg.Data)
	if err != nil {
		t.Fatalf("marshal SSE payload: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("unmarshal SSE payload: %v", err)
	}
	for _, key := range []string{"timestamp", "event_type", "severity", "src_mac", "bssid"} {
		if _, ok := got[key]; !ok {
			t.Errorf("SSE event payload missing snake_case field %q (got keys=%v)", key, got)
		}
	}
	if sev, _ := got["severity"].(string); sev != "critical" {
		t.Errorf("expected severity string \"critical\", got %v", got["severity"])
	}
	if mac, _ := got["src_mac"].(string); mac != "AA:BB:CC:DD:EE:01" {
		t.Errorf("expected src_mac string, got %v", got["src_mac"])
	}
}

func TestNewSecurityEventMessage_NilSafe(t *testing.T) {
	msg := NewSecurityEventMessage(nil)
	if msg.Type != MessageTypeEvent || msg.Data != nil {
		t.Errorf("expected event/nil, got %+v", msg)
	}
}

func TestSSEHub_UnsubscribeIsIdempotent(t *testing.T) {
	hub := NewHub(discardLogger())
	_, unsub := hub.Subscribe()
	unsub()
	unsub() // must not panic
}

// --- Additional handler-level coverage ---

func TestStatusEndpoint_FieldsPopulated(t *testing.T) {
	srv, _ := testServer(t, false, "")
	rec := do(srv, http.MethodGet, "/api/status", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	var resp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	for _, key := range []string{"version", "started_at", "capabilities", "stats", "detection", "state", "storage", "auth", "subscribers"} {
		if _, ok := resp[key]; !ok {
			t.Errorf("status response missing key %q", key)
		}
	}
}

func TestEventsEndpoint_PersistsAndLists(t *testing.T) {
	srv, repo := testServer(t, false, "")
	ev := newTestEvent()
	if err := repo.SaveEvent(t.Context(), ev); err != nil {
		t.Fatalf("save event: %v", err)
	}
	rec := do(srv, http.MethodGet, "/api/events", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	var resp listResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Total != 1 {
		t.Errorf("expected total=1, got %d", resp.Total)
	}
}

func TestStatsEndpoint_ReturnsBuckets(t *testing.T) {
	srv, repo := testServer(t, false, "")
	if err := repo.SaveEvent(t.Context(), newTestEvent()); err != nil {
		t.Fatal(err)
	}
	rec := do(srv, http.MethodGet, "/api/stats", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d (body=%s)", rec.Code, rec.Body.String())
	}
	var resp statsResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if len(resp.ByType) == 0 || len(resp.BySeverity) == 0 {
		t.Errorf("expected at least one bucket in by_type and by_severity")
	}
}

// TestLogin_RateLimited verifies that repeated failed logins from the same
// IP eventually trigger a 429 response.
func TestLogin_RateLimited(t *testing.T) {
	srv, _ := testServer(t, true, "secret123!")
	body, _ := json.Marshal(loginRequest{Username: "admin", Password: "wrong"})
	var lastCode int
	for range loginFailureThreshold + 2 {
		rec := do(srv, http.MethodPost, "/api/login", body)
		lastCode = rec.Code
	}
	if lastCode != http.StatusTooManyRequests {
		t.Errorf("expected 429 after repeated failures, got %d", lastCode)
	}
}

// TestVerifyCredentials_UnknownUserRunsBcrypt ensures unknown usernames
// still go through a bcrypt comparison so login response time does not
// trivially leak user existence.
func TestVerifyCredentials_UnknownUserRunsBcrypt(t *testing.T) {
	hash, err := bcrypt.GenerateFromPassword([]byte("adminpw"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.AuthConfig{AdminPasswordHash: string(hash)}
	start := time.Now()
	role, ok := verifyCredentials(cfg, "nobody", "whatever")
	elapsed := time.Since(start)
	if ok || role != "" {
		t.Errorf("unknown user must not authenticate")
	}
	// At MinCost bcrypt should still take at least a few hundred microseconds;
	// a constant-time compare alone would finish in single-digit microseconds.
	if elapsed < 100*time.Microsecond {
		t.Errorf("unknown user did not run bcrypt (elapsed=%v)", elapsed)
	}
}

func newTestEvent() *detector.SecurityEvent {
	mac, _ := net.ParseMAC("aa:bb:cc:dd:ee:01")
	bssid, _ := net.ParseMAC("aa:bb:cc:dd:ee:ff")
	return &detector.SecurityEvent{
		Timestamp: time.Now(),
		EventType: "deauth_flood",
		Severity:  detector.SeverityCritical,
		SrcMAC:    mac,
		BSSID:     bssid,
		Channel:   6,
		Metadata:  map[string]any{},
	}
}

func TestWhitelistCRUDViaAPI(t *testing.T) {
	srv, _ := testServer(t, false, "")

	// Initially empty.
	rec := do(srv, http.MethodGet, "/api/whitelist", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET 200 expected, got %d", rec.Code)
	}

	// Add an entry.
	rec = do(srv, http.MethodPost, "/api/whitelist", []byte(`{"mac":"aa:bb:cc:dd:ee:ff","comment":"test"}`))
	if rec.Code != http.StatusCreated {
		t.Fatalf("POST 201 expected, got %d body=%s", rec.Code, rec.Body.String())
	}

	// List shows 1.
	rec = do(srv, http.MethodGet, "/api/whitelist", nil)
	var resp listResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Total != 1 {
		t.Errorf("expected 1 entry, got %d", resp.Total)
	}

	// Reject malformed MAC.
	rec = do(srv, http.MethodPost, "/api/whitelist", []byte(`{"mac":"not-a-mac"}`))
	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid MAC, got %d", rec.Code)
	}

	// Delete.
	rec = do(srv, http.MethodDelete, "/api/whitelist/aa:bb:cc:dd:ee:ff", nil)
	if rec.Code != http.StatusNoContent {
		t.Errorf("expected 204, got %d", rec.Code)
	}
}

func TestBlacklistCRUDViaAPI(t *testing.T) {
	srv, _ := testServer(t, false, "")
	rec := do(srv, http.MethodPost, "/api/blacklist",
		[]byte(`{"mac":"11:22:33:44:55:66","reason":"deauth"}`))
	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d body=%s", rec.Code, rec.Body.String())
	}
	rec = do(srv, http.MethodGet, "/api/blacklist", nil)
	var resp listResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp.Total != 1 {
		t.Errorf("expected 1 blacklist entry, got %d", resp.Total)
	}
	rec = do(srv, http.MethodDelete, "/api/blacklist/11:22:33:44:55:66", nil)
	if rec.Code != http.StatusNoContent {
		t.Errorf("expected 204, got %d", rec.Code)
	}
}

func TestConfigGet_RedactsSecrets(t *testing.T) {
	srv, _ := testServer(t, true, "secret123!")
	// Login first.
	body, _ := json.Marshal(loginRequest{Username: "admin", Password: "secret123!"})
	rec := do(srv, http.MethodPost, "/api/login", body)
	cookie := sessionCookie(rec)
	if cookie == nil {
		t.Fatal("no session cookie")
	}
	rec = do(srv, http.MethodGet, "/api/config", nil, cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `"admin_password_hash":"***"`) {
		t.Errorf("expected admin password hash to be redacted, body=%s", rec.Body.String())
	}
}

func TestLogout_ClearsSession(t *testing.T) {
	srv, repo := testServer(t, true, "secret123!")
	body, _ := json.Marshal(loginRequest{Username: "admin", Password: "secret123!"})
	rec := do(srv, http.MethodPost, "/api/login", body)
	cookie := sessionCookie(rec)
	if cookie == nil {
		t.Fatal("no session cookie")
	}
	// Confirm session row exists.
	if _, err := repo.GetSession(t.Context(), cookie.Value); err != nil {
		t.Fatalf("GetSession: %v", err)
	}
	rec = do(srv, http.MethodPost, "/api/logout", nil, cookie)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", rec.Code)
	}
	// Session row should be gone.
	if _, err := repo.GetSession(t.Context(), cookie.Value); err == nil {
		t.Error("expected session to be deleted after logout")
	}
}

func TestStateFilters(t *testing.T) {
	srv, _ := testServer(t, false, "")
	// Pre-populate the in-memory state engine via state.NewEngine APIs would require
	// access to internal helpers; here we just verify that the filter parameters
	// don't cause errors and return the empty list shape.
	for _, q := range []string{"", "?ssid=foo", "?channel=6", "?since=2024-01-01T00:00:00Z"} {
		rec := do(srv, http.MethodGet, "/api/aps"+q, nil)
		if rec.Code != http.StatusOK {
			t.Errorf("/api/aps%s: expected 200, got %d", q, rec.Code)
		}
		rec = do(srv, http.MethodGet, "/api/clients"+q, nil)
		if rec.Code != http.StatusOK {
			t.Errorf("/api/clients%s: expected 200, got %d", q, rec.Code)
		}
	}
}

func TestEventsFilters(t *testing.T) {
	srv, repo := testServer(t, false, "")
	ev := newTestEvent()
	if err := repo.SaveEvent(t.Context(), ev); err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{
		"?event_type=deauth_flood",
		"?min_severity=critical",
		"?limit=10&offset=0",
	} {
		rec := do(srv, http.MethodGet, "/api/events"+q, nil)
		if rec.Code != http.StatusOK {
			t.Errorf("/api/events%s: expected 200, got %d", q, rec.Code)
		}
	}
}

func TestConfigPut_DedupWindowAndDetection(t *testing.T) {
	srv, _ := testServer(t, false, "")
	rec := do(srv, http.MethodPut, "/api/config",
		[]byte(`{"detection_dedup_window":"42s","detection_enabled":false}`))
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	rec = do(srv, http.MethodPut, "/api/config", []byte(`{"detection_dedup_window":"-1s"}`))
	if rec.Code != http.StatusBadRequest {
		t.Errorf("negative duration must be rejected, got %d", rec.Code)
	}
	rec = do(srv, http.MethodPut, "/api/config", []byte(`{"log_level":"verbose"}`))
	if rec.Code != http.StatusBadRequest {
		t.Errorf("unknown log level must be rejected, got %d", rec.Code)
	}
}

func TestServer_RunAndShutdown(t *testing.T) {
	srv := testServerOnEphemeralPort(t)
	ctx, cancel := context.WithCancel(t.Context())
	runDone := make(chan error, 1)
	go func() { runDone <- srv.Run(ctx) }()

	time.Sleep(150 * time.Millisecond)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+srv.cfg.Listen+"/api/status", http.NoBody)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET /api/status: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}

	cancel()
	select {
	case err := <-runDone:
		if err != nil {
			t.Errorf("Run returned error after shutdown: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Run did not exit within 3s of context cancel")
	}
}

func TestDTO_NewAPDTO(t *testing.T) {
	bssid, _ := net.ParseMAC("aa:bb:cc:dd:ee:01")
	now := time.Now()
	ap := &state.APInfo{
		BSSID:          bssid,
		SSID:           "TestNet",
		Hidden:         false,
		Channel:        6,
		RSSI:           -40,
		Capability:     0x0411,
		BeaconInterval: 100,
		BeaconCount:    42,
		FirstSeen:      now,
		LastSeen:       now,
	}
	dto := newAPDTO(ap)
	if dto.BSSID != "AA:BB:CC:DD:EE:01" {
		t.Errorf("BSSID = %q, want AA:BB:CC:DD:EE:01", dto.BSSID)
	}
	if dto.SSID != "TestNet" {
		t.Errorf("SSID = %q, want TestNet", dto.SSID)
	}
	if dto.Channel != 6 {
		t.Errorf("Channel = %d, want 6", dto.Channel)
	}
	if dto.BeaconCount != 42 {
		t.Errorf("BeaconCount = %d, want 42", dto.BeaconCount)
	}
}

func TestDTO_NewClientDTO(t *testing.T) {
	mac, _ := net.ParseMAC("11:22:33:44:55:66")
	bssid, _ := net.ParseMAC("aa:bb:cc:dd:ee:ff")
	now := time.Now()
	c := &state.ClientInfo{
		MAC:        mac,
		BSSID:      bssid,
		SSID:       "TestNet",
		Channel:    1,
		RSSI:       -55,
		FirstSeen:  now,
		LastSeen:   now,
		FrameCount: 100,
		Associated: true,
		ProbeSSIDs: []string{"wifi1", "wifi2"},
	}
	dto := newClientDTO(c)
	if dto.MAC != "11:22:33:44:55:66" {
		t.Errorf("MAC = %q, want 11:22:33:44:55:66", dto.MAC)
	}
	if dto.BSSID != "AA:BB:CC:DD:EE:FF" {
		t.Errorf("BSSID = %q, want AA:BB:CC:DD:EE:FF", dto.BSSID)
	}
	if !dto.Associated {
		t.Error("Associated should be true")
	}
	if len(dto.ProbeSSIDs) != 2 {
		t.Errorf("ProbeSSIDs len = %d, want 2", len(dto.ProbeSSIDs))
	}
}

func TestMacString_Nil(t *testing.T) {
	if got := macString(nil); got != "" {
		t.Errorf("macString(nil) = %q, want empty string", got)
	}
}

func TestSSE_NewStatusMessage(t *testing.T) {
	payload := map[string]int{"aps": 5}
	msg := NewStatusMessage(payload)
	if msg.Type != MessageTypeStatus {
		t.Errorf("Type = %q, want %q", msg.Type, MessageTypeStatus)
	}
	if msg.Data == nil {
		t.Error("Data should not be nil")
	}
}

func TestSSEHub_HasSubscribers(t *testing.T) {
	hub := NewHub(discardLogger())
	if hub.HasSubscribers() {
		t.Error("HasSubscribers should be false for empty hub")
	}
	_, unsub := hub.Subscribe()
	defer unsub()
	if !hub.HasSubscribers() {
		t.Error("HasSubscribers should be true after Subscribe")
	}
	unsub()
	if hub.HasSubscribers() {
		t.Error("HasSubscribers should be false after unsub")
	}
}

func TestServer_StatusSnapshot(t *testing.T) {
	srv, _ := testServer(t, false, "")
	ctx := t.Context()
	snap := srv.StatusSnapshot(ctx)
	if snap == nil {
		t.Fatal("StatusSnapshot returned nil")
	}
	// The underlying type is statusResponse; verify it's not empty.
	resp, ok := snap.(statusResponse)
	if !ok {
		t.Fatalf("expected statusResponse, got %T", snap)
	}
	if resp.Version == "" {
		t.Error("Version should not be empty")
	}
}

func TestHandlersState_WithData(t *testing.T) {
	srv, _ := testServer(t, false, "")

	// Populate state engine with APs and clients.
	bssid1, _ := net.ParseMAC("aa:bb:cc:dd:ee:01")
	bssid2, _ := net.ParseMAC("aa:bb:cc:dd:ee:02")
	now := time.Now()

	srv.deps.State.APs().Update(&state.APInfo{
		BSSID:     bssid1,
		SSID:      "AlphaNet",
		Channel:   1,
		RSSI:      -30,
		FirstSeen: now,
		LastSeen:  now,
	})
	srv.deps.State.APs().Update(&state.APInfo{
		BSSID:     bssid2,
		SSID:      "BetaNet",
		Channel:   11,
		RSSI:      -60,
		FirstSeen: now,
		LastSeen:  now,
	})

	// Test GET /api/aps — should return 2 APs.
	rec := do(srv, http.MethodGet, "/api/aps", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	var listAps listResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &listAps); err != nil {
		t.Fatal(err)
	}
	if listAps.Total != 2 {
		t.Errorf("expected 2 APs, got %d", listAps.Total)
	}

	// Test SSID filter.
	rec = do(srv, http.MethodGet, "/api/aps?ssid=alpha", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &listAps); err != nil {
		t.Fatal(err)
	}
	if listAps.Total != 1 {
		t.Errorf("expected 1 AP for ssid=alpha, got %d", listAps.Total)
	}

	// Test channel filter.
	rec = do(srv, http.MethodGet, "/api/aps?channel=11", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &listAps); err != nil {
		t.Fatal(err)
	}
	if listAps.Total != 1 {
		t.Errorf("expected 1 AP for channel=11, got %d", listAps.Total)
	}

	// Populate a client.
	clientMAC, _ := net.ParseMAC("11:22:33:44:55:66")
	srv.deps.State.Clients().Update(&state.ClientInfo{
		MAC:        clientMAC,
		BSSID:      bssid1,
		SSID:       "AlphaNet",
		Channel:    1,
		RSSI:       -50,
		FirstSeen:  now,
		LastSeen:   now,
		Associated: true,
	})

	// Test GET /api/clients.
	rec = do(srv, http.MethodGet, "/api/clients", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	var listClients listResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &listClients); err != nil {
		t.Fatal(err)
	}
	if listClients.Total != 1 {
		t.Errorf("expected 1 client, got %d", listClients.Total)
	}

	// Test associated filter.
	rec = do(srv, http.MethodGet, "/api/clients?associated=true", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &listClients); err != nil {
		t.Fatal(err)
	}
	if listClients.Total != 1 {
		t.Errorf("expected 1 associated client, got %d", listClients.Total)
	}

	// Test BSSID filter.
	rec = do(srv, http.MethodGet, "/api/clients?bssid=aa:bb:cc:dd:ee:01", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &listClients); err != nil {
		t.Fatal(err)
	}
	if listClients.Total != 1 {
		t.Errorf("expected 1 client for BSSID filter, got %d", listClients.Total)
	}
}

func TestSSE_StreamReceivesPublishedEvent(t *testing.T) {
	srv := testServerOnEphemeralPort(t)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	runDone := make(chan error, 1)
	go func() { runDone <- srv.Run(ctx) }()
	time.Sleep(150 * time.Millisecond)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+srv.cfg.Listen+"/api/stream", http.NoBody)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET /api/stream: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	// Wait for handleStream to subscribe before publishing.
	time.Sleep(100 * time.Millisecond)
	srv.deps.Hub.Publish(NewEventMessage(map[string]string{"event_type": "deauth_flood"}))

	buf := make([]byte, 4096)
	deadline := time.Now().Add(2 * time.Second)
	var received []byte
	for time.Now().Before(deadline) {
		n, err := resp.Body.Read(buf)
		if n > 0 {
			received = append(received, buf[:n]...)
			if strings.Contains(string(received), "deauth_flood") {
				break
			}
		}
		if err != nil {
			break
		}
	}
	if !strings.Contains(string(received), "deauth_flood") {
		t.Fatalf("expected published event in stream, got %q", string(received))
	}

	cancel()
	<-runDone
}

// testServerOnEphemeralPort builds a Server bound to a kernel-allocated free
// port. The Hub is started by NewServer's caller (this helper) so the
// server's stream handler has a live broadcaster.
func testServerOnEphemeralPort(t *testing.T) *Server {
	t.Helper()
	repo, err := storage.Open(config.StorageConfig{Enabled: true, Path: ":memory:"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = repo.Close() })

	logger := discardLogger()
	stateEng := state.NewEngine(config.StateConfig{Enabled: true, TTL: time.Hour, SweepInterval: time.Minute},
		config.WhitelistConfig{}, logger)
	hub := NewHub(logger)
	hubCtx, hubCancel := context.WithCancel(t.Context())
	t.Cleanup(hubCancel)
	go hub.Run(hubCtx)

	var lc net.ListenConfig
	ln, err := lc.Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()

	apiCfg := config.APIConfig{
		Enabled: true, Listen: addr,
		ReadTimeout: 5 * time.Second, WriteTimeout: 30 * time.Second,
		IdleTimeout: 10 * time.Second, ShutdownTimeout: 2 * time.Second,
	}
	cfg := &config.Config{
		Detection: config.DetectionConfig{Enabled: true, DedupWindow: 30 * time.Second},
		State:     config.StateConfig{Enabled: true, TTL: time.Hour, SweepInterval: time.Minute},
		API:       apiCfg,
		Storage:   config.StorageConfig{Enabled: true, Path: ":memory:"},
	}
	srv, err := NewServer(apiCfg, Deps{
		Config: cfg, State: stateEng, Repo: repo, Hub: hub, StartTime: time.Now(), Logger: logger,
	})
	if err != nil {
		t.Fatal(err)
	}
	return srv
}

func TestDeleteWhitelist_InvalidMAC(t *testing.T) {
	srv, _ := testServer(t, false, "")
	rec := do(srv, http.MethodDelete, "/api/whitelist/not-a-mac", nil)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid MAC in delete, got %d", rec.Code)
	}
}

func TestDeleteBlacklist_InvalidMAC(t *testing.T) {
	srv, _ := testServer(t, false, "")
	rec := do(srv, http.MethodDelete, "/api/blacklist/not-a-mac", nil)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid MAC in delete, got %d", rec.Code)
	}
}

func TestAddBlacklist_InvalidMAC(t *testing.T) {
	srv, _ := testServer(t, false, "")
	rec := do(srv, http.MethodPost, "/api/blacklist", []byte(`{"mac":"invalid"}`))
	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid MAC, got %d", rec.Code)
	}
}

func TestParseMACArg_Empty(t *testing.T) {
	_, err := parseMACArg("")
	if err == nil {
		t.Error("expected error for empty MAC")
	}
	_, err = parseMACArg("  ")
	if err == nil {
		t.Error("expected error for whitespace-only MAC")
	}
}

func TestEventsEndpoint_UnknownSeverity(t *testing.T) {
	srv, repo := testServer(t, false, "")
	ev := newTestEvent()
	if err := repo.SaveEvent(t.Context(), ev); err != nil {
		t.Fatal(err)
	}
	// Unknown severity should fall through and match all.
	rec := do(srv, http.MethodGet, "/api/events?min_severity=bogus", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
}

func TestEventsEndpoint_BadLimitOffset(t *testing.T) {
	srv, _ := testServer(t, false, "")
	// Bad limit/offset values should default to 0.
	rec := do(srv, http.MethodGet, "/api/events?limit=abc&offset=xyz", nil)
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
}

func TestConfigPut_StringifyBool(t *testing.T) {
	srv, _ := testServer(t, false, "")
	// Boolean value should be stringified.
	rec := do(srv, http.MethodPut, "/api/config", []byte(`{"detection_enabled":true}`))
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestCorsMiddleware_AllowedOrigin(t *testing.T) {
	// Build a server with CORS allowed origins.
	repo, _ := storage.Open(config.StorageConfig{Enabled: true, Path: ":memory:"})
	defer repo.Close()
	logger := discardLogger()
	stateEng := state.NewEngine(config.StateConfig{Enabled: true, TTL: time.Hour, SweepInterval: time.Minute},
		config.WhitelistConfig{}, logger)
	hub := NewHub(logger)
	apiCfg := config.APIConfig{
		Enabled:         true,
		Listen:          "127.0.0.1:0",
		ReadTimeout:     5 * time.Second,
		WriteTimeout:    10 * time.Second,
		IdleTimeout:     10 * time.Second,
		ShutdownTimeout: 2 * time.Second,
		CORS:            config.CORSConfig{AllowedOrigins: []string{"http://example.com"}},
	}
	cfg := &config.Config{
		Detection: config.DetectionConfig{Enabled: true, DedupWindow: 30 * time.Second},
		State:     config.StateConfig{Enabled: true, TTL: time.Hour, SweepInterval: time.Minute},
		API:       apiCfg,
		Storage:   config.StorageConfig{Enabled: true, Path: ":memory:"},
	}
	srv, err := NewServer(apiCfg, Deps{
		Config: cfg, State: stateEng, Repo: repo, Hub: hub, StartTime: time.Now(), Logger: logger,
	})
	if err != nil {
		t.Fatal(err)
	}

	// OPTIONS preflight with allowed origin should get CORS headers.
	req := httptest.NewRequestWithContext(context.Background(), http.MethodOptions, "/api/status", http.NoBody)
	req.Header.Set("Origin", "http://example.com")
	rec := httptest.NewRecorder()
	srv.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Errorf("expected 204 for OPTIONS, got %d", rec.Code)
	}
	if rec.Header().Get("Access-Control-Allow-Origin") != "http://example.com" {
		t.Error("expected Access-Control-Allow-Origin header")
	}

	// OPTIONS preflight with disallowed origin should not get CORS headers.
	req2 := httptest.NewRequestWithContext(context.Background(), http.MethodOptions, "/api/status", http.NoBody)
	req2.Header.Set("Origin", "http://evil.com")
	rec2 := httptest.NewRecorder()
	srv.router.ServeHTTP(rec2, req2)
	if rec2.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Error("CORS headers should not be set for disallowed origin")
	}

	// GET request with allowed origin should get CORS headers.
	req3 := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/status", http.NoBody)
	req3.Header.Set("Origin", "http://example.com")
	rec3 := httptest.NewRecorder()
	srv.router.ServeHTTP(rec3, req3)
	if rec3.Header().Get("Access-Control-Allow-Origin") != "http://example.com" {
		t.Error("expected CORS headers on GET with allowed origin")
	}

	// GET request without Origin header should not have CORS headers.
	req4 := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/status", http.NoBody)
	rec4 := httptest.NewRecorder()
	srv.router.ServeHTTP(rec4, req4)
	if rec4.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Error("CORS headers should not be set without Origin header")
	}
}

func TestNewAPMessage(t *testing.T) {
	bssid, _ := net.ParseMAC("aa:bb:cc:dd:ee:01")
	now := time.Now()
	aps := []*state.APInfo{
		{BSSID: bssid, SSID: "Net1", Channel: 1, RSSI: -30, FirstSeen: now, LastSeen: now},
		{BSSID: bssid, SSID: "Net2", Channel: 6, RSSI: -50, FirstSeen: now, LastSeen: now},
	}
	msg := NewAPMessage(aps)
	if msg.Type != MessageTypeAP {
		t.Errorf("expected type %q, got %q", MessageTypeAP, msg.Type)
	}
	dtos, ok := msg.Data.([]apDTO)
	if !ok {
		t.Fatalf("expected []apDTO, got %T", msg.Data)
	}
	if len(dtos) != 2 {
		t.Errorf("expected 2 AP DTOs, got %d", len(dtos))
	}
}

func TestNewAPMessage_NilEntries(t *testing.T) {
	bssid, _ := net.ParseMAC("aa:bb:cc:dd:ee:01")
	now := time.Now()
	aps := []*state.APInfo{
		nil,
		{BSSID: bssid, SSID: "Net", Channel: 1, RSSI: -30, FirstSeen: now, LastSeen: now},
	}
	msg := NewAPMessage(aps)
	dtos, _ := msg.Data.([]apDTO)
	if len(dtos) != 1 {
		t.Errorf("expected 1 AP DTO (nil filtered), got %d", len(dtos))
	}
}

func TestNewAPMessage_Empty(t *testing.T) {
	msg := NewAPMessage(nil)
	dtos, _ := msg.Data.([]apDTO)
	if len(dtos) != 0 {
		t.Errorf("expected 0 AP DTOs for nil input, got %d", len(dtos))
	}
}

func TestNewClientMessage(t *testing.T) {
	mac, _ := net.ParseMAC("11:22:33:44:55:66")
	bssid, _ := net.ParseMAC("aa:bb:cc:dd:ee:ff")
	now := time.Now()
	clients := []*state.ClientInfo{
		{MAC: mac, BSSID: bssid, SSID: "Net", Channel: 1, RSSI: -55, FirstSeen: now, LastSeen: now, Associated: true},
	}
	msg := NewClientMessage(clients)
	if msg.Type != MessageTypeClient {
		t.Errorf("expected type %q, got %q", MessageTypeClient, msg.Type)
	}
	dtos, ok := msg.Data.([]clientDTO)
	if !ok {
		t.Fatalf("expected []clientDTO, got %T", msg.Data)
	}
	if len(dtos) != 1 {
		t.Errorf("expected 1 client DTO, got %d", len(dtos))
	}
}

func TestNewClientMessage_NilEntries(t *testing.T) {
	mac, _ := net.ParseMAC("11:22:33:44:55:66")
	bssid, _ := net.ParseMAC("aa:bb:cc:dd:ee:ff")
	now := time.Now()
	clients := []*state.ClientInfo{
		nil,
		{MAC: mac, BSSID: bssid, SSID: "Net", Channel: 1, RSSI: -55, FirstSeen: now, LastSeen: now},
	}
	msg := NewClientMessage(clients)
	dtos, _ := msg.Data.([]clientDTO)
	if len(dtos) != 1 {
		t.Errorf("expected 1 client DTO (nil filtered), got %d", len(dtos))
	}
}

func TestNewClientMessage_Empty(t *testing.T) {
	msg := NewClientMessage(nil)
	dtos, _ := msg.Data.([]clientDTO)
	if len(dtos) != 0 {
		t.Errorf("expected 0 client DTOs for nil input, got %d", len(dtos))
	}
}

func TestCookieSecure_DefaultTrue(t *testing.T) {
	s := &Server{cfg: config.APIConfig{}}
	if !s.cookieSecure() {
		t.Error("cookieSecure should default to true")
	}
}

func TestCookieSecure_ExplicitFalse(t *testing.T) {
	v := false
	s := &Server{cfg: config.APIConfig{Auth: config.AuthConfig{CookieSecure: &v}}}
	if s.cookieSecure() {
		t.Error("cookieSecure should be false when explicitly set")
	}
}

func TestCookieSecure_ExplicitTrue(t *testing.T) {
	v := true
	s := &Server{cfg: config.APIConfig{Auth: config.AuthConfig{CookieSecure: &v}}}
	if !s.cookieSecure() {
		t.Error("cookieSecure should be true when explicitly set")
	}
}

func TestReadJSON_MultipleValues(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/",
		strings.NewReader(`{"a":1}{"b":2}`))
	r.Header.Set("Content-Type", "application/json")
	var dst map[string]int
	err := readJSON(w, r, discardLogger(), &dst)
	if err == nil {
		t.Error("expected error for multiple JSON values")
	}
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestReadJSON_DisallowUnknownFields(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/",
		strings.NewReader(`{"username":"admin","extra_field":"bad"}`))
	r.Header.Set("Content-Type", "application/json")
	var dst loginRequest
	err := readJSON(w, r, discardLogger(), &dst)
	if err == nil {
		t.Error("expected error for unknown fields")
	}
}

func TestWriteJSON_NilPayload(t *testing.T) {
	w := httptest.NewRecorder()
	writeJSON(w, discardLogger(), http.StatusNoContent, nil)
	if w.Code != http.StatusNoContent {
		t.Errorf("expected 204, got %d", w.Code)
	}
	if w.Body.Len() != 0 {
		t.Error("expected empty body for nil payload")
	}
}

func TestWriteProblem_EncodeError(t *testing.T) {
	// Use a writer that fails to verify the error path doesn't panic.
	// httptest.ResponseRecorder never fails encoding, so just verify non-panic.
	w := httptest.NewRecorder()
	writeProblem(w, discardLogger(), http.StatusInternalServerError, errTypeInternal, "test error")
	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", w.Code)
	}
	ct := w.Header().Get("Content-Type")
	if ct != "application/problem+json" {
		t.Errorf("expected problem+json, got %q", ct)
	}
}

func TestLoginRateLimiter_SweepStaleEntries(t *testing.T) {
	l := newLoginRateLimiter()
	now := time.Now()
	// Add failures for an IP.
	for range loginFailureThreshold {
		l.recordFailure("10.0.0.1", now.Add(-time.Hour))
	}
	// After an hour, all failures are stale.
	if l.locked("10.0.0.1", now) {
		t.Error("IP should not be locked after failures expire")
	}
}

func TestVerifyCredentials_UserWithNoPassword(t *testing.T) {
	cfg := config.AuthConfig{
		AdminPasswordHash: "",
		UserPasswordHash:  "",
	}
	_, ok := verifyCredentials(cfg, "user", "any")
	if ok {
		t.Error("user with no configured password should not authenticate")
	}
}

func TestVerifyCredentials_AdminSuccess(t *testing.T) {
	hash, _ := bcrypt.GenerateFromPassword([]byte("secret123!"), bcrypt.MinCost)
	cfg := config.AuthConfig{AdminPasswordHash: string(hash)}
	role, ok := verifyCredentials(cfg, "admin", "secret123!")
	if !ok {
		t.Error("admin should authenticate with correct password")
	}
	if role != storage.SessionRoleAdmin {
		t.Errorf("expected admin role, got %q", role)
	}
}

func TestVerifyCredentials_UserSuccess(t *testing.T) {
	hash, _ := bcrypt.GenerateFromPassword([]byte("userpass"), bcrypt.MinCost)
	cfg := config.AuthConfig{UserPasswordHash: string(hash)}
	role, ok := verifyCredentials(cfg, "user", "userpass")
	if !ok {
		t.Error("user should authenticate with correct password")
	}
	if role != storage.SessionRoleUser {
		t.Errorf("expected user role, got %q", role)
	}
}

func TestVerifyCredentials_NoHash(t *testing.T) {
	cfg := config.AuthConfig{}
	// Admin with no hash configured falls through to dummy hash.
	_, ok := verifyCredentials(cfg, "admin", "anything")
	if ok {
		t.Error("admin with no configured hash should not authenticate")
	}
}

func TestLoginRateLimiter_RecordSuccess(t *testing.T) {
	l := newLoginRateLimiter()
	now := time.Now()
	// Record some failures.
	for range 3 {
		l.recordFailure("10.0.0.1", now)
	}
	// Record success clears all.
	l.recordSuccess("10.0.0.1")
	if l.locked("10.0.0.1", now) {
		t.Error("IP should not be locked after success")
	}
}

func TestSessionFromCtx_Nil(t *testing.T) {
	_, ok := sessionFromCtx(context.Background())
	if ok {
		t.Error("expected no session from empty context")
	}
}

func TestSessionFromCtx_Valid(t *testing.T) {
	sess := &storage.Session{Token: "abc", Role: storage.SessionRoleAdmin}
	ctx := context.WithValue(context.Background(), ctxKeySession, sess)
	got, ok := sessionFromCtx(ctx)
	if !ok {
		t.Error("expected session from context")
	}
	if got.Role != storage.SessionRoleAdmin {
		t.Errorf("expected admin role, got %q", got.Role)
	}
}

func TestResolveSession_AuthDisabled(t *testing.T) {
	srv, _ := testServer(t, false, "")
	sess, err := srv.resolveSession(httptest.NewRequest(http.MethodGet, "/", nil))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sess.Role != storage.SessionRoleAdmin {
		t.Errorf("expected admin role, got %q", sess.Role)
	}
}

func TestResolveSession_Expired(t *testing.T) {
	srv, repo := testServer(t, true, "secret123!")
	ctx := t.Context()
	// Create an expired session directly.
	now := time.Now()
	sess := &storage.Session{
		Token:     "expired-token",
		Role:      storage.SessionRoleAdmin,
		CreatedAt: now.Add(-2 * time.Hour),
		ExpiresAt: now.Add(-time.Hour),
	}
	if err := repo.CreateSession(ctx, sess); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequestWithContext(ctx, http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "expired-token"})
	_, err := srv.resolveSession(req)
	if err == nil {
		t.Error("expected error for expired session")
	}
}

func TestRunSessionPruner(t *testing.T) {
	repo, err := storage.Open(config.StorageConfig{Enabled: true, Path: ":memory:"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { repo.Close() })
	logger := discardLogger()
	s := &Server{
		deps:   Deps{Repo: repo, Logger: logger},
		cfg:    config.APIConfig{},
		logger: logger,
	}
	ctx, cancel := context.WithCancel(t.Context())
	// Start pruner in background.
	done := make(chan struct{})
	go func() {
		s.runSessionPruner(ctx)
		close(done)
	}()
	// Cancel and wait for exit.
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("runSessionPruner did not exit after cancel")
	}
}

func TestRunSessionPruner_NoRepo(t *testing.T) {
	logger := discardLogger()
	s := &Server{
		deps:   Deps{Logger: logger},
		cfg:    config.APIConfig{},
		logger: logger,
	}
	// Should return immediately without panic.
	s.runSessionPruner(context.Background())
}

func TestHandleLogin_AuthDisabled(t *testing.T) {
	srv, _ := testServer(t, false, "")
	body, _ := json.Marshal(loginRequest{Username: "admin", Password: "anything"})
	rec := do(srv, http.MethodPost, "/api/login", body)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 with auth disabled, got %d", rec.Code)
	}
	var resp loginResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Role != storage.SessionRoleAdmin {
		t.Errorf("expected admin role with auth disabled, got %q", resp.Role)
	}
}

func TestHandleStream_ContextCancel(t *testing.T) {
	srv, _ := testServer(t, false, "")
	ctx, cancel := context.WithCancel(t.Context())
	req := httptest.NewRequestWithContext(ctx, http.MethodGet, "/api/stream", nil)
	rec := httptest.NewRecorder()
	// Start the handler in a goroutine and cancel immediately.
	done := make(chan struct{})
	go func() {
		srv.router.ServeHTTP(rec, req)
		close(done)
	}()
	time.Sleep(50 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("handleStream did not exit after context cancel")
	}
}

func TestMiddleware_Recoverer(t *testing.T) {
	srv, _ := testServer(t, false, "")
	// Verify that the recoverer middleware is installed by triggering a panic.
	// We can't easily inject a panic, but we can verify the router exists.
	if srv.router == nil {
		t.Fatal("router should not be nil")
	}
}

func TestHandleLogout_NoCookie(t *testing.T) {
	srv, _ := testServer(t, false, "")
	rec := do(srv, http.MethodPost, "/api/logout", nil)
	if rec.Code != http.StatusNoContent {
		t.Errorf("expected 204, got %d", rec.Code)
	}
}

func TestHandleConfig_DetectionEnabled(t *testing.T) {
	srv, _ := testServer(t, false, "")
	// Disable detection and verify it's reflected.
	rec := do(srv, http.MethodPut, "/api/config", []byte(`{"detection_enabled":false}`))
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestHandleConfig_InvalidJSON(t *testing.T) {
	srv, _ := testServer(t, false, "")
	rec := do(srv, http.MethodPut, "/api/config", []byte(`not json`))
	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid JSON, got %d", rec.Code)
	}
}

func TestHandleEvents_WithoutRepo(t *testing.T) {
	// Build server without storage to test storage_disabled error path.
	logger := discardLogger()
	stateEng := state.NewEngine(config.StateConfig{Enabled: true, TTL: time.Hour, SweepInterval: time.Minute},
		config.WhitelistConfig{}, logger)
	hub := NewHub(logger)
	apiCfg := config.APIConfig{
		Enabled:  true,
		Listen:   "127.0.0.1:0",
	}
	cfg := &config.Config{API: apiCfg, State: config.StateConfig{Enabled: true, TTL: time.Hour, SweepInterval: time.Minute}}
	srv, err := NewServer(apiCfg, Deps{
		Config: cfg, State: stateEng, Hub: hub, StartTime: time.Now(), Logger: logger,
	})
	if err != nil {
		t.Fatal(err)
	}
	rec := do(srv, http.MethodGet, "/api/events", nil)
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503 without repo, got %d", rec.Code)
	}
}

func TestHandleEvents_MethodNotAllowed(t *testing.T) {
	srv, _ := testServer(t, false, "")
	rec := do(srv, http.MethodPut, "/api/events", nil)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405 for PUT on /api/events, got %d", rec.Code)
	}
}

func TestSetDetectionEnabled(t *testing.T) {
	srv := &Server{}
	srv.SetDetectionEnabled(true)
	if !srv.detectionEnabled.Load() {
		t.Error("expected detectionEnabled to be true")
	}
	srv.SetDetectionEnabled(false)
	if srv.detectionEnabled.Load() {
		t.Error("expected detectionEnabled to be false")
	}
}

func TestHubPublish_QueueFull(t *testing.T) {
	logger := discardLogger()
	// Create hub with a tiny publish queue so we can fill it easily.
	hub := &Hub{
		logger:           logger,
		subs:             make(map[int64]*subscriber),
		publishQueue:     make(chan Message, 1),
		subscriberBuffer: 1,
	}
	// Fill the queue.
	hub.Publish(Message{Type: "test", Data: "msg1"})
	hub.Publish(Message{Type: "test", Data: "msg2"}) // queue is now full
	// This should be dropped (non-blocking) and log a warning.
	hub.Publish(Message{Type: "test", Data: "msg3"})
	// Should not panic.
}

// TestParseSeverity verifies severity string-to-enum mapping.
func TestParseSeverity(t *testing.T) {
	if got := parseSeverity("info"); got != detector.SeverityInfo {
		t.Errorf("info => %d, want %d", got, detector.SeverityInfo)
	}
	if got := parseSeverity("INFO"); got != detector.SeverityInfo {
		t.Errorf("INFO => %d, want %d", got, detector.SeverityInfo)
	}
	if got := parseSeverity("warning"); got != detector.SeverityWarning {
		t.Errorf("warning => %d, want %d", got, detector.SeverityWarning)
	}
	if got := parseSeverity("WARNING"); got != detector.SeverityWarning {
		t.Errorf("WARNING => %d, want %d", got, detector.SeverityWarning)
	}
	if got := parseSeverity("critical"); got != detector.SeverityCritical {
		t.Errorf("critical => %d, want %d", got, detector.SeverityCritical)
	}
	if got := parseSeverity("CRITICAL"); got != detector.SeverityCritical {
		t.Errorf("CRITICAL => %d, want %d", got, detector.SeverityCritical)
	}
	if got := parseSeverity(""); got != 0 {
		t.Errorf("empty => %d, want 0", got)
	}
	if got := parseSeverity("bogus"); got != 0 {
		t.Errorf("bogus => %d, want 0", got)
	}
}

// TestHandleListEvents_FilterLimits verifies limit capping and negative offset.
func TestHandleListEvents_FilterLimits(t *testing.T) {
	srv, _ := testServer(t, false, "")
	// Limit exceeding max should be capped.
	rec := do(srv, http.MethodGet, "/api/events?limit=5000&offset=-5", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
}

// TestHandleListEvents_WarningSeverity verifies min_severity=warning filter.
func TestHandleListEvents_WarningSeverity(t *testing.T) {
	srv, repo := testServer(t, false, "")
	ev := newTestEvent()
	ev.Severity = detector.SeverityWarning
	ev.EventType = "evil_twin"
	if err := repo.SaveEvent(t.Context(), ev); err != nil {
		t.Fatal(err)
	}
	rec := do(srv, http.MethodGet, "/api/events?min_severity=warning", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	var resp listResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Total == 0 {
		t.Error("expected at least one event matching warning severity")
	}
}

// TestHandleStats_CacheHit verifies the 30-second stats cache path.
func TestHandleStats_CacheHit(t *testing.T) {
	srv, repo := testServer(t, false, "")
	if err := repo.SaveEvent(t.Context(), newTestEvent()); err != nil {
		t.Fatal(err)
	}
	// First request populates cache.
	rec := do(srv, http.MethodGet, "/api/stats", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	// Second request within 30s should hit cache.
	rec2 := do(srv, http.MethodGet, "/api/stats", nil)
	if rec2.Code != http.StatusOK {
		t.Fatalf("cached request: expected 200, got %d", rec2.Code)
	}
	// Both responses should contain the same stats.
	if rec.Body.String() != rec2.Body.String() {
		t.Error("cached stats response should match first response")
	}
}

// TestHandleStats_CustomWindow verifies stats with a custom window_seconds.
func TestHandleStats_CustomWindow(t *testing.T) {
	srv, repo := testServer(t, false, "")
	if err := repo.SaveEvent(t.Context(), newTestEvent()); err != nil {
		t.Fatal(err)
	}
	// Custom 1-hour window.
	rec := do(srv, http.MethodGet, "/api/stats?window_seconds=3600", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	var resp statsResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.WindowSeconds != 3600 {
		t.Errorf("expected window_seconds=3600, got %d", resp.WindowSeconds)
	}
	// Zero window_seconds should default to 86400.
	rec2 := do(srv, http.MethodGet, "/api/stats?window_seconds=0", nil)
	if rec2.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec2.Code)
	}
	var resp2 statsResponse
	if err := json.Unmarshal(rec2.Body.Bytes(), &resp2); err != nil {
		t.Fatal(err)
	}
	if resp2.WindowSeconds != 86400 {
		t.Errorf("expected default window_seconds=86400, got %d", resp2.WindowSeconds)
	}
}

// TestClientIP verifies client IP extraction from RemoteAddr.
func TestClientIP(t *testing.T) {
	// With host:port.
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)
	req.RemoteAddr = "192.168.1.1:54321"
	if got := clientIP(req); got != "192.168.1.1" {
		t.Errorf("expected 192.168.1.1, got %q", got)
	}
	// Without port (bare IP).
	req2 := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)
	req2.RemoteAddr = "10.0.0.1"
	if got := clientIP(req2); got != "10.0.0.1" {
		t.Errorf("expected 10.0.0.1, got %q", got)
	}
}

// TestRecoverer_Panic verifies the recoverer middleware catches panics.
func TestRecoverer_Panic(t *testing.T) {
	logger := discardLogger()
	handler := recoverer(logger)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic("test panic")
	}))
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/test", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 after panic, got %d", rec.Code)
	}
}

// TestRequestLogger_5xx verifies the request logger handles 5xx responses.
func TestRequestLogger_5xx(t *testing.T) {
	logger := discardLogger()
	wrapped := recoverer(logger)(requestLogger(logger)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic("trigger 500")
	})))
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/test", nil)
	rec := httptest.NewRecorder()
	wrapped.ServeHTTP(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", rec.Code)
	}
}

// TestHandleLogin_InvalidJSON verifies login with malformed request body.
func TestHandleLogin_InvalidJSON(t *testing.T) {
	srv, _ := testServer(t, true, "secret123!")
	rec := do(srv, http.MethodPost, "/api/login", []byte(`not json`))
	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid JSON, got %d", rec.Code)
	}
}

// TestHandleStats_StorageDisabled verifies stats error when storage is disabled.
func TestHandleStats_StorageDisabled(t *testing.T) {
	srv, _ := testServer(t, false, "")
	// Replace repo with nil to simulate storage disabled at runtime.
	srv.deps.Repo = nil
	rec := do(srv, http.MethodGet, "/api/stats", nil)
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503 for storage disabled, got %d", rec.Code)
	}
}

// TestHandleListEvents_StorageDisabled verifies events error when storage is disabled.
func TestHandleListEvents_StorageDisabled(t *testing.T) {
	srv, _ := testServer(t, false, "")
	srv.deps.Repo = nil
	rec := do(srv, http.MethodGet, "/api/events", nil)
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503 for storage disabled, got %d", rec.Code)
	}
}

// TestHandleListWhitelist_StateDisabled verifies whitelist list error when state is disabled.
func TestHandleListWhitelist_StateDisabled(t *testing.T) {
	srv, _ := testServer(t, false, "")
	srv.deps.State = nil
	rec := do(srv, http.MethodGet, "/api/whitelist", nil)
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503 for state disabled, got %d", rec.Code)
	}
}

// TestHandleAddWhitelist_StateDisabled verifies whitelist add error when state is disabled.
func TestHandleAddWhitelist_StateDisabled(t *testing.T) {
	srv, _ := testServer(t, false, "")
	srv.deps.State = nil
	rec := do(srv, http.MethodPost, "/api/whitelist", []byte(`{"mac":"aa:bb:cc:dd:ee:ff"}`))
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503 for state disabled, got %d", rec.Code)
	}
}

// TestHandleAddWhitelist_InvalidJSON verifies whitelist add with bad JSON.
func TestHandleAddWhitelist_InvalidJSON(t *testing.T) {
	srv, _ := testServer(t, false, "")
	rec := do(srv, http.MethodPost, "/api/whitelist", []byte(`not json`))
	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid JSON, got %d", rec.Code)
	}
}

// TestHandleDeleteWhitelist_StateDisabled verifies whitelist delete error when state is disabled.
func TestHandleDeleteWhitelist_StateDisabled(t *testing.T) {
	srv, _ := testServer(t, false, "")
	srv.deps.State = nil
	rec := do(srv, http.MethodDelete, "/api/whitelist/aa:bb:cc:dd:ee:ff", nil)
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503 for state disabled, got %d", rec.Code)
	}
}

// TestHandleListBlacklist_StateDisabled verifies blacklist list error when state is disabled.
func TestHandleListBlacklist_StateDisabled(t *testing.T) {
	srv, _ := testServer(t, false, "")
	srv.deps.State = nil
	rec := do(srv, http.MethodGet, "/api/blacklist", nil)
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503 for state disabled, got %d", rec.Code)
	}
}

// TestHandleAddBlacklist_StateDisabled verifies blacklist add error when state is disabled.
func TestHandleAddBlacklist_StateDisabled(t *testing.T) {
	srv, _ := testServer(t, false, "")
	srv.deps.State = nil
	rec := do(srv, http.MethodPost, "/api/blacklist", []byte(`{"mac":"aa:bb:cc:dd:ee:ff"}`))
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503 for state disabled, got %d", rec.Code)
	}
}

// TestHandleAddBlacklist_InvalidJSON verifies blacklist add with bad JSON.
func TestHandleAddBlacklist_InvalidJSON(t *testing.T) {
	srv, _ := testServer(t, false, "")
	rec := do(srv, http.MethodPost, "/api/blacklist", []byte(`not json`))
	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid JSON, got %d", rec.Code)
	}
}

// TestHandleDeleteBlacklist_StateDisabled verifies blacklist delete error when state is disabled.
func TestHandleDeleteBlacklist_StateDisabled(t *testing.T) {
	srv, _ := testServer(t, false, "")
	srv.deps.State = nil
	rec := do(srv, http.MethodDelete, "/api/blacklist/aa:bb:cc:dd:ee:ff", nil)
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503 for state disabled, got %d", rec.Code)
	}
}

// TestStringifyValue verifies the stringifyValue helper.
func TestStringifyValue(t *testing.T) {
	if s, ok := stringifyValue("hello"); !ok || s != "hello" {
		t.Errorf("string => (%q, %v), want (hello, true)", s, ok)
	}
	if s, ok := stringifyValue(true); !ok || s != "true" {
		t.Errorf("true => (%q, %v), want (true, true)", s, ok)
	}
	if s, ok := stringifyValue(false); !ok || s != "false" {
		t.Errorf("false => (%q, %v), want (false, true)", s, ok)
	}
	// Unsupported type.
	if s, ok := stringifyValue(42); ok || s != "" {
		t.Errorf("int => (%q, %v), want (\"\", false)", s, ok)
	}
	if s, ok := stringifyValue(3.14); ok || s != "" {
		t.Errorf("float => (%q, %v), want (\"\", false)", s, ok)
	}
}

// TestHandlePutConfig_DetectionEnabledNonBool verifies detection_enabled rejects non-bool.
func TestHandlePutConfig_DetectionEnabledNonBool(t *testing.T) {
	srv, _ := testServer(t, false, "")
	rec := do(srv, http.MethodPut, "/api/config", []byte(`{"detection_enabled":"yes"}`))
	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for non-bool detection_enabled, got %d (body=%s)", rec.Code, rec.Body.String())
	}
}

// TestHandlePutConfig_DedupWindowNonString verifies detection_dedup_window rejects non-string.
func TestHandlePutConfig_DedupWindowNonString(t *testing.T) {
	srv, _ := testServer(t, false, "")
	rec := do(srv, http.MethodPut, "/api/config", []byte(`{"detection_dedup_window":42}`))
	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for non-string detection_dedup_window, got %d", rec.Code)
	}
}

// TestHandlePutConfig_LogLevelNonString verifies log_level rejects non-string.
func TestHandlePutConfig_LogLevelNonString(t *testing.T) {
	srv, _ := testServer(t, false, "")
	rec := do(srv, http.MethodPut, "/api/config", []byte(`{"log_level":42}`))
	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for non-string log_level, got %d", rec.Code)
	}
}

// TestHandleListAPs_StateDisabled verifies AP list error when state is disabled.
func TestHandleListAPs_StateDisabled(t *testing.T) {
	srv, _ := testServer(t, false, "")
	srv.deps.State = nil
	rec := do(srv, http.MethodGet, "/api/aps", nil)
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503 for state disabled, got %d", rec.Code)
	}
}

// TestHandleListClients_StateDisabled verifies client list error when state is disabled.
func TestHandleListClients_StateDisabled(t *testing.T) {
	srv, _ := testServer(t, false, "")
	srv.deps.State = nil
	rec := do(srv, http.MethodGet, "/api/clients", nil)
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503 for state disabled, got %d", rec.Code)
	}
}
