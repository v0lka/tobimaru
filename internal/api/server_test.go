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
	req := httptest.NewRequest(method, path, bodyR)
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
