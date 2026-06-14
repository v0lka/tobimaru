package api

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/vkochetkov/tobimaru/internal/config"
	"github.com/vkochetkov/tobimaru/internal/storage"
)

// sessionCookieName is the HttpOnly cookie that carries the opaque session
// token between the SPA and the API.
const sessionCookieName = "tobimaru_session"

// dummyBcryptHash is a precomputed bcrypt hash used to equalize the cost of
// verifyCredentials when the username is unknown or has no configured
// password. Without this, an unknown username would skip bcrypt entirely
// and leak existence via response time. The plaintext is irrelevant; the
// goal is only to spend a comparable amount of CPU.
const dummyBcryptHash = "$2a$10$CwTycUXWue0Thq9StjUM0uJ8.8kQcXG1V0z7mQpQuQ2bH0X3Yj3GO"

// loginFailureWindow caps how recent failed login attempts are kept when
// computing the per-IP backoff threshold.
const loginFailureWindow = 15 * time.Minute

// loginFailureThreshold is the number of failures within loginFailureWindow
// before further attempts from the same IP are throttled.
const loginFailureThreshold = 5

// loginLockoutDuration is how long a client IP is locked out after exceeding
// loginFailureThreshold.
const loginLockoutDuration = 15 * time.Minute

// ctxKey is a private type used for request-context keys to avoid collisions.
type ctxKey int

const (
	ctxKeySession ctxKey = iota
)

// loginRequest is the JSON body for POST /api/login.
type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// loginResponse is the JSON body returned by POST /api/login on success.
type loginResponse struct {
	Role      string    `json:"role"`
	ExpiresAt time.Time `json:"expires_at"`
}

// sessionFromCtx returns the authenticated session associated with the
// request, if any.
func sessionFromCtx(ctx context.Context) (*storage.Session, bool) {
	s, ok := ctx.Value(ctxKeySession).(*storage.Session)
	return s, ok
}

// generateToken produces a 32-byte URL-safe base64 token.
func generateToken() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// verifyCredentials checks (username, password) against the configured bcrypt
// hashes and returns the role on success.
//
// To minimize the user-existence side channel, every invocation runs exactly
// one bcrypt comparison: against the configured hash for known usernames or
// against a fixed dummy hash for unknown ones / users with no configured
// password. This keeps the bcrypt CPU cost roughly constant regardless of
// whether the username exists.
func verifyCredentials(cfg config.AuthConfig, username, password string) (string, bool) {
	hash := dummyBcryptHash
	role := ""
	switch username {
	case storage.SessionRoleAdmin:
		if cfg.AdminPasswordHash != "" {
			hash = cfg.AdminPasswordHash
			role = storage.SessionRoleAdmin
		}
	case storage.SessionRoleUser:
		if cfg.UserPasswordHash != "" {
			hash = cfg.UserPasswordHash
			role = storage.SessionRoleUser
		}
	}
	match := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
	if !match || role == "" {
		return "", false
	}
	return role, true
}

// handleLogin issues a session cookie on valid credentials.
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if !s.cfg.Auth.Enabled {
		// With auth disabled the SPA can call /api/login as a no-op so the
		// flow remains uniform; respond as admin.
		writeJSON(w, s.logger, http.StatusOK, loginResponse{
			Role:      storage.SessionRoleAdmin,
			ExpiresAt: time.Now().Add(s.cfg.Auth.SessionTTL),
		})
		return
	}

	ip := clientIP(r)
	if s.loginLimiter.locked(ip, time.Now()) {
		s.logger.Warn("api: login rate-limited", "ip", ip)
		writeProblem(w, s.logger, http.StatusTooManyRequests, errTypeRateLimited,
			"too many failed login attempts; try again later")
		return
	}

	var req loginRequest
	if err := readJSON(w, r, s.logger, &req); err != nil {
		return
	}
	role, ok := verifyCredentials(s.cfg.Auth, strings.TrimSpace(req.Username), req.Password)
	if !ok {
		s.loginLimiter.recordFailure(ip, time.Now())
		writeProblem(w, s.logger, http.StatusUnauthorized, errTypeUnauthorized,
			"invalid username or password")
		return
	}
	if s.deps.Repo == nil {
		writeProblem(w, s.logger, http.StatusServiceUnavailable, errTypeStorageDisabled,
			"authentication requires storage to be enabled")
		return
	}

	token, err := generateToken()
	if err != nil {
		s.logger.Error("api: failed to generate session token", "error", err)
		writeProblem(w, s.logger, http.StatusInternalServerError, errTypeInternal, "")
		return
	}
	now := time.Now()
	sess := &storage.Session{
		Token:     token,
		Role:      role,
		CreatedAt: now,
		ExpiresAt: now.Add(s.cfg.Auth.SessionTTL),
	}
	if err := s.deps.Repo.CreateSession(r.Context(), sess); err != nil {
		s.logger.Error("api: failed to persist session", "error", err)
		writeProblem(w, s.logger, http.StatusInternalServerError, errTypeInternal, "")
		return
	}

	s.loginLimiter.recordSuccess(ip)
	//nolint:gosec // Secure is intentionally configurable for local HTTP development
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    token,
		Path:     "/",
		Expires:  sess.ExpiresAt,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Secure:   s.cookieSecure(),
	})
	writeJSON(w, s.logger, http.StatusOK, loginResponse{
		Role:      role,
		ExpiresAt: sess.ExpiresAt,
	})
}

// handleLogout deletes the current session and clears the cookie.
func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie(sessionCookieName); err == nil && cookie.Value != "" && s.deps.Repo != nil {
		if err := s.deps.Repo.DeleteSession(r.Context(), cookie.Value); err != nil {
			s.logger.Warn("api: failed to delete session on logout", "error", err)
		}
	}
	//nolint:gosec // Secure is intentionally configurable for local HTTP development
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Secure:   s.cookieSecure(),
	})
	w.WriteHeader(http.StatusNoContent)
}

// cookieSecure resolves the Secure attribute for session cookies. Defaults
// to true (production-safe). When CookieSecure is explicitly set in YAML it
// is honored verbatim, allowing local-development HTTP loopback.
func (s *Server) cookieSecure() bool {
	if s.cfg.Auth.CookieSecure == nil {
		return true
	}
	return *s.cfg.Auth.CookieSecure
}

// clientIP extracts the client IP from the request. Falls back to the raw
// RemoteAddr when host:port parsing fails. The daemon is intended to run
// behind a reverse proxy or directly on loopback, so X-Forwarded-For is
// intentionally not honored to prevent spoofed throttling keys.
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// loginRateLimiter throttles password guessing on a per-IP basis. It is a
// minimal in-memory sliding-window tracker: failures older than
// loginFailureWindow are dropped on every check, and an IP that exceeds
// loginFailureThreshold within the window is locked out for
// loginLockoutDuration. A successful login resets the counter for that IP.
type loginRateLimiter struct {
	mu      sync.Mutex
	entries map[string]*loginFailureRecord
}

type loginFailureRecord struct {
	failures   []time.Time
	lockedTill time.Time
}

func newLoginRateLimiter() *loginRateLimiter {
	return &loginRateLimiter{entries: make(map[string]*loginFailureRecord)}
}

// locked reports whether the given IP is currently locked out. Also drops
// expired records to keep the map bounded in size. An amortized sweep of all
// entries prevents unbounded growth from slow brute-force IPs that never
// return after 1–4 failures.
func (l *loginRateLimiter) locked(ip string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.sweepStaleLocked(now)

	rec, ok := l.entries[ip]
	if !ok {
		return false
	}
	if now.Before(rec.lockedTill) {
		return true
	}
	rec.failures = pruneFailures(rec.failures, now.Add(-loginFailureWindow))
	if len(rec.failures) == 0 && rec.lockedTill.Before(now) {
		delete(l.entries, ip)
	}
	return false
}

// sweepStaleLocked removes entries whose failures have all expired and whose
// lockout period has ended. Called under l.mu.
func (l *loginRateLimiter) sweepStaleLocked(now time.Time) {
	cutoff := now.Add(-loginFailureWindow)
	for ip, rec := range l.entries {
		rec.failures = pruneFailures(rec.failures, cutoff)
		if len(rec.failures) == 0 && rec.lockedTill.Before(now) {
			delete(l.entries, ip)
		}
	}
}

// recordFailure registers a failed login. When the rolling failure count
// exceeds the threshold, the IP enters the lockout state.
func (l *loginRateLimiter) recordFailure(ip string, now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	rec, ok := l.entries[ip]
	if !ok {
		rec = &loginFailureRecord{}
		l.entries[ip] = rec
	}
	rec.failures = append(pruneFailures(rec.failures, now.Add(-loginFailureWindow)), now)
	if len(rec.failures) >= loginFailureThreshold {
		rec.lockedTill = now.Add(loginLockoutDuration)
		rec.failures = nil
	}
}

// recordSuccess clears any pending failures for the given IP.
func (l *loginRateLimiter) recordSuccess(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.entries, ip)
}

// pruneFailures returns failures more recent than cutoff, in place when
// possible to avoid extra allocation in the hot path.
func pruneFailures(failures []time.Time, cutoff time.Time) []time.Time {
	n := 0
	for _, t := range failures {
		if t.After(cutoff) {
			failures[n] = t
			n++
		}
	}
	return failures[:n]
}

// resolveSession looks up the session referenced by the request cookie,
// verifies expiry, and returns the session. When auth is disabled it
// returns a synthetic admin session so handlers can treat all requests
// uniformly.
func (s *Server) resolveSession(r *http.Request) (*storage.Session, error) {
	if !s.cfg.Auth.Enabled {
		return &storage.Session{
			Token:     "",
			Role:      storage.SessionRoleAdmin,
			CreatedAt: time.Now(),
			ExpiresAt: time.Now().Add(s.cfg.Auth.SessionTTL),
		}, nil
	}
	if s.deps.Repo == nil {
		return nil, errors.New("storage is not available")
	}
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil || cookie.Value == "" {
		return nil, errors.New("missing session cookie")
	}
	sess, err := s.deps.Repo.GetSession(r.Context(), cookie.Value)
	if err != nil {
		return nil, err
	}
	if !time.Now().Before(sess.ExpiresAt) {
		// Best-effort cleanup of the expired session.
		_ = s.deps.Repo.DeleteSession(r.Context(), sess.Token)
		return nil, errors.New("session expired")
	}
	return sess, nil
}

// requireAuth is middleware that rejects unauthenticated requests with 401.
func (s *Server) requireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sess, err := s.resolveSession(r)
		if err != nil {
			writeProblem(w, s.logger, http.StatusUnauthorized, errTypeUnauthorized,
				"authentication required")
			return
		}
		ctx := context.WithValue(r.Context(), ctxKeySession, sess)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// requireAdmin is middleware that requires the session role to be admin.
// It must be used downstream of requireAuth.
func (s *Server) requireAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sess, ok := sessionFromCtx(r.Context())
		if !ok || sess == nil {
			writeProblem(w, s.logger, http.StatusUnauthorized, errTypeUnauthorized,
				"authentication required")
			return
		}
		if sess.Role != storage.SessionRoleAdmin {
			writeProblem(w, s.logger, http.StatusForbidden, errTypeForbidden,
				"admin role required")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// runSessionPruner periodically removes expired sessions from the repository.
// It is started by Server.Run and exits on context cancellation.
func (s *Server) runSessionPruner(ctx context.Context) {
	if s.deps.Repo == nil {
		return
	}
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if removed, err := s.deps.Repo.PruneExpiredSessions(ctx, time.Now()); err != nil {
				s.logger.Warn("api: failed to prune expired sessions", "error", err)
			} else if removed > 0 {
				s.logger.Debug("api: pruned expired sessions", "count", removed)
			}
		}
	}
}
