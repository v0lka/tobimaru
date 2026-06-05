package api

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/vkochetkov/tobimaru/internal/config"
	"github.com/vkochetkov/tobimaru/internal/storage"
)

// sessionCookieName is the HttpOnly cookie that carries the opaque session
// token between the SPA and the API.
const sessionCookieName = "tobimaru_session"

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
func verifyCredentials(cfg config.AuthConfig, username, password string) (string, bool) {
	switch username {
	case storage.SessionRoleAdmin:
		if cfg.AdminPasswordHash == "" {
			return "", false
		}
		if err := bcrypt.CompareHashAndPassword([]byte(cfg.AdminPasswordHash), []byte(password)); err == nil {
			return storage.SessionRoleAdmin, true
		}
	case storage.SessionRoleUser:
		if cfg.UserPasswordHash == "" {
			return "", false
		}
		if err := bcrypt.CompareHashAndPassword([]byte(cfg.UserPasswordHash), []byte(password)); err == nil {
			return storage.SessionRoleUser, true
		}
	}
	// Equalize timing for a non-existent username.
	_ = subtle.ConstantTimeCompare([]byte(username), []byte("admin"))
	return "", false
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

	var req loginRequest
	if err := readJSON(w, r, s.logger, &req); err != nil {
		return
	}
	role, ok := verifyCredentials(s.cfg.Auth, strings.TrimSpace(req.Username), req.Password)
	if !ok {
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

	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    token,
		Path:     "/",
		Expires:  sess.ExpiresAt,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Secure:   r.TLS != nil,
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
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Secure:   r.TLS != nil,
	})
	w.WriteHeader(http.StatusNoContent)
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
