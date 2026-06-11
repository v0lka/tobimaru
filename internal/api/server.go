package api

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"

	"github.com/vkochetkov/tobimaru/internal/api/web"
	"github.com/vkochetkov/tobimaru/internal/capture"
	"github.com/vkochetkov/tobimaru/internal/config"
	"github.com/vkochetkov/tobimaru/internal/detector"
	"github.com/vkochetkov/tobimaru/internal/state"
	"github.com/vkochetkov/tobimaru/internal/storage"
)

// Deps groups the runtime dependencies the API server needs. Every field is
// optional except Logger and Config: when a dependency is nil, related
// endpoints respond with 503 problem+json so the SPA can degrade gracefully.
type Deps struct {
	Config    *config.Config
	State     *state.Engine
	Repo      storage.Repository
	Detector  *detector.Engine
	Pipeline  *capture.Pipeline
	Hub       *Hub
	StartTime time.Time
	Logger    *slog.Logger
}

// Server wraps the chi router and the standard library http.Server so the
// orchestrator (cmd/tobimaru) can start, run, and gracefully stop the API.
type Server struct {
	cfg    config.APIConfig
	deps   Deps
	logger *slog.Logger

	router *chi.Mux
	httpd  *http.Server

	// detectionEnabled mirrors deps.Config.Detection.Enabled but can be
	// flipped at runtime via PUT /api/config. Detection rules still run
	// regardless; this flag is reflected in /api/status and persisted in
	// the SQLite KV store.
	detectionEnabled atomic.Bool

	// statsMu guards statsCache for the 30-second stats caching window.
	statsMu    sync.Mutex
	statsCache *statsCacheEntry

	// loginLimiter throttles failed login attempts on a per-IP basis.
	loginLimiter *loginRateLimiter
}

// NewServer builds a Server with the provided configuration and dependencies.
// It returns an error when required dependencies are missing.
func NewServer(cfg config.APIConfig, deps Deps) (*Server, error) {
	if deps.Logger == nil {
		return nil, errors.New("api: Deps.Logger is required")
	}
	if deps.Config == nil {
		return nil, errors.New("api: Deps.Config is required")
	}
	if cfg.Auth.Enabled && deps.Repo == nil {
		return nil, errors.New("api: auth.enabled requires storage.enabled (Deps.Repo is nil)")
	}
	s := &Server{
		cfg:          cfg,
		deps:         deps,
		logger:       deps.Logger.With("component", "api"),
		loginLimiter: newLoginRateLimiter(),
	}
	s.detectionEnabled.Store(deps.Config.Detection.Enabled)
	s.router = s.buildRouter()
	s.httpd = &http.Server{
		Addr:              cfg.Listen,
		Handler:           s.router,
		ReadTimeout:       cfg.ReadTimeout,
		ReadHeaderTimeout: cfg.ReadTimeout,
		WriteTimeout:      cfg.WriteTimeout,
		IdleTimeout:       cfg.IdleTimeout,
		ErrorLog:          slog.NewLogLogger(s.logger.Handler(), slog.LevelWarn),
	}
	return s, nil
}

// buildRouter constructs the chi router with middleware stack and routes.
func (s *Server) buildRouter() *chi.Mux {
	r := chi.NewRouter()

	r.Use(chimw.RequestID)
	r.Use(recoverer(s.logger))
	r.Use(requestLogger(s.logger))
	r.Use(corsMiddleware(s.cfg.CORS.AllowedOrigins))
	r.Use(noCacheAPI)

	// Public routes.
	r.Get("/api/status", s.handleStatus)
	r.Post("/api/login", s.handleLogin)
	r.Post("/api/logout", s.handleLogout)

	// Authenticated read routes.
	r.Group(func(r chi.Router) {
		r.Use(s.requireAuth)
		r.Get("/api/aps", s.handleListAPs)
		r.Get("/api/clients", s.handleListClients)
		r.Get("/api/events", s.handleListEvents)
		r.Get("/api/stats", s.handleStats)
		r.Get("/api/whitelist", s.handleListWhitelist)
		r.Get("/api/blacklist", s.handleListBlacklist)
		r.Get("/api/config", s.handleGetConfig)
		r.Get("/api/stream", s.handleStream)
	})

	// Admin-only routes.
	r.Group(func(r chi.Router) {
		r.Use(s.requireAuth)
		r.Use(s.requireAdmin)
		r.Put("/api/config", s.handlePutConfig)
		r.Post("/api/whitelist", s.handleAddWhitelist)
		r.Delete("/api/whitelist/{mac}", s.handleDeleteWhitelist)
		r.Post("/api/blacklist", s.handleAddBlacklist)
		r.Delete("/api/blacklist/{mac}", s.handleDeleteBlacklist)
	})

	// Embedded SPA — must be mounted last so /api/ routes win.
	spa := web.Handler()
	r.NotFound(func(w http.ResponseWriter, r *http.Request) {
		// Routes under /api/ that miss return JSON.
		if isAPIPath(r.URL.Path) {
			writeProblem(w, s.logger, http.StatusNotFound, errTypeNotFound, "")
			return
		}
		spa.ServeHTTP(w, r)
	})
	r.MethodNotAllowed(func(w http.ResponseWriter, r *http.Request) {
		writeProblem(w, s.logger, http.StatusMethodNotAllowed, errTypeMethodNotAllowed, "")
	})

	return r
}

// isAPIPath reports whether p is under /api/.
func isAPIPath(p string) bool {
	const prefix = "/api/"
	return len(p) >= len(prefix) && p[:len(prefix)] == prefix
}

// Run starts the HTTP server and blocks until ctx is canceled or the server
// fails. It also runs the session pruner goroutine.
func (s *Server) Run(ctx context.Context) error {
	pruneCtx, pruneCancel := context.WithCancel(ctx)
	defer pruneCancel()
	go s.runSessionPruner(pruneCtx)

	s.logger.Info("api server listening",
		"addr", s.cfg.Listen,
		"auth_enabled", s.cfg.Auth.Enabled,
	)

	errCh := make(chan error, 1)
	go func() {
		err := s.httpd.ListenAndServe()
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
			return
		}
		errCh <- nil
	}()

	select {
	case <-ctx.Done():
		return s.shutdownInternal()
	case err := <-errCh:
		if err != nil {
			return fmt.Errorf("api server: %w", err)
		}
		return nil
	}
}

// Shutdown gracefully stops the HTTP server. Repeated calls are safe;
// a server that was already shut down returns nil.
func (s *Server) Shutdown(ctx context.Context) error {
	if s.httpd == nil {
		return nil
	}
	if err := s.httpd.Shutdown(ctx); err != nil {
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return fmt.Errorf("api: shutdown: %w", err)
	}
	return nil
}

// shutdownInternal applies the configured ShutdownTimeout when ctx triggers
// the natural exit path of Run.
func (s *Server) shutdownInternal() error {
	ctx, cancel := context.WithTimeout(context.Background(), s.cfg.ShutdownTimeout)
	defer cancel()
	return s.Shutdown(ctx)
}

// SetDetectionEnabled updates the runtime detection toggle and persists the
// change to the in-memory atomic flag that /api/status reports. Used during
// startup to restore the persisted value from the KV store.
func (s *Server) SetDetectionEnabled(v bool) {
	s.detectionEnabled.Store(v)
}
