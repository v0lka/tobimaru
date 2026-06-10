package api

import (
	"log/slog"
	"net/http"
	"runtime/debug"
	"slices"
	"strings"
	"time"
)

// statusRecorder wraps http.ResponseWriter to capture the status code so
// the request logger can log it.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

// WriteHeader records the status before delegating.
func (sr *statusRecorder) WriteHeader(code int) {
	sr.status = code
	sr.ResponseWriter.WriteHeader(code)
}

// Flush forwards to the underlying writer when it supports flushing. Required
// for SSE streaming through this middleware.
func (sr *statusRecorder) Flush() {
	if f, ok := sr.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Unwrap exposes the underlying response writer for http.ResponseController.
func (sr *statusRecorder) Unwrap() http.ResponseWriter { return sr.ResponseWriter }

// requestLogger logs every request at debug level (or warn for 5xx).
func requestLogger(logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
			next.ServeHTTP(rec, r)
			dur := time.Since(start)
			level := slog.LevelDebug
			if rec.status >= http.StatusInternalServerError {
				level = slog.LevelWarn
			}
			logger.Log(r.Context(), level, "api request",
				"method", r.Method,
				"path", r.URL.Path,
				"status", rec.status,
				"duration", dur,
			)
		})
	}
}

// recoverer converts panics in handlers into 500 responses and logs the stack.
func recoverer(logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if rec := recover(); rec != nil {
					logger.Error("api: handler panic recovered",
						"path", r.URL.Path,
						"panic", rec,
						"stack", string(debug.Stack()),
					)
					writeProblem(w, logger, http.StatusInternalServerError, errTypeInternal, "")
				}
			}()
			next.ServeHTTP(w, r)
		})
	}
}

// corsMiddleware applies a minimal CORS policy. When AllowedOrigins is empty
// no CORS headers are emitted (browsers enforce same-origin). Otherwise the
// requested Origin is echoed back if it is in the allow-list.
func corsMiddleware(allowed []string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")
			if origin != "" && len(allowed) > 0 && slices.Contains(allowed, origin) {
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Set("Vary", "Origin")
				w.Header().Set("Access-Control-Allow-Credentials", "true")
				w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
				w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Accept")
				if r.Method == http.MethodOptions {
					w.WriteHeader(http.StatusNoContent)
					return
				}
			} else if origin != "" && len(allowed) > 0 && r.Method == http.MethodOptions {
				// Origin not allowed: short-circuit preflight without headers.
				w.WriteHeader(http.StatusNoContent)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// noCacheAPI adds Cache-Control headers to every /api/ JSON response.
func noCacheAPI(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") {
			w.Header().Set("Cache-Control", "no-store")
			w.Header().Set("Pragma", "no-cache")
		}
		next.ServeHTTP(w, r)
	})
}
