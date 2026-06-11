package api

import (
	"context"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/vkochetkov/tobimaru/internal/config"
	"github.com/vkochetkov/tobimaru/internal/logging"
)

// redactedSecret is the placeholder substituted for sensitive fields in
// GET /api/config responses.
const redactedSecret = "***"

// configResponse is a redacted, JSON-friendly view of the loaded *config.Config.
type configResponse struct {
	Effective effectiveConfig `json:"effective"`
	Mutable   mutableConfig   `json:"mutable"`
}

// effectiveConfig mirrors the loaded YAML structure for the SPA "Configuration"
// view. Secrets are redacted.
type effectiveConfig struct {
	Log       config.LogConfig       `json:"log"`
	Monitor   config.MonitorConfig   `json:"monitor"`
	Detection config.DetectionConfig `json:"detection"`
	State     config.StateConfig     `json:"state"`
	Whitelist config.WhitelistConfig `json:"whitelist"`
	Storage   config.StorageConfig   `json:"storage"`
	API       redactedAPIConfig      `json:"api"`
}

// redactedAPIConfig is APIConfig with password hashes replaced by "***" when
// non-empty.
type redactedAPIConfig struct {
	Enabled         bool              `json:"enabled"`
	Listen          string            `json:"listen"`
	ReadTimeout     time.Duration     `json:"read_timeout_ns"`
	WriteTimeout    time.Duration     `json:"write_timeout_ns"`
	IdleTimeout     time.Duration     `json:"idle_timeout_ns"`
	ShutdownTimeout time.Duration     `json:"shutdown_timeout_ns"`
	CORS            config.CORSConfig `json:"cors"`
	Auth            redactedAuthBlock `json:"auth"`
}

type redactedAuthBlock struct {
	Enabled           bool          `json:"enabled"`
	SessionTTL        time.Duration `json:"session_ttl_ns"`
	AdminPasswordHash string        `json:"admin_password_hash"`
	UserPasswordHash  string        `json:"user_password_hash"`
}

// mutableConfig describes the small set of fields that PUT /api/config can
// change at runtime, plus their current values.
type mutableConfig struct {
	LogLevel             string        `json:"log_level"`
	DetectionEnabled     bool          `json:"detection_enabled"`
	DetectionDedupWindow time.Duration `json:"detection_dedup_window_ns"`
}

// mutableKeys lists the JSON field names that PUT /api/config accepts. It is
// the canonical source of truth for the unsupported_field validation below.
// Each field maps to: log_level→string, detection_enabled→bool,
// detection_dedup_window→duration string (e.g. "30s").
var mutableKeys = []string{
	"log_level",
	"detection_enabled",
	"detection_dedup_window",
}

// handleGetConfig serves GET /api/config.
func (s *Server) handleGetConfig(w http.ResponseWriter, _ *http.Request) {
	resp := configResponse{
		Effective: effectiveConfig{
			Log:       s.deps.Config.Log,
			Monitor:   s.deps.Config.Monitor,
			Detection: s.deps.Config.Detection,
			State:     s.deps.Config.State,
			Whitelist: s.deps.Config.Whitelist,
			Storage:   s.deps.Config.Storage,
			API: redactedAPIConfig{
				Enabled:         s.deps.Config.API.Enabled,
				Listen:          s.deps.Config.API.Listen,
				ReadTimeout:     s.deps.Config.API.ReadTimeout,
				WriteTimeout:    s.deps.Config.API.WriteTimeout,
				IdleTimeout:     s.deps.Config.API.IdleTimeout,
				ShutdownTimeout: s.deps.Config.API.ShutdownTimeout,
				CORS:            s.deps.Config.API.CORS,
				Auth: redactedAuthBlock{
					Enabled:           s.deps.Config.API.Auth.Enabled,
					SessionTTL:        s.deps.Config.API.Auth.SessionTTL,
					AdminPasswordHash: maskSecret(s.deps.Config.API.Auth.AdminPasswordHash),
					UserPasswordHash:  maskSecret(s.deps.Config.API.Auth.UserPasswordHash),
				},
			},
		},
		Mutable: s.currentMutable(),
	}
	writeJSON(w, s.logger, http.StatusOK, resp)
}

// handlePutConfig serves PUT /api/config (admin only). It applies a patch in
// memory; the YAML file on disk is never modified.
func (s *Server) handlePutConfig(w http.ResponseWriter, r *http.Request) { //nolint:gocyclo // sequential field validation is linear, not branching complexity
	// Enforce strict whitelist by parsing the body into a generic map first
	// and rejecting any unknown keys with a stable error type.
	var raw map[string]any
	if err := readJSON(w, r, s.logger, &raw); err != nil {
		return
	}
	for key := range raw {
		if !slices.Contains(mutableKeys, key) {
			writeProblem(w, s.logger, http.StatusBadRequest, errTypeUnsupportedField,
				"field "+key+" is not mutable at runtime")
			return
		}
	}

	if v, ok := raw["log_level"]; ok {
		level, ok := v.(string)
		if !ok || !logging.SetLevel(strings.TrimSpace(level)) {
			writeProblem(w, s.logger, http.StatusBadRequest, errTypeBadRequest,
				"log_level must be one of: debug, info, warn, error")
			return
		}
	}
	if v, ok := raw["detection_enabled"]; ok {
		b, ok := v.(bool)
		if !ok {
			writeProblem(w, s.logger, http.StatusBadRequest, errTypeBadRequest,
				"detection_enabled must be a boolean")
			return
		}
		s.detectionEnabled.Store(b)
		if s.deps.Detector != nil {
			s.deps.Detector.SetEnabled(b)
		}
	}
	if v, ok := raw["detection_dedup_window"]; ok {
		str, ok := v.(string)
		if !ok {
			writeProblem(w, s.logger, http.StatusBadRequest, errTypeBadRequest,
				"detection_dedup_window must be a duration string")
			return
		}
		dur, err := time.ParseDuration(str)
		if err != nil || dur <= 0 {
			writeProblem(w, s.logger, http.StatusBadRequest, errTypeBadRequest,
				"detection_dedup_window must be a positive duration string (e.g. 30s)")
			return
		}
		if s.deps.Detector != nil {
			s.deps.Detector.SetDedupWindow(dur)
		}
	}

	if s.deps.Repo != nil {
		// Persist mutable settings so they survive restarts.
		persistMutable(r.Context(), s, raw)
	}

	writeJSON(w, s.logger, http.StatusOK, s.currentMutable())
}

// currentMutable returns the current values of fields exposed by PUT /api/config.
func (s *Server) currentMutable() mutableConfig {
	out := mutableConfig{
		LogLevel:         logging.Level(),
		DetectionEnabled: s.detectionEnabled.Load(),
	}
	if s.deps.Detector != nil {
		out.DetectionDedupWindow = s.deps.Detector.DedupWindow()
	} else {
		out.DetectionDedupWindow = s.deps.Config.Detection.DedupWindow
	}
	return out
}

// persistMutable writes accepted mutable patch fields to the SQLite KV store.
// Failures are logged but not returned to the caller (best-effort persistence).
func persistMutable(ctx context.Context, s *Server, raw map[string]any) {
	if s.deps.Repo == nil {
		return
	}
	for _, key := range mutableKeys {
		v, ok := raw[key]
		if !ok {
			continue
		}
		val, ok := stringifyValue(v)
		if !ok {
			continue
		}
		if err := s.deps.Repo.SetConfig(ctx, "runtime."+key, val); err != nil {
			s.logger.Warn("api: failed to persist mutable config",
				"key", key, "error", err)
		}
	}
}

// stringifyValue converts an interface{} from a JSON map into the string we
// store in the KV table. Returns (s, true) on success.
func stringifyValue(v any) (string, bool) {
	switch x := v.(type) {
	case string:
		return x, true
	case bool:
		return strconv.FormatBool(x), true
	default:
		return "", false
	}
}

// maskSecret returns "***" for non-empty inputs and "" otherwise.
func maskSecret(s string) string {
	if s == "" {
		return ""
	}
	return redactedSecret
}
