package config

import (
	"errors"
	"net"
	"strings"
)

var validLogLevels = map[string]bool{
	LogLevelDebug: true,
	LogLevelInfo:  true,
	LogLevelWarn:  true,
	LogLevelError: true,
}

var validLogFormats = map[string]bool{
	LogFormatText: true,
	LogFormatJSON: true,
}

// Sentinel errors for state, whitelist, and storage validation.
//
// Note on "must be positive" semantics: applyDefaults runs before validate,
// and treats a zero value as "unset" by replacing it with the default.
// Therefore these errors fire only on explicitly negative values that
// survive defaulting.
var (
	ErrInvalidStateTTL         = errors.New("state.ttl must be positive when state is enabled (0 uses default; negative is rejected)")
	ErrInvalidSweepInterval    = errors.New("state.sweep_interval must be positive when state is enabled (0 uses default; negative is rejected)")
	ErrInvalidStoragePath      = errors.New("storage.path is required when storage is enabled")
	ErrInvalidSnapshotInterval = errors.New("storage.snapshot_interval must be positive when storage is enabled (0 uses default; negative is rejected)")
	ErrInvalidMaxSnapshots     = errors.New("storage.max_snapshots must be >= 0 when storage is enabled (0 uses default; negative is rejected)")
	ErrInvalidMaxEvents        = errors.New("storage.max_events must be >= 0 when storage is enabled (0 uses default; negative is rejected)")
	ErrInvalidLearningDuration = errors.New("whitelist.auto_learning.duration must be positive when enabled (0 uses default; negative is rejected)")
	ErrInvalidAPIListen        = errors.New("api.listen must be a valid host:port when api is enabled")
	ErrInvalidAPITimeout       = errors.New("api.{read,write,idle,shutdown}_timeout must be positive when api is enabled")
	ErrMissingAdminHash        = errors.New("api.auth.admin_password_hash is required when api.auth is enabled")
	ErrInvalidPasswordHash     = errors.New("api.auth password hash must look like a bcrypt hash ($2a$..., $2b$..., or $2y$...)")
)

func validate(cfg *Config) error { //nolint:gocyclo // sequential field validation, linear flow
	var errs []error

	if cfg.Monitor.Interface == "" {
		errs = append(errs, ErrMissingInterface)
	}
	if !validLogLevels[cfg.Log.Level] {
		errs = append(errs, ErrInvalidLogLevel)
	}
	if !validLogFormats[cfg.Log.Format] {
		errs = append(errs, ErrInvalidLogFormat)
	}
	if cfg.Monitor.Capture.Snaplen <= 0 {
		errs = append(errs, ErrInvalidSnaplen)
	}
	if cfg.Monitor.Capture.BufferSize <= 0 {
		errs = append(errs, ErrInvalidBufferSize)
	}
	if cfg.Monitor.Capture.Timeout <= 0 {
		errs = append(errs, ErrInvalidTimeout)
	}

	// State validation (only when enabled).
	if cfg.State.Enabled {
		if cfg.State.TTL <= 0 {
			errs = append(errs, ErrInvalidStateTTL)
		}
		if cfg.State.SweepInterval <= 0 {
			errs = append(errs, ErrInvalidSweepInterval)
		}
	}

	// Storage validation (only when enabled).
	if cfg.Storage.Enabled {
		if cfg.Storage.Path == "" {
			errs = append(errs, ErrInvalidStoragePath)
		}
		if cfg.Storage.SnapshotInterval <= 0 {
			errs = append(errs, ErrInvalidSnapshotInterval)
		}
		if cfg.Storage.MaxSnapshots < 0 {
			errs = append(errs, ErrInvalidMaxSnapshots)
		}
		if cfg.Storage.MaxEvents < 0 {
			errs = append(errs, ErrInvalidMaxEvents)
		}
	}

	// Auto-learning validation (only when enabled).
	if cfg.Whitelist.AutoLearning.Enabled {
		if cfg.Whitelist.AutoLearning.Duration <= 0 {
			errs = append(errs, ErrInvalidLearningDuration)
		}
	}

	// API validation (only when enabled).
	if cfg.API.Enabled {
		if _, _, err := net.SplitHostPort(cfg.API.Listen); err != nil {
			errs = append(errs, ErrInvalidAPIListen)
		}
		if cfg.API.ReadTimeout <= 0 || cfg.API.WriteTimeout <= 0 ||
			cfg.API.IdleTimeout <= 0 || cfg.API.ShutdownTimeout <= 0 {
			errs = append(errs, ErrInvalidAPITimeout)
		}
		if cfg.API.Auth.Enabled {
			if cfg.API.Auth.AdminPasswordHash == "" {
				errs = append(errs, ErrMissingAdminHash)
			} else if !looksLikeBcrypt(cfg.API.Auth.AdminPasswordHash) {
				errs = append(errs, ErrInvalidPasswordHash)
			}
			if cfg.API.Auth.UserPasswordHash != "" && !looksLikeBcrypt(cfg.API.Auth.UserPasswordHash) {
				errs = append(errs, ErrInvalidPasswordHash)
			}
		}
	}

	if len(errs) > 0 {
		return &ValidationError{Errors: errs}
	}
	return nil
}

// IsValidationError checks if the error is a ValidationError.
func IsValidationError(err error) bool {
	var ve *ValidationError
	return errors.As(err, &ve)
}

// looksLikeBcrypt performs a syntactic check that the string is shaped like a
// bcrypt-encoded password hash. The full check (CompareHashAndPassword) is
// done at runtime by the auth layer; this guards against typos and missing
// hashes at startup.
func looksLikeBcrypt(s string) bool {
	if len(s) < 60 {
		return false
	}
	return strings.HasPrefix(s, "$2a$") ||
		strings.HasPrefix(s, "$2b$") ||
		strings.HasPrefix(s, "$2y$")
}
