package config

import "errors"

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
	ErrInvalidLearningDuration = errors.New("whitelist.auto_learning.duration must be positive when enabled (0 uses default; negative is rejected)")
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
	}

	// Auto-learning validation (only when enabled).
	if cfg.Whitelist.AutoLearning.Enabled {
		if cfg.Whitelist.AutoLearning.Duration <= 0 {
			errs = append(errs, ErrInvalidLearningDuration)
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
