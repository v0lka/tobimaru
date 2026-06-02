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

func validate(cfg *Config) error {
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
