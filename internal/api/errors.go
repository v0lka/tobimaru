// Package api implements the HTTP API server, middleware, authentication,
// SSE event hub, and embedded SPA handler for the Tobimaru WiFi Watchdog.
//
// Routes are mounted under /api/ and the SPA is served from / with a
// catch-all fallback to index.html for client-side routing. The package is
// consumed only by cmd/tobimaru, which constructs Server with the runtime
// dependencies (state engine, repository, capture pipeline, detection engine,
// loaded config, SSE hub, and logger).
package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
)

// problemDetails is an RFC 7807-style error envelope used for every API
// failure response. Keeping a stable shape simplifies the SPA error UI.
type problemDetails struct {
	Type   string `json:"type"`
	Title  string `json:"title"`
	Status int    `json:"status"`
	Detail string `json:"detail,omitempty"`
}

// Error type slugs used by problemDetails.Type for stable client-side handling.
const (
	errTypeBadRequest        = "bad_request"
	errTypeUnauthorized      = "unauthorized"
	errTypeForbidden         = "forbidden"
	errTypeNotFound          = "not_found"
	errTypeMethodNotAllowed  = "method_not_allowed"
	errTypeInternal          = "internal_error"
	errTypeUnsupportedField  = "unsupported_field"
	errTypeStorageDisabled   = "storage_disabled"
	errTypeStateDisabled     = "state_disabled"
	errTypeDetectionDisabled = "detection_disabled"
)

// writeProblem writes an RFC 7807-style JSON error response.
func writeProblem(w http.ResponseWriter, logger *slog.Logger, status int, slug, detail string) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	body := problemDetails{
		Type:   slug,
		Title:  http.StatusText(status),
		Status: status,
		Detail: detail,
	}
	if err := json.NewEncoder(w).Encode(body); err != nil && logger != nil {
		logger.Warn("api: failed to write problem response", "error", err)
	}
}

// writeJSON writes a JSON response with the given status code.
func writeJSON(w http.ResponseWriter, logger *slog.Logger, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if payload == nil {
		return
	}
	if err := json.NewEncoder(w).Encode(payload); err != nil && logger != nil {
		logger.Warn("api: failed to write JSON response", "error", err)
	}
}

// readJSON decodes the request body into dst with strict field handling and
// a small size cap. It writes a 400 problem response and returns an error on
// failure; callers should return immediately when a non-nil error is returned.
func readJSON(w http.ResponseWriter, r *http.Request, logger *slog.Logger, dst any) error {
	const maxBodyBytes = 1 << 16 // 64 KiB
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		writeProblem(w, logger, http.StatusBadRequest, errTypeBadRequest,
			fmt.Sprintf("invalid JSON body: %v", err))
		return err
	}
	if dec.More() {
		err := errors.New("request body must contain a single JSON value")
		writeProblem(w, logger, http.StatusBadRequest, errTypeBadRequest, err.Error())
		return err
	}
	return nil
}
