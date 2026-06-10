package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// sseKeepaliveInterval is the interval between SSE comment keepalives that
// prevent intermediaries from idling out the connection.
const sseKeepaliveInterval = 15 * time.Second

// handleStream serves GET /api/stream as a Server-Sent Events feed. The
// caller's context is bound to the request, so closing the browser tab or
// the daemon shutting down both terminate the loop.
func (s *Server) handleStream(w http.ResponseWriter, r *http.Request) {
	if s.deps.Hub == nil {
		writeProblem(w, s.logger, http.StatusServiceUnavailable, errTypeInternal,
			"sse hub not initialized")
		return
	}

	flusher, ok := w.(http.Flusher)
	if !ok {
		// chi's middleware wraps the writer but the wrapper implements
		// http.Flusher via Unwrap; this fallback is defensive.
		writeProblem(w, s.logger, http.StatusInternalServerError, errTypeInternal,
			"streaming not supported by underlying ResponseWriter")
		return
	}

	// Disable per-write deadline so SSE can stay open indefinitely.
	rc := http.NewResponseController(w)
	_ = rc.SetWriteDeadline(time.Time{})

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache, no-transform")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no") // for nginx, harmless elsewhere
	w.WriteHeader(http.StatusOK)
	flusher.Flush()

	msgCh, unsubscribe := s.deps.Hub.Subscribe()
	defer unsubscribe()

	keepalive := time.NewTicker(sseKeepaliveInterval)
	defer keepalive.Stop()

	// Send a hello frame so the client immediately knows the stream is live.
	writeSSEEvent(w, "hello", map[string]any{"time": time.Now()})
	flusher.Flush()

	for {
		select {
		case <-r.Context().Done():
			return
		case <-keepalive.C:
			if _, err := fmt.Fprintf(w, ": keepalive\n\n"); err != nil {
				return
			}
			flusher.Flush()
		case msg, ok := <-msgCh:
			if !ok {
				return
			}
			writeSSEEvent(w, msg.Type, msg.Data)
			flusher.Flush()
		}
	}
}

// writeSSEEvent writes a single SSE event in the standard `event:`/`data:` form.
// Any JSON-marshal error is logged via the dropped event; we cannot return one
// to the caller mid-stream.
func writeSSEEvent(w http.ResponseWriter, event string, payload any) {
	body, err := json.Marshal(payload)
	if err != nil {
		body = []byte(`null`)
	}
	if event != "" {
		_, _ = fmt.Fprintf(w, "event: %s\n", event)
	}
	_, _ = fmt.Fprintf(w, "data: %s\n\n", body)
}
