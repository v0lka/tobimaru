package api

import (
	"net/http"
	"strconv"
	"strings"
	"time"
)

// strTrue is the canonical string for boolean "true" in query parameters.
const strTrue = "true"

// listResponse is a thin envelope for paginated list endpoints. Total may be
// -1 when the underlying source does not provide a separate count.
type listResponse struct {
	Items any   `json:"items"`
	Total int64 `json:"total"`
}

// handleListAPs serves GET /api/aps with optional filters: ssid, channel, since.
func (s *Server) handleListAPs(w http.ResponseWriter, r *http.Request) {
	if s.deps.State == nil {
		writeProblem(w, s.logger, http.StatusServiceUnavailable, errTypeStateDisabled,
			"state engine is disabled")
		return
	}
	q := r.URL.Query()
	ssidFilter := strings.ToLower(q.Get("ssid"))
	channelFilter, _ := strconv.Atoi(q.Get("channel"))
	since := parseTimeQuery(q.Get("since"))

	all := s.deps.State.APs().All()
	out := make([]apDTO, 0, len(all))
	for _, ap := range all {
		if ssidFilter != "" && !strings.Contains(strings.ToLower(ap.SSID), ssidFilter) {
			continue
		}
		if channelFilter > 0 && ap.Channel != channelFilter {
			continue
		}
		if !since.IsZero() && ap.LastSeen.Before(since) {
			continue
		}
		out = append(out, newAPDTO(ap))
	}
	writeJSON(w, s.logger, http.StatusOK, listResponse{Items: out, Total: int64(len(out))})
}

// handleListClients serves GET /api/clients with optional filters:
// associated, bssid, since.
func (s *Server) handleListClients(w http.ResponseWriter, r *http.Request) {
	if s.deps.State == nil {
		writeProblem(w, s.logger, http.StatusServiceUnavailable, errTypeStateDisabled,
			"state engine is disabled")
		return
	}
	q := r.URL.Query()
	associatedOnly := q.Get("associated") == strTrue
	bssidFilter := strings.ToUpper(q.Get("bssid"))
	since := parseTimeQuery(q.Get("since"))

	all := s.deps.State.Clients().All()
	out := make([]clientDTO, 0, len(all))
	for _, c := range all {
		if associatedOnly && !c.Associated {
			continue
		}
		if bssidFilter != "" && (c.BSSID == nil || strings.ToUpper(c.BSSID.String()) != bssidFilter) {
			continue
		}
		if !since.IsZero() && c.LastSeen.Before(since) {
			continue
		}
		out = append(out, newClientDTO(c))
	}
	writeJSON(w, s.logger, http.StatusOK, listResponse{Items: out, Total: int64(len(out))})
}

// parseTimeQuery parses an RFC3339 timestamp from a query string, returning
// the zero time on failure.
func parseTimeQuery(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}
	}
	return t
}
