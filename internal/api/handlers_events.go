package api

import (
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/vkochetkov/tobimaru/internal/detector"
	"github.com/vkochetkov/tobimaru/internal/storage"
)

// maxEventsPageSize caps how many events a single GET /api/events response
// will return so that pathological clients cannot OOM the daemon.
const maxEventsPageSize = 1000

// defaultEventsPageSize is used when the limit query parameter is absent.
const defaultEventsPageSize = 100

// statsResponse aggregates events for the dashboard Stats page.
type statsResponse struct {
	WindowSeconds int             `json:"window_seconds"`
	ByType        []countBucket   `json:"by_type"`
	BySeverity    []countBucket   `json:"by_severity"`
	PerHour       []timeBucketRow `json:"per_hour"`
}

type countBucket struct {
	Key   string `json:"key"`
	Count int64  `json:"count"`
}

type timeBucketRow struct {
	HourStart time.Time `json:"hour_start"`
	Count     int64     `json:"count"`
}

// statsCacheEntry holds a cached stats response with its TTL metadata.
type statsCacheEntry struct {
	windowSeconds int
	expiresAt     time.Time
	value         statsResponse
}

// handleListEvents serves GET /api/events with filters from EventFilter.
func (s *Server) handleListEvents(w http.ResponseWriter, r *http.Request) {
	if s.deps.Repo == nil {
		writeProblem(w, s.logger, http.StatusServiceUnavailable, errTypeStorageDisabled,
			"storage is disabled")
		return
	}
	filter := parseEventFilter(r)

	events, err := s.deps.Repo.ListEvents(r.Context(), filter)
	if err != nil {
		s.logger.Warn("api: ListEvents failed", "error", err)
		writeProblem(w, s.logger, http.StatusInternalServerError, errTypeInternal, "")
		return
	}
	total, err := s.deps.Repo.CountEvents(r.Context(), filter)
	if err != nil {
		// CountEvents failure is non-fatal; expose the page only.
		s.logger.Warn("api: CountEvents failed", "error", err)
		total = int64(len(events))
	}

	out := make([]eventDTO, 0, len(events))
	for _, ev := range events {
		out = append(out, newEventDTO(ev))
	}
	writeJSON(w, s.logger, http.StatusOK, listResponse{Items: out, Total: total})
}

// handleStats serves GET /api/stats — the dashboard charts data source.
func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	if s.deps.Repo == nil {
		writeProblem(w, s.logger, http.StatusServiceUnavailable, errTypeStorageDisabled,
			"storage is disabled")
		return
	}
	q := r.URL.Query()
	windowSecondsRaw := q.Get("window_seconds")
	windowSeconds, _ := strconv.Atoi(windowSecondsRaw)
	if windowSeconds <= 0 || windowSeconds > 7*24*3600 {
		windowSeconds = 24 * 3600
	}

	// Check 30-second cache.
	now := time.Now()
	s.statsMu.Lock()
	if s.statsCache != nil && s.statsCache.windowSeconds == windowSeconds && now.Before(s.statsCache.expiresAt) {
		resp := s.statsCache.value
		s.statsMu.Unlock()
		writeJSON(w, s.logger, http.StatusOK, resp)
		return
	}
	s.statsMu.Unlock()

	since := now.Add(-time.Duration(windowSeconds) * time.Second)

	events, err := s.deps.Repo.ListEvents(r.Context(), storage.EventFilter{
		Since: since,
		Limit: maxEventsPageSize * 10, // upper bound for aggregation
	})
	if err != nil {
		s.logger.Warn("api: stats ListEvents failed", "error", err)
		writeProblem(w, s.logger, http.StatusInternalServerError, errTypeInternal, "")
		return
	}

	byType := make(map[string]int64)
	bySeverity := make(map[string]int64)
	perHour := make(map[time.Time]int64)
	for _, ev := range events {
		byType[ev.EventType]++
		bySeverity[ev.Severity.String()]++
		hour := ev.Timestamp.UTC().Truncate(time.Hour)
		perHour[hour]++
	}

	resp := statsResponse{
		WindowSeconds: windowSeconds,
		ByType:        bucketize(byType),
		BySeverity:    bucketize(bySeverity),
		PerHour:       bucketizeHours(perHour),
	}

	// Store in cache.
	s.statsMu.Lock()
	s.statsCache = &statsCacheEntry{
		windowSeconds: windowSeconds,
		expiresAt:     time.Now().Add(30 * time.Second),
		value:         resp,
	}
	s.statsMu.Unlock()

	writeJSON(w, s.logger, http.StatusOK, resp)
}

// parseEventFilter extracts filter knobs from query parameters.
func parseEventFilter(r *http.Request) storage.EventFilter {
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	if limit <= 0 {
		limit = defaultEventsPageSize
	}
	if limit > maxEventsPageSize {
		limit = maxEventsPageSize
	}
	offset, _ := strconv.Atoi(q.Get("offset"))
	if offset < 0 {
		offset = 0
	}
	minSeverity := parseSeverity(q.Get("min_severity"))
	return storage.EventFilter{
		Since:       parseTimeQuery(q.Get("since")),
		Until:       parseTimeQuery(q.Get("until")),
		EventType:   strings.TrimSpace(q.Get("event_type")),
		MinSeverity: minSeverity,
		Limit:       limit,
		Offset:      offset,
	}
}

// parseSeverity maps a string severity name to a detector.Severity. Returns 0
// (info) when unknown, which means "no filter" because the storage layer
// only filters when MinSeverity > 0.
func parseSeverity(s string) detector.Severity {
	switch strings.ToLower(s) {
	case "info":
		return detector.SeverityInfo
	case "warning":
		return detector.SeverityWarning
	case "critical":
		return detector.SeverityCritical
	default:
		return 0
	}
}

// eventFilterAll returns an empty filter that matches every event.
func eventFilterAll() storage.EventFilter { return storage.EventFilter{} }

// eventFilterSince returns a filter restricted to events at or after t.
func eventFilterSince(t time.Time) storage.EventFilter {
	return storage.EventFilter{Since: t}
}

// bucketize converts a count map into a sorted slice for stable JSON output.
func bucketize(m map[string]int64) []countBucket {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]countBucket, 0, len(keys))
	for _, k := range keys {
		out = append(out, countBucket{Key: k, Count: m[k]})
	}
	return out
}

// bucketizeHours converts an hour-bucket count map into a chronological slice.
func bucketizeHours(m map[time.Time]int64) []timeBucketRow {
	out := make([]timeBucketRow, 0, len(m))
	for t, c := range m {
		out = append(out, timeBucketRow{HourStart: t, Count: c})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].HourStart.Before(out[j].HourStart) })
	return out
}
