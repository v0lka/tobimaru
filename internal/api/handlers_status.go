package api

import (
	"context"
	"net/http"
	"time"

	"github.com/vkochetkov/tobimaru/internal/platform"
	"github.com/vkochetkov/tobimaru/internal/version"
)

// statusResponse is the JSON shape of GET /api/status.
type statusResponse struct {
	Version             string                 `json:"version"`
	Commit              string                 `json:"commit"`
	BuildDate           string                 `json:"build_date"`
	StartedAt           time.Time              `json:"started_at"`
	UptimeSeconds       int64                  `json:"uptime_seconds"`
	MonitorInterface    string                 `json:"monitor_interface"`
	CurrentChannel      int                    `json:"current_channel"`
	ChannelHopping      bool                   `json:"channel_hopping"`
	Capabilities        platform.Capabilities  `json:"capabilities"`
	PlatformLimitations []string               `json:"platform_limitations"`
	Stats               statusStatsBlock       `json:"stats"`
	Detection           statusDetectionBlock   `json:"detection"`
	State               statusStateBlock       `json:"state"`
	Storage             statusStorageBlock     `json:"storage"`
	Auth                statusAuthBlock        `json:"auth"`
	Subscribers         statusSubscribersBlock `json:"subscribers"`
}

type statusStatsBlock struct {
	APs         int   `json:"aps"`
	Clients     int   `json:"clients"`
	EventsTotal int64 `json:"events_total"`
	Events24h   int64 `json:"events_24h"`
}

type statusDetectionBlock struct {
	Enabled     bool          `json:"enabled"`
	Rules       int           `json:"rules"`
	DedupWindow time.Duration `json:"dedup_window_ns"`
}

type statusStateBlock struct {
	Enabled       bool          `json:"enabled"`
	TTL           time.Duration `json:"ttl_ns"`
	SweepInterval time.Duration `json:"sweep_interval_ns"`
}

type statusStorageBlock struct {
	Enabled bool `json:"enabled"`
}

type statusAuthBlock struct {
	Enabled bool `json:"enabled"`
	// Role is the authenticated session's role when present, e.g. "admin" or
	// "user". Empty when auth is disabled or the request is anonymous; the
	// SPA uses it to gate admin-only UI affordances after a page reload.
	Role string `json:"role,omitempty"`
}

type statusSubscribersBlock struct {
	SSE int `json:"sse"`
}

// buildStatusResponse constructs the full status payload used by both the
// REST endpoint and the periodic SSE broadcast.
func (s *Server) buildStatusResponse(ctx context.Context) statusResponse {
	now := time.Now()
	resp := statusResponse{
		Version:          version.Version,
		Commit:           version.Commit,
		BuildDate:        version.Date,
		StartedAt:        s.deps.StartTime,
		UptimeSeconds:    int64(now.Sub(s.deps.StartTime).Seconds()),
		MonitorInterface: s.deps.Config.Monitor.Interface,
		ChannelHopping:   s.deps.Config.Monitor.ChannelHopping.Enabled,
		Detection: statusDetectionBlock{
			Enabled: s.detectionEnabled.Load(),
		},
		State: statusStateBlock{
			Enabled:       s.deps.Config.State.Enabled,
			TTL:           s.deps.Config.State.TTL,
			SweepInterval: s.deps.Config.State.SweepInterval,
		},
		Storage: statusStorageBlock{Enabled: s.deps.Config.Storage.Enabled},
		Auth:    statusAuthBlock{Enabled: s.cfg.Auth.Enabled},
	}
	// Surface the active session role so the SPA can keep admin-only
	// controls visible across reloads. Falls through silently when the
	// caller is anonymous or auth is disabled.
	if sess, ok := sessionFromCtx(ctx); ok && sess != nil {
		resp.Auth.Role = sess.Role
	}
	if s.deps.Hub != nil {
		resp.Subscribers.SSE = s.deps.Hub.SubscriberCount()
	}
	if s.deps.Pipeline != nil {
		resp.Capabilities = s.deps.Pipeline.Capabilities()
		resp.PlatformLimitations = resp.Capabilities.ReportLimitations()
		resp.CurrentChannel = s.deps.Pipeline.CurrentChannel()
	}
	if s.deps.Detector != nil {
		resp.Detection.Rules = s.deps.Detector.RuleCount()
		resp.Detection.DedupWindow = s.deps.Detector.DedupWindow()
	}
	if s.deps.State != nil {
		resp.Stats.APs = s.deps.State.APs().Len()
		resp.Stats.Clients = s.deps.State.Clients().Len()
	}
	if s.deps.Repo != nil {
		if total, err := s.deps.Repo.CountEvents(ctx, eventFilterAll()); err == nil {
			resp.Stats.EventsTotal = total
		}
		since24h := now.Add(-24 * time.Hour)
		if total, err := s.deps.Repo.CountEvents(ctx, eventFilterSince(since24h)); err == nil {
			resp.Stats.Events24h = total
		}
	}
	return resp
}

// StatusSnapshot returns the current full status as a JSON-serializable value.
// Used by the periodic SSE publisher in cmd/tobimaru to broadcast consistent
// status payloads.
func (s *Server) StatusSnapshot(ctx context.Context) any {
	return s.buildStatusResponse(ctx)
}

// handleStatus serves GET /api/status. Public route; if the request carries
// a valid session cookie the response includes the session role so the SPA
// can preserve admin-only UI across reloads. Anonymous requests still get a
// 200 with role omitted.
func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if sess, err := s.resolveSession(r); err == nil && sess != nil {
		ctx = context.WithValue(ctx, ctxKeySession, sess)
	}
	resp := s.buildStatusResponse(ctx)
	writeJSON(w, s.logger, http.StatusOK, resp)
}
