package api

import (
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
}

type statusSubscribersBlock struct {
	SSE int `json:"sse"`
}

// handleStatus serves GET /api/status. Public route.
func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
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
		if total, err := s.deps.Repo.CountEvents(r.Context(), eventFilterAll()); err == nil {
			resp.Stats.EventsTotal = total
		}
		since24h := now.Add(-24 * time.Hour)
		if total, err := s.deps.Repo.CountEvents(r.Context(), eventFilterSince(since24h)); err == nil {
			resp.Stats.Events24h = total
		}
	}
	writeJSON(w, s.logger, http.StatusOK, resp)
}
