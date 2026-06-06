package api

import (
	"errors"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/vkochetkov/tobimaru/internal/state"
)

// whitelistAddRequest is the JSON body for POST /api/whitelist.
type whitelistAddRequest struct {
	MAC     string `json:"mac"`
	SSID    string `json:"ssid"`
	Comment string `json:"comment"`
}

// blacklistAddRequest is the JSON body for POST /api/blacklist.
type blacklistAddRequest struct {
	MAC     string `json:"mac"`
	Reason  string `json:"reason"`
	Comment string `json:"comment"`
}

// handleListWhitelist serves GET /api/whitelist.
func (s *Server) handleListWhitelist(w http.ResponseWriter, _ *http.Request) {
	if s.deps.State == nil {
		writeProblem(w, s.logger, http.StatusServiceUnavailable, errTypeStateDisabled,
			"state engine is disabled")
		return
	}
	entries := s.deps.State.Whitelist().ListWhitelist()
	out := make([]whitelistDTO, 0, len(entries))
	for _, e := range entries {
		out = append(out, newWhitelistDTO(e))
	}
	writeJSON(w, s.logger, http.StatusOK, listResponse{Items: out, Total: int64(len(out))})
}

// handleAddWhitelist serves POST /api/whitelist (admin only).
func (s *Server) handleAddWhitelist(w http.ResponseWriter, r *http.Request) {
	if s.deps.State == nil {
		writeProblem(w, s.logger, http.StatusServiceUnavailable, errTypeStateDisabled,
			"state engine is disabled")
		return
	}
	var req whitelistAddRequest
	if err := readJSON(w, r, s.logger, &req); err != nil {
		return
	}
	mac, err := parseMACArg(req.MAC)
	if err != nil {
		writeProblem(w, s.logger, http.StatusBadRequest, errTypeBadRequest, err.Error())
		return
	}
	entry := &state.WhitelistEntry{
		MAC:       mac,
		SSID:      strings.TrimSpace(req.SSID),
		Comment:   strings.TrimSpace(req.Comment),
		Source:    state.WhitelistSourceManual,
		CreatedAt: time.Now(),
	}
	s.deps.State.Whitelist().AddWhitelist(entry)
	if s.deps.Repo != nil {
		if err := s.deps.Repo.SaveWhitelistEntry(r.Context(), entry); err != nil {
			s.logger.Warn("api: failed to persist whitelist entry", "error", err)
		}
	}
	writeJSON(w, s.logger, http.StatusCreated, newWhitelistDTO(entry))
}

// handleDeleteWhitelist serves DELETE /api/whitelist/{mac} (admin only).
func (s *Server) handleDeleteWhitelist(w http.ResponseWriter, r *http.Request) {
	if s.deps.State == nil {
		writeProblem(w, s.logger, http.StatusServiceUnavailable, errTypeStateDisabled,
			"state engine is disabled")
		return
	}
	mac, err := parseMACArg(chi.URLParam(r, "mac"))
	if err != nil {
		writeProblem(w, s.logger, http.StatusBadRequest, errTypeBadRequest, err.Error())
		return
	}
	s.deps.State.Whitelist().RemoveWhitelist(mac)
	if s.deps.Repo != nil {
		if err := s.deps.Repo.DeleteWhitelistEntry(r.Context(), mac.String()); err != nil {
			s.logger.Warn("api: failed to delete whitelist entry", "error", err)
		}
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleListBlacklist serves GET /api/blacklist.
func (s *Server) handleListBlacklist(w http.ResponseWriter, _ *http.Request) {
	if s.deps.State == nil {
		writeProblem(w, s.logger, http.StatusServiceUnavailable, errTypeStateDisabled,
			"state engine is disabled")
		return
	}
	entries := s.deps.State.Whitelist().ListBlacklist()
	out := make([]blacklistDTO, 0, len(entries))
	for _, e := range entries {
		out = append(out, newBlacklistDTO(e))
	}
	writeJSON(w, s.logger, http.StatusOK, listResponse{Items: out, Total: int64(len(out))})
}

// handleAddBlacklist serves POST /api/blacklist (admin only).
func (s *Server) handleAddBlacklist(w http.ResponseWriter, r *http.Request) {
	if s.deps.State == nil {
		writeProblem(w, s.logger, http.StatusServiceUnavailable, errTypeStateDisabled,
			"state engine is disabled")
		return
	}
	var req blacklistAddRequest
	if err := readJSON(w, r, s.logger, &req); err != nil {
		return
	}
	mac, err := parseMACArg(req.MAC)
	if err != nil {
		writeProblem(w, s.logger, http.StatusBadRequest, errTypeBadRequest, err.Error())
		return
	}
	entry := &state.BlacklistEntry{
		MAC:       mac,
		Reason:    strings.TrimSpace(req.Reason),
		Comment:   strings.TrimSpace(req.Comment),
		CreatedAt: time.Now(),
	}
	s.deps.State.Whitelist().AddBlacklist(entry)
	if s.deps.Repo != nil {
		if err := s.deps.Repo.SaveBlacklistEntry(r.Context(), entry); err != nil {
			s.logger.Warn("api: failed to persist blacklist entry", "error", err)
		}
	}
	writeJSON(w, s.logger, http.StatusCreated, newBlacklistDTO(entry))
}

// handleDeleteBlacklist serves DELETE /api/blacklist/{mac} (admin only).
func (s *Server) handleDeleteBlacklist(w http.ResponseWriter, r *http.Request) {
	if s.deps.State == nil {
		writeProblem(w, s.logger, http.StatusServiceUnavailable, errTypeStateDisabled,
			"state engine is disabled")
		return
	}
	mac, err := parseMACArg(chi.URLParam(r, "mac"))
	if err != nil {
		writeProblem(w, s.logger, http.StatusBadRequest, errTypeBadRequest, err.Error())
		return
	}
	s.deps.State.Whitelist().RemoveBlacklist(mac)
	if s.deps.Repo != nil {
		if err := s.deps.Repo.DeleteBlacklistEntry(r.Context(), mac.String()); err != nil {
			s.logger.Warn("api: failed to delete blacklist entry", "error", err)
		}
	}
	w.WriteHeader(http.StatusNoContent)
}

// parseMACArg parses a MAC address string; rejects empty input.
func parseMACArg(s string) (net.HardwareAddr, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, errors.New("mac is required")
	}
	mac, err := net.ParseMAC(s)
	if err != nil {
		return nil, errors.New("invalid mac: " + err.Error())
	}
	return mac, nil
}
