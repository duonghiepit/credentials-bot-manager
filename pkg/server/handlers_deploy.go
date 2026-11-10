package server

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/duonghiepit/platform-controller/pkg/deployer"
	"github.com/duonghiepit/platform-controller/pkg/logger"
)

// handleDeployContainerImages initiates a GitOps deployment cycle.
// Supports both /api/v1/deploy and /configsManager/deployContainerImages (KV format).
func (s *Server) handleDeployContainerImages(w http.ResponseWriter, r *http.Request) {
	log := logger.L()
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // 1MB payload limit

	var req deployer.DeployRequest
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(&req); err != nil {
		log.Warn("Failed to decode deploy request", slog.String("error", err.Error()))
		http.Error(w, "invalid request payload", http.StatusBadRequest)
		return
	}

	if s.deployManager == nil {
		http.Error(w, "deployer engine is not enabled on this controller", http.StatusServiceUnavailable)
		return
	}

	resp, err := s.deployManager.StartDeployment(r.Context(), req)
	if err != nil {
		log.Warn("Deploy rejected", slog.String("error", err.Error()))
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"code":    200,
		"message": "success",
		"data":    resp,
	})
}

// handleReloadDeployStatus polls the current status of a deployment event.
// Supports both /api/v1/deploy/status and /configsManager/reloadDeployStatus (KV format).
func (s *Server) handleReloadDeployStatus(w http.ResponseWriter, r *http.Request) {
	log := logger.L()
	if r.Method != http.MethodPost && r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var eventID string
	if r.Method == http.MethodGet {
		eventID = r.URL.Query().Get("eventId")
	} else {
		var req deployer.DeployStatusRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			log.Warn("Failed to decode reload deploy status request", slog.String("error", err.Error()))
			http.Error(w, "invalid request payload", http.StatusBadRequest)
			return
		}
		eventID = req.EventID
	}

	if eventID == "" {
		http.Error(w, "eventId is required", http.StatusBadRequest)
		return
	}

	if s.deployManager == nil {
		http.Error(w, "deployer engine is not enabled on this controller", http.StatusServiceUnavailable)
		return
	}

	event, found := s.deployManager.GetEventStatus(eventID)
	if !found {
		http.Error(w, "deployment event not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"code":    200,
		"message": "success",
		"data": map[string]interface{}{
			"eventId":       event.EventID,
			"deployStatus":  event.DeployStatus,
			"deployMessage": event.DeployMessage,
			"imageUrl":      event.ImageURL,
			"imageTag":      event.ImageTag,
			"gitCommit":     event.GitCommit,
			"updatedAt":     event.UpdatedAt,
		},
	})
}
