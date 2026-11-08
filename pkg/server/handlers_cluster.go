package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/duonghiepit/platform-controller/pkg/logger"
	"github.com/duonghiepit/platform-controller/pkg/model"
	"github.com/duonghiepit/platform-controller/pkg/vault"
)

// ClusterJoinRequest payload for /api/v1/cluster/join.
// Note: K8sHostOverride is forbidden via HTTP API to prevent SSRF / Vault Auth hijacking.
type ClusterJoinRequest struct {
	ClusterName    string `json:"cluster_name"`
	Namespace      string `json:"namespace,omitempty"`
	VaultMountPath string `json:"vault_mount_path,omitempty"`
}

func (s *Server) handleClusterJoin(w http.ResponseWriter, r *http.Request) {
	log := logger.L()
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // 1MB payload limit

	var req ClusterJoinRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		log.Warn("Failed to decode cluster join request", slog.String("error", err.Error()))
		http.Error(w, "invalid request payload", http.StatusBadRequest)
		return
	}

	if err := model.ValidateIdentifier("cluster_name", req.ClusterName); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if req.Namespace == "" {
		req.Namespace = "external-secrets"
	}
	if err := model.ValidateIdentifier("namespace", req.Namespace); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if req.VaultMountPath == "" {
		req.VaultMountPath = fmt.Sprintf("%s-kubernetes", req.ClusterName)
	}
	if err := model.ValidateIdentifier("vault_mount_path", req.VaultMountPath); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	log.Info("Processing cluster join request",
		slog.String("cluster", req.ClusterName),
		slog.String("vault_mount", req.VaultMountPath),
	)

	ctx, cancel := context.WithTimeout(r.Context(), 1*time.Minute)
	defer cancel()

	// 1. Ensure TokenReviewer
	creds, err := s.k8sClient.EnsureTokenReviewer(ctx, req.Namespace)
	if err != nil {
		log.Error("Failed to bootstrap token reviewer", slog.String("error", err.Error()))
		http.Error(w, "failed to bootstrap token reviewer", http.StatusInternalServerError)
		return
	}

	// 2. Connect to Vault
	vaultClient, err := vault.NewClient(s.cfg.VaultAddr, s.cfg.VaultToken)
	if err != nil {
		log.Error("Failed to connect to vault", slog.String("error", err.Error()))
		http.Error(w, "failed to connect to vault", http.StatusInternalServerError)
		return
	}

	payload := vault.K8sAuthConfigPayload{
		KubernetesHost:       s.k8sClient.Host,
		KubernetesCACert:     creds.CACert,
		TokenReviewerJWT:     creds.Token,
		DisableLocalCAJWT:    true,
		DisableISSValidation: true,
	}

	if err := vaultClient.ConfigureKubernetesAuth(ctx, req.VaultMountPath, payload); err != nil {
		log.Error("Failed to configure vault auth backend", slog.String("error", err.Error()))
		http.Error(w, "failed to configure vault auth backend", http.StatusInternalServerError)
		return
	}

	log.Info("Cluster joined Vault successfully",
		slog.String("cluster", req.ClusterName),
		slog.String("vault_mount", req.VaultMountPath),
	)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"status":      "success",
		"cluster":     req.ClusterName,
		"vault_mount": req.VaultMountPath,
	})
}
