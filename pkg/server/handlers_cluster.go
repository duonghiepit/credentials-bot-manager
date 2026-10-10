package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/duonghiepit/platform-controller/pkg/logger"
	"github.com/duonghiepit/platform-controller/pkg/vault"
)

// ClusterJoinRequest payload for /api/v1/cluster/join.
type ClusterJoinRequest struct {
	ClusterName     string `json:"cluster_name"`
	Namespace       string `json:"namespace"`
	VaultMountPath  string `json:"vault_mount_path"`
	K8sHostOverride string `json:"k8s_host_override"`
}

func (s *Server) handleClusterJoin(w http.ResponseWriter, r *http.Request) {
	log := logger.L()
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // 1MB payload limit

	var req ClusterJoinRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Warn("Failed to decode cluster join request", slog.String("error", err.Error()))
		http.Error(w, fmt.Sprintf("invalid json: %v", err), http.StatusBadRequest)
		return
	}

	if req.ClusterName == "" {
		http.Error(w, "cluster_name is required", http.StatusBadRequest)
		return
	}
	if req.Namespace == "" {
		req.Namespace = "external-secrets"
	}
	if req.VaultMountPath == "" {
		req.VaultMountPath = fmt.Sprintf("%s-kubernetes", req.ClusterName)
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
		http.Error(w, fmt.Sprintf("failed to bootstrap token reviewer: %v", err), http.StatusInternalServerError)
		return
	}

	// 2. Connect to Vault
	vaultClient, err := vault.NewClient(s.cfg.VaultAddr, s.cfg.VaultToken)
	if err != nil {
		log.Error("Failed to connect to vault", slog.String("error", err.Error()))
		http.Error(w, fmt.Sprintf("failed to connect to vault: %v", err), http.StatusInternalServerError)
		return
	}

	k8sHost := s.k8sClient.Host
	if req.K8sHostOverride != "" {
		k8sHost = req.K8sHostOverride
	}

	payload := vault.K8sAuthConfigPayload{
		KubernetesHost:       k8sHost,
		KubernetesCACert:     creds.CACert,
		TokenReviewerJWT:     creds.Token,
		DisableLocalCAJWT:    true,
		DisableISSValidation: true,
	}

	if err := vaultClient.ConfigureKubernetesAuth(ctx, req.VaultMountPath, payload); err != nil {
		log.Error("Failed to configure vault auth backend", slog.String("error", err.Error()))
		http.Error(w, fmt.Sprintf("failed to configure vault: %v", err), http.StatusInternalServerError)
		return
	}

	log.Info("Cluster joined Vault successfully",
		slog.String("cluster", req.ClusterName),
		slog.String("vault_mount", req.VaultMountPath),
	)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"status":       "success",
		"cluster":      req.ClusterName,
		"vault_mount":  req.VaultMountPath,
		"token_length": len(creds.Token),
		"ca_length":    len(creds.CACert),
	})
}
