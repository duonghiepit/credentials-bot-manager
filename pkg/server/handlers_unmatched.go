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
	syncpkg "github.com/duonghiepit/platform-controller/pkg/sync"
	"github.com/duonghiepit/platform-controller/pkg/vault"
)

// UnmatchedSecretRequest defines payload for deleting or querying unmatched secrets.
type UnmatchedSecretRequest struct {
	ClusterName string                          `json:"cluster_name"`
	Namespace   string                          `json:"namespace,omitempty"`
	Target      string                          `json:"target,omitempty"` // "all", "k8s", "vault"
	DryRun      bool                            `json:"dry_run,omitempty"`
	Declared    map[string]*model.SecretsConfig `json:"declared,omitempty"`
}

func (s *Server) getVaultClient() (*vault.Client, error) {
	if s.cfg.VaultAddr == "" {
		return nil, fmt.Errorf("vault_addr is not configured")
	}
	return vault.NewClient(s.cfg.VaultAddr, s.cfg.VaultToken)
}

func (s *Server) handleSecretUnmatched(w http.ResponseWriter, r *http.Request) {
	log := logger.L()

	clusterName := r.URL.Query().Get("cluster")
	nsFilter := r.URL.Query().Get("namespace")
	target := r.URL.Query().Get("target")
	dryRunStr := r.URL.Query().Get("dry_run")
	dryRun := dryRunStr == "true" || dryRunStr == "1"

	var req UnmatchedSecretRequest
	if r.Body != nil && r.ContentLength > 0 {
		if err := json.NewDecoder(r.Body).Decode(&req); err == nil {
			if req.ClusterName != "" {
				clusterName = req.ClusterName
			}
			if req.Namespace != "" {
				nsFilter = req.Namespace
			}
			if req.Target != "" {
				target = req.Target
			}
			if req.DryRun {
				dryRun = true
			}
		}
	}

	if clusterName == "" {
		clusterName = s.cfg.ClusterName
	}
	if clusterName == "" {
		http.Error(w, "cluster is required (query param ?cluster= or json field)", http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
	defer cancel()

	vaultClient, err := s.getVaultClient()
	if err != nil {
		log.Warn("Vault client initialization warning for unmatched check", slog.String("error", err.Error()))
	}

	var report *syncpkg.UnmatchedReport
	if len(req.Declared) > 0 {
		var configs []*model.NamespaceConfig
		for ns, sec := range req.Declared {
			if nsFilter != "" && ns != nsFilter {
				continue
			}
			configs = append(configs, &model.NamespaceConfig{
				ClusterName: clusterName,
				Namespace:   ns,
				Secrets:     *sec,
			})
		}
		report, err = syncpkg.DetectConfigsUnmatchedSecrets(
			ctx,
			clusterName,
			configs,
			nsFilter == "",
			vaultClient,
			s.k8sClient.DynamicClient,
		)
	} else {
		report, err = syncpkg.DetectClusterUnmatchedSecrets(
			ctx,
			s.cfg.RegistryPath,
			clusterName,
			nsFilter,
			vaultClient,
			s.k8sClient.DynamicClient,
		)
	}
	if err != nil {
		log.Error("Failed to detect unmatched secrets", slog.String("error", err.Error()))
		http.Error(w, fmt.Sprintf("failed to detect unmatched secrets: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")

	switch r.Method {
	case http.MethodGet:
		log.Info("Unmatched secrets check completed",
			slog.String("cluster", clusterName),
			slog.Int("total_vault", report.TotalVaultUnmatched),
			slog.Int("total_k8s", report.TotalK8sUnmatched),
		)
		_ = json.NewEncoder(w).Encode(report)

	case http.MethodDelete:
		if target == "" {
			target = "all"
		}
		result, err := syncpkg.PurgeClusterUnmatchedSecrets(
			ctx,
			report,
			vaultClient,
			s.k8sClient.DynamicClient,
			target,
			dryRun,
		)
		if err != nil {
			log.Error("Failed to purge unmatched secrets", slog.String("error", err.Error()))
			http.Error(w, fmt.Sprintf("failed to purge unmatched secrets: %v", err), http.StatusInternalServerError)
			return
		}

		log.Info("Unmatched secrets cleanup completed",
			slog.String("cluster", clusterName),
			slog.String("target", target),
			slog.Bool("dry_run", dryRun),
			slog.Int("deleted_vault", len(result.DeletedVaultSecrets)),
			slog.Int("deleted_k8s", len(result.DeletedK8sSecrets)),
		)
		_ = json.NewEncoder(w).Encode(result)

	case http.MethodPost:
		if r.URL.Query().Get("action") == "cleanup" || (!dryRun && target != "") {
			if target == "" {
				target = "all"
			}
			result, err := syncpkg.PurgeClusterUnmatchedSecrets(
				ctx,
				report,
				vaultClient,
				s.k8sClient.DynamicClient,
				target,
				dryRun,
			)
			if err != nil {
				log.Error("Failed to purge unmatched secrets", slog.String("error", err.Error()))
				http.Error(w, fmt.Sprintf("failed to purge unmatched secrets: %v", err), http.StatusInternalServerError)
				return
			}
			_ = json.NewEncoder(w).Encode(result)
		} else {
			_ = json.NewEncoder(w).Encode(report)
		}

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}
