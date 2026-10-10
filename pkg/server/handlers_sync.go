package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/duonghiepit/platform-controller/pkg/logger"
	"github.com/duonghiepit/platform-controller/pkg/model"
	syncpkg "github.com/duonghiepit/platform-controller/pkg/sync"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// SecretSyncRequest payload for /api/v1/secret/sync.
type SecretSyncRequest struct {
	ClusterName string               `json:"cluster_name"`
	Namespace   string               `json:"namespace"`
	VaultServer string               `json:"vault_server,omitempty"`
	Secrets     *model.SecretsConfig `json:"secrets,omitempty"`
}

// SyncStats encapsulates the granular outcomes of a secret synchronization cycle.
type SyncStats struct {
	Total     int `json:"total"`
	Created   int `json:"created"`
	Updated   int `json:"updated"`
	Unchanged int `json:"unchanged"`
}

func (s *Server) handleSecretSync(w http.ResponseWriter, r *http.Request) {
	log := logger.L()
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // 1MB payload limit

	var req SecretSyncRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Warn("Failed to decode secret sync request", slog.String("error", err.Error()))
		http.Error(w, fmt.Sprintf("invalid json: %v", err), http.StatusBadRequest)
		return
	}

	if req.ClusterName == "" {
		req.ClusterName = s.cfg.ClusterName
	}
	if req.ClusterName == "" {
		http.Error(w, "cluster_name is required", http.StatusBadRequest)
		return
	}
	if req.VaultServer == "" {
		req.VaultServer = s.cfg.VaultServer
	}
	if req.VaultServer == "" {
		req.VaultServer = "http://vault.external-secrets.svc:8200"
	}

	log.Info("Processing secret sync request",
		slog.String("cluster", req.ClusterName),
		slog.String("namespace", req.Namespace),
	)

	ctx, cancel := context.WithTimeout(r.Context(), 1*time.Minute)
	defer cancel()

	var configs []*model.NamespaceConfig
	if req.Secrets != nil {
		if req.Namespace == "" {
			http.Error(w, "namespace is required when secrets payload is provided", http.StatusBadRequest)
			return
		}
		configs = append(configs, &model.NamespaceConfig{
			ClusterName: req.ClusterName,
			Namespace:   req.Namespace,
			Secrets:     *req.Secrets,
		})
	} else {
		var err error
		configs, err = syncpkg.LoadClusterConfigs(s.cfg.RegistryPath, req.ClusterName, req.Namespace)
		if err != nil {
			log.Error("Failed to load configs from registry", slog.String("error", err.Error()))
			http.Error(w, fmt.Sprintf("failed to load configs: %v", err), http.StatusInternalServerError)
			return
		}
	}

	stats, err := s.applyConfigs(ctx, configs, req.VaultServer)
	if err != nil {
		log.Error("Secret sync failed", slog.String("error", err.Error()))
		http.Error(w, fmt.Sprintf("sync failed: %v", err), http.StatusInternalServerError)
		return
	}

	log.Info("Secret sync completed successfully",
		slog.String("cluster", req.ClusterName),
		slog.Int("total", stats.Total),
		slog.Int("created", stats.Created),
		slog.Int("updated", stats.Updated),
		slog.Int("unchanged", stats.Unchanged),
	)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"status":         "success",
		"cluster":        req.ClusterName,
		"synced_objects": stats.Total,
		"created":        stats.Created,
		"updated":        stats.Updated,
		"unchanged":      stats.Unchanged,
	})
}

func (s *Server) applyConfigs(ctx context.Context, configs []*model.NamespaceConfig, vaultServer string) (*SyncStats, error) {
	stats := &SyncStats{}
	var mu sync.Mutex

	recordAction := func(action syncpkg.ApplyAction) {
		mu.Lock()
		defer mu.Unlock()
		stats.Total++
		switch action {
		case syncpkg.ActionCreated:
			stats.Created++
		case syncpkg.ActionUpdated:
			stats.Updated++
		case syncpkg.ActionUnchanged:
			stats.Unchanged++
		}
	}

	for _, cfg := range configs {
		manifests, err := syncpkg.RenderAllForNamespace(cfg, vaultServer)
		if err != nil {
			return stats, fmt.Errorf("render failed for %s: %w", cfg.Namespace, err)
		}
		if len(manifests) == 0 {
			continue
		}

		// 1. Apply SecretStore first sequentially (required dependency for ExternalSecrets)
		action, err := s.applier.ApplyObject(ctx, manifests[0])
		if err != nil {
			return stats, fmt.Errorf("apply failed for %s/%s: %w", manifests[0].GetKind(), manifests[0].GetName(), err)
		}
		recordAction(action)

		// 2. Concurrently apply remaining manifests (ExternalSecrets & SecretProviderClasses)
		remaining := manifests[1:]
		if len(remaining) == 0 {
			continue
		}

		concurrency := 5
		if len(remaining) < concurrency {
			concurrency = len(remaining)
		}

		sem := make(chan struct{}, concurrency)
		errCh := make(chan error, len(remaining))
		var wg sync.WaitGroup

		for _, m := range remaining {
			wg.Add(1)
			go func(obj *unstructured.Unstructured) {
				defer wg.Done()
				select {
				case sem <- struct{}{}:
					defer func() { <-sem }()
				case <-ctx.Done():
					errCh <- ctx.Err()
					return
				}

				act, err := s.applier.ApplyObject(ctx, obj)
				if err != nil {
					errCh <- fmt.Errorf("apply failed for %s/%s: %w", obj.GetKind(), obj.GetName(), err)
					return
				}
				recordAction(act)
			}(m)
		}

		wg.Wait()
		close(errCh)

		if applyErr := <-errCh; applyErr != nil {
			return stats, applyErr
		}
	}
	return stats, nil
}

func (s *Server) syncSecrets(ctx context.Context, clusterName, nsFilter, vaultServer string) (*SyncStats, error) {
	configs, err := syncpkg.LoadClusterConfigs(s.cfg.RegistryPath, clusterName, nsFilter)
	if err != nil {
		return nil, fmt.Errorf("failed to load configs: %w", err)
	}
	return s.applyConfigs(ctx, configs, vaultServer)
}

func (s *Server) runReconciler(ctx context.Context) {
	defer s.wg.Done()
	log := logger.L()

	ticker := time.NewTicker(s.cfg.SyncInterval)
	defer ticker.Stop()

	log.Info("Auto-reconciler worker started",
		slog.String("cluster", s.cfg.ClusterName),
		slog.Duration("interval", s.cfg.SyncInterval),
	)

	for {
		select {
		case <-ctx.Done():
			log.Info("Auto-reconciler stopping...")
			return
		case <-ticker.C:
			stats, err := s.syncSecrets(ctx, s.cfg.ClusterName, "", s.cfg.VaultServer)
			if err != nil {
				log.Warn("Reconciler cycle encountered error", slog.String("error", err.Error()))
			} else {
				log.Info("Reconciler cycle completed",
					slog.Int("total", stats.Total),
					slog.Int("created", stats.Created),
					slog.Int("updated", stats.Updated),
					slog.Int("unchanged", stats.Unchanged),
				)
			}
		}
	}
}
