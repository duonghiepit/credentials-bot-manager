package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/duonghiepit/platform-controller/pkg/k8s"
	"github.com/duonghiepit/platform-controller/pkg/sync"
	"github.com/duonghiepit/platform-controller/pkg/vault"
)

// Config holds the configuration for the HTTP daemon server.
type Config struct {
	Port         int
	RegistryPath string
	VaultAddr    string
	VaultToken   string
	SyncInterval time.Duration
	ClusterName  string
	VaultServer  string
}

// Server implements the HTTP API daemon and background reconciler.
type Server struct {
	cfg       Config
	k8sClient *k8s.Client
	applier   *sync.Applier
	server    *http.Server
}

// NewServer initializes a new Server.
func NewServer(cfg Config) (*Server, error) {
	k8sClient, err := k8s.NewClient("", "")
	if err != nil {
		return nil, fmt.Errorf("failed to initialize kubernetes client: %w", err)
	}

	applier := sync.NewApplier(k8sClient.DynamicClient)

	s := &Server{
		cfg:       cfg,
		k8sClient: k8sClient,
		applier:   applier,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", s.handleHealthz)
	mux.HandleFunc("/readyz", s.handleHealthz)
	mux.HandleFunc("/api/v1/cluster/join", s.handleClusterJoin)
	mux.HandleFunc("/api/v1/secret/sync", s.handleSecretSync)

	s.server = &http.Server{
		Addr:         fmt.Sprintf(":%d", cfg.Port),
		Handler:      mux,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 60 * time.Second,
	}

	return s, nil
}

// Start runs the HTTP server and optional reconciliation loop.
func (s *Server) Start(ctx context.Context) error {
	if s.cfg.SyncInterval > 0 && s.cfg.ClusterName != "" {
		go s.runReconciler(ctx)
	}

	log.Printf("🚀 Platform Controller listening on port %d...", s.cfg.Port)
	errChan := make(chan error, 1)
	go func() {
		if err := s.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errChan <- err
		}
	}()

	select {
	case <-ctx.Done():
		log.Println("Shutting down server...")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return s.server.Shutdown(shutdownCtx)
	case err := <-errChan:
		return err
	}
}

func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"status":    "healthy",
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	})
}

// ClusterJoinRequest payload for /api/v1/cluster/join.
type ClusterJoinRequest struct {
	ClusterName     string `json:"cluster_name"`
	Namespace       string `json:"namespace"`
	VaultMountPath  string `json:"vault_mount_path"`
	K8sHostOverride string `json:"k8s_host_override"`
}

func (s *Server) handleClusterJoin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req ClusterJoinRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
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

	ctx, cancel := context.WithTimeout(r.Context(), 1*time.Minute)
	defer cancel()

	// 1. Ensure TokenReviewer
	creds, err := s.k8sClient.EnsureTokenReviewer(ctx, req.Namespace)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to bootstrap token reviewer: %v", err), http.StatusInternalServerError)
		return
	}

	// 2. Connect to Vault
	vaultClient, err := vault.NewClient(s.cfg.VaultAddr, s.cfg.VaultToken)
	if err != nil {
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
		http.Error(w, fmt.Sprintf("failed to configure vault: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"status":       "success",
		"cluster":      req.ClusterName,
		"vault_mount":  req.VaultMountPath,
		"token_length": len(creds.Token),
		"ca_length":    len(creds.CACert),
	})
}

// SecretSyncRequest payload for /api/v1/secret/sync.
type SecretSyncRequest struct {
	ClusterName string `json:"cluster_name"`
	Namespace   string `json:"namespace"`
	VaultServer string `json:"vault_server"`
}

func (s *Server) handleSecretSync(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req SecretSyncRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
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

	ctx, cancel := context.WithTimeout(r.Context(), 1*time.Minute)
	defer cancel()

	syncedCount, err := s.syncSecrets(ctx, req.ClusterName, req.Namespace, req.VaultServer)
	if err != nil {
		http.Error(w, fmt.Sprintf("sync failed: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"status":         "success",
		"cluster":        req.ClusterName,
		"synced_objects": syncedCount,
	})
}

func (s *Server) syncSecrets(ctx context.Context, clusterName, nsFilter, vaultServer string) (int, error) {
	configs, err := sync.LoadClusterConfigs(s.cfg.RegistryPath, clusterName, nsFilter)
	if err != nil {
		return 0, fmt.Errorf("failed to load configs: %w", err)
	}

	totalSynced := 0
	for _, cfg := range configs {
		manifests, err := sync.RenderAllForNamespace(cfg, vaultServer)
		if err != nil {
			return totalSynced, fmt.Errorf("render failed for %s: %w", cfg.Namespace, err)
		}

		for _, m := range manifests {
			if err := s.applier.ApplyObject(ctx, m); err != nil {
				return totalSynced, fmt.Errorf("apply failed for %s/%s: %w", m.GetKind(), m.GetName(), err)
			}
			totalSynced++
		}
	}

	return totalSynced, nil
}

func (s *Server) runReconciler(ctx context.Context) {
	ticker := time.NewTicker(s.cfg.SyncInterval)
	defer ticker.Stop()

	log.Printf("🔄 Auto-reconciler enabled: syncing cluster '%s' every %v", s.cfg.ClusterName, s.cfg.SyncInterval)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			count, err := s.syncSecrets(ctx, s.cfg.ClusterName, "", s.cfg.VaultServer)
			if err != nil {
				log.Printf("⚠️  Reconciler error: %v", err)
			} else {
				log.Printf("✅ Reconciler cycle complete: %d object(s) in sync", count)
			}
		}
	}
}
