package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/duonghiepit/platform-controller/pkg/k8s"
	"github.com/duonghiepit/platform-controller/pkg/logger"
	syncpkg "github.com/duonghiepit/platform-controller/pkg/sync"
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
	applier   *syncpkg.Applier
	server    *http.Server
	wg        sync.WaitGroup
}

// NewServer initializes a new Server.
func NewServer(cfg Config) (*Server, error) {
	k8sClient, err := k8s.NewClient("", "")
	if err != nil {
		return nil, fmt.Errorf("failed to initialize kubernetes client: %w", err)
	}

	applier := syncpkg.NewApplier(k8sClient.DynamicClient)

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

	loggedHandler := loggingMiddleware(mux)

	s.server = &http.Server{
		Addr:         fmt.Sprintf(":%d", cfg.Port),
		Handler:      loggedHandler,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 60 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	return s, nil
}

// Start runs the HTTP server and handles graceful shutdown.
func (s *Server) Start(ctx context.Context) error {
	log := logger.L()

	if s.cfg.SyncInterval > 0 && s.cfg.ClusterName != "" {
		s.wg.Add(1)
		go s.runReconciler(ctx)
	}

	log.Info("Starting HTTP daemon server",
		slog.Int("port", s.cfg.Port),
		slog.String("vault_addr", s.cfg.VaultAddr),
		slog.String("registry_path", s.cfg.RegistryPath),
	)

	errChan := make(chan error, 1)
	go func() {
		if err := s.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errChan <- err
		}
	}()

	select {
	case <-ctx.Done():
		log.Info("Shutdown signal received. Initiating graceful shutdown...",
			slog.Duration("grace_period", 15*time.Second),
		)

		s.server.SetKeepAlivesEnabled(false)

		shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()

		if err := s.server.Shutdown(shutdownCtx); err != nil {
			log.Error("HTTP server forced to shutdown", slog.String("error", err.Error()))
		} else {
			log.Info("HTTP server drained and closed listeners cleanly")
		}

		// Wait for background tasks
		log.Info("Waiting for background workers to complete...")
		s.wg.Wait()
		log.Info("All workers completed. Graceful shutdown finished.")
		return nil

	case err := <-errChan:
		log.Error("HTTP server encountered fatal error", slog.String("error", err.Error()))
		return err
	}
}

// statusWriter wraps http.ResponseWriter to capture the HTTP status code and size.
type statusWriter struct {
	http.ResponseWriter
	status int
	length int
}

func (w *statusWriter) WriteHeader(status int) {
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	n, err := w.ResponseWriter.Write(b)
	w.length += n
	return n, err
}

func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w}

		next.ServeHTTP(sw, r)

		duration := time.Since(start)
		status := sw.status
		if status == 0 {
			status = http.StatusOK
		}

		// Don't spam debug healthchecks in info level unless status != 200
		if (r.URL.Path == "/healthz" || r.URL.Path == "/readyz") && status == http.StatusOK {
			logger.L().Debug("Healthcheck probe",
				slog.String("path", r.URL.Path),
				slog.Int("status", status),
			)
			return
		}

		logger.L().Info("HTTP request handled",
			slog.String("method", r.Method),
			slog.String("path", r.URL.Path),
			slog.Int("status", status),
			slog.Float64("duration_ms", float64(duration.Microseconds())/1000.0),
			slog.String("remote_addr", r.RemoteAddr),
			slog.Int("bytes", sw.length),
		)
	})
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
	log := logger.L()
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

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

// SecretSyncRequest payload for /api/v1/secret/sync.
type SecretSyncRequest struct {
	ClusterName string `json:"cluster_name"`
	Namespace   string `json:"namespace"`
	VaultServer string `json:"vault_server"`
}

func (s *Server) handleSecretSync(w http.ResponseWriter, r *http.Request) {
	log := logger.L()
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

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

	syncedCount, err := s.syncSecrets(ctx, req.ClusterName, req.Namespace, req.VaultServer)
	if err != nil {
		log.Error("Secret sync failed", slog.String("error", err.Error()))
		http.Error(w, fmt.Sprintf("sync failed: %v", err), http.StatusInternalServerError)
		return
	}

	log.Info("Secret sync completed successfully",
		slog.String("cluster", req.ClusterName),
		slog.Int("synced_objects", syncedCount),
	)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"status":         "success",
		"cluster":        req.ClusterName,
		"synced_objects": syncedCount,
	})
}

func (s *Server) syncSecrets(ctx context.Context, clusterName, nsFilter, vaultServer string) (int, error) {
	configs, err := syncpkg.LoadClusterConfigs(s.cfg.RegistryPath, clusterName, nsFilter)
	if err != nil {
		return 0, fmt.Errorf("failed to load configs: %w", err)
	}

	totalSynced := 0
	for _, cfg := range configs {
		manifests, err := syncpkg.RenderAllForNamespace(cfg, vaultServer)
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
			count, err := s.syncSecrets(ctx, s.cfg.ClusterName, "", s.cfg.VaultServer)
			if err != nil {
				log.Warn("Reconciler cycle encountered error", slog.String("error", err.Error()))
			} else {
				log.Info("Reconciler cycle completed", slog.Int("synced_objects", count))
			}
		}
	}
}
