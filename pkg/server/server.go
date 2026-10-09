package server

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/duonghiepit/platform-controller/pkg/k8s"
	"github.com/duonghiepit/platform-controller/pkg/logger"
	"github.com/duonghiepit/platform-controller/pkg/model"
	syncpkg "github.com/duonghiepit/platform-controller/pkg/sync"
	"github.com/duonghiepit/platform-controller/pkg/vault"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

const (
	defaultAuthSecretName = "platform-controller-auth"
	authSecretKey         = "api_key"
)

// Config holds the configuration for the HTTP daemon server.
type Config struct {
	Port          int
	RegistryPath  string
	VaultAddr     string
	VaultToken    string
	SyncInterval  time.Duration
	ClusterName   string
	VaultServer   string
	AuthNamespace string
}

// Server implements the HTTP API daemon and background reconciler.
type Server struct {
	cfg       Config
	k8sClient *k8s.Client
	applier   *syncpkg.Applier
	server    *http.Server
	wg        sync.WaitGroup

	tokenMu     sync.RWMutex
	activeToken string
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

	if err := s.ensureAuthToken(context.Background()); err != nil {
		return nil, fmt.Errorf("failed to bootstrap auth token: %w", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", s.handleHealthz)
	mux.HandleFunc("/readyz", s.handleHealthz)
	mux.HandleFunc("/api/v1/cluster/join", s.handleClusterJoin)
	mux.HandleFunc("/api/v1/secret/sync", s.handleSecretSync)
	mux.HandleFunc("/api/v1/secret/unmatched", s.handleSecretUnmatched)
	mux.HandleFunc("/api/v1/auth/rotate-token", s.handleRotateToken)

	authHandler := s.authMiddleware(mux)
	loggedHandler := loggingMiddleware(authHandler)

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

func generateSecureToken() (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "vtt_sec_" + hex.EncodeToString(b), nil
}

func (s *Server) ensureAuthToken(ctx context.Context) error {
	log := logger.L()
	ns := s.cfg.AuthNamespace
	if ns == "" {
		ns = "platform-system"
	}

	if s.k8sClient == nil || s.k8sClient.Clientset == nil {
		token, _ := generateSecureToken()
		s.tokenMu.Lock()
		s.activeToken = token
		s.tokenMu.Unlock()
		log.Warn("Running without Kubernetes client; generated standalone in-memory API token", slog.String("token", token))
		return nil
	}

	secret, err := s.k8sClient.Clientset.CoreV1().Secrets(ns).Get(ctx, defaultAuthSecretName, metav1.GetOptions{})
	if err == nil && secret != nil && len(secret.Data[authSecretKey]) > 0 {
		token := string(secret.Data[authSecretKey])
		s.tokenMu.Lock()
		s.activeToken = token
		s.tokenMu.Unlock()
		log.Info("Loaded existing API token from Kubernetes Secret (ArgoCD style)",
			slog.String("namespace", ns),
			slog.String("secret", defaultAuthSecretName),
		)
		return nil
	}

	newToken, err := generateSecureToken()
	if err != nil {
		return fmt.Errorf("failed to generate secure token: %w", err)
	}

	newSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      defaultAuthSecretName,
			Namespace: ns,
			Labels: map[string]string{
				"app.kubernetes.io/name":      "platform-controller",
				"app.kubernetes.io/component": "auth",
			},
		},
		Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{
			authSecretKey: []byte(newToken),
		},
	}

	_, err = s.k8sClient.Clientset.CoreV1().Secrets(ns).Create(ctx, newSecret, metav1.CreateOptions{})
	if err != nil {
		sec, getErr := s.k8sClient.Clientset.CoreV1().Secrets(ns).Get(ctx, defaultAuthSecretName, metav1.GetOptions{})
		if getErr == nil && len(sec.Data[authSecretKey]) > 0 {
			s.tokenMu.Lock()
			s.activeToken = string(sec.Data[authSecretKey])
			s.tokenMu.Unlock()
			return nil
		}
		return fmt.Errorf("failed to create auth secret %s/%s: %w", ns, defaultAuthSecretName, err)
	}

	s.tokenMu.Lock()
	s.activeToken = newToken
	s.tokenMu.Unlock()

	log.Info("Successfully generated initial API token and persisted to Kubernetes Secret (ArgoCD style)",
		slog.String("namespace", ns),
		slog.String("secret", defaultAuthSecretName),
	)
	return nil
}

func (s *Server) handleRotateToken(w http.ResponseWriter, r *http.Request) {
	log := logger.L()
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	newToken, err := generateSecureToken()
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to generate token: %v", err), http.StatusInternalServerError)
		return
	}

	ns := s.cfg.AuthNamespace
	if ns == "" {
		ns = "platform-system"
	}

	if s.k8sClient != nil && s.k8sClient.Clientset != nil {
		secret, err := s.k8sClient.Clientset.CoreV1().Secrets(ns).Get(ctx, defaultAuthSecretName, metav1.GetOptions{})
		if err == nil && secret != nil {
			if secret.Data == nil {
				secret.Data = make(map[string][]byte)
			}
			secret.Data[authSecretKey] = []byte(newToken)
			_, err = s.k8sClient.Clientset.CoreV1().Secrets(ns).Update(ctx, secret, metav1.UpdateOptions{})
			if err != nil {
				log.Error("Failed to update auth secret", slog.String("error", err.Error()))
				http.Error(w, fmt.Sprintf("failed to update auth secret: %v", err), http.StatusInternalServerError)
				return
			}
		} else {
			newSecret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      defaultAuthSecretName,
					Namespace: ns,
					Labels: map[string]string{
						"app.kubernetes.io/name":      "platform-controller",
						"app.kubernetes.io/component": "auth",
					},
				},
				Type: corev1.SecretTypeOpaque,
				Data: map[string][]byte{
					authSecretKey: []byte(newToken),
				},
			}
			_, err = s.k8sClient.Clientset.CoreV1().Secrets(ns).Create(ctx, newSecret, metav1.CreateOptions{})
			if err != nil {
				log.Error("Failed to create auth secret", slog.String("error", err.Error()))
				http.Error(w, fmt.Sprintf("failed to create auth secret: %v", err), http.StatusInternalServerError)
				return
			}
		}
	}

	s.tokenMu.Lock()
	s.activeToken = newToken
	s.tokenMu.Unlock()

	log.Info("API token successfully rotated",
		slog.String("namespace", ns),
		slog.String("secret", defaultAuthSecretName),
	)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"status":     "success",
		"message":    "API token rotated successfully",
		"api_key":    newToken,
		"secret_ref": fmt.Sprintf("%s/%s", ns, defaultAuthSecretName),
	})
}

func (s *Server) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Healthchecks bypass authentication unconditionally
		if r.URL.Path == "/healthz" || r.URL.Path == "/readyz" {
			next.ServeHTTP(w, r)
			return
		}

		s.tokenMu.RLock()
		expectedKey := s.activeToken
		s.tokenMu.RUnlock()

		if expectedKey != "" {
			reqKey := r.Header.Get("Api-Key")
			if reqKey == "" {
				authHeader := r.Header.Get("Authorization")
				if strings.HasPrefix(authHeader, "Bearer ") {
					reqKey = strings.TrimPrefix(authHeader, "Bearer ")
				}
			}

			if reqKey != expectedKey {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusUnauthorized)
				_ = json.NewEncoder(w).Encode(map[string]string{
					"error": "unauthorized: missing or invalid Api-Key header",
				})
				return
			}
		}

		next.ServeHTTP(w, r)
	})
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
