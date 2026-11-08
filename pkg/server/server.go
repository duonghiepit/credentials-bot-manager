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
	cfg         Config
	k8sClient   *k8s.Client
	applier     *syncpkg.Applier
	server      *http.Server
	wg          sync.WaitGroup
	authTracker *authAttemptTracker

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
		cfg:         cfg,
		k8sClient:   k8sClient,
		applier:     applier,
		authTracker: newAuthAttemptTracker(),
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
	mux.HandleFunc("/", s.handleNotFound)

	authHandler := s.authMiddleware(mux)
	secHandler := securityHeadersMiddleware(authHandler)
	loggedHandler := loggingMiddleware(secHandler)

	s.server = &http.Server{
		Addr:              fmt.Sprintf(":%d", cfg.Port),
		Handler:           loggedHandler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 14, // 16KB max headers
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

		log.Info("Waiting for background workers to complete...")
		s.wg.Wait()
		log.Info("All workers completed. Graceful shutdown finished.")
		return nil

	case err := <-errChan:
		log.Error("HTTP server encountered fatal error", slog.String("error", err.Error()))
		return err
	}
}

func securityHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Security-Policy", "default-src 'none'")
		next.ServeHTTP(w, r)
	})
}

// statusWriter wraps http.ResponseWriter to capture HTTP status and response size.
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
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"status": "ok",
	})
}

func (s *Server) handleNotFound(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusNotFound)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error": "not found",
	})
}
