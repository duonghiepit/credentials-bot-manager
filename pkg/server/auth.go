package server

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/duonghiepit/platform-controller/pkg/logger"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	defaultAuthSecretName = "platform-controller-auth"
	authSecretKey         = "api_key"
	maxFailedAuthPerMin   = 10
	authLockoutWindow     = 1 * time.Minute
)

type authAttemptTracker struct {
	mu       sync.Mutex
	attempts map[string]*ipAttempt
}

type ipAttempt struct {
	failures  int
	resetTime time.Time
}

func newAuthAttemptTracker() *authAttemptTracker {
	return &authAttemptTracker{
		attempts: make(map[string]*ipAttempt),
	}
}

func (t *authAttemptTracker) isBlocked(ip string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()

	now := time.Now()
	entry, exists := t.attempts[ip]
	if !exists {
		return false
	}
	if now.After(entry.resetTime) {
		delete(t.attempts, ip)
		return false
	}
	return entry.failures >= maxFailedAuthPerMin
}

func (t *authAttemptTracker) recordFailure(ip string) {
	t.mu.Lock()
	defer t.mu.Unlock()

	now := time.Now()
	if len(t.attempts) > 4096 {
		for k, v := range t.attempts {
			if now.After(v.resetTime) {
				delete(t.attempts, k)
			}
		}
	}

	entry, exists := t.attempts[ip]
	if !exists || now.After(entry.resetTime) {
		t.attempts[ip] = &ipAttempt{
			failures:  1,
			resetTime: now.Add(authLockoutWindow),
		}
		return
	}
	entry.failures++
}

func (t *authAttemptTracker) reset(ip string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.attempts, ip)
}

func extractClientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	ip := net.ParseIP(host)
	if ip != nil && (ip.IsPrivate() || ip.IsLoopback()) {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			parts := strings.Split(xff, ",")
			if first := strings.TrimSpace(parts[0]); first != "" {
				return first
			}
		}
		if xrip := strings.TrimSpace(r.Header.Get("X-Real-IP")); xrip != "" {
			return xrip
		}
	}
	return host
}

func generateSecureToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "vtt_sec_" + hex.EncodeToString(b), nil
}

// ensureAuthToken loads an existing token from K8s Secret or generates and persists a new one.
func (s *Server) ensureAuthToken(ctx context.Context) error {
	log := logger.L()
	ns := s.cfg.AuthNamespace
	if ns == "" {
		ns = "platform-system"
	}

	if s.k8sClient == nil || s.k8sClient.Clientset == nil {
		token, err := generateSecureToken()
		if err != nil {
			return fmt.Errorf("failed to generate standalone token: %w", err)
		}
		s.tokenMu.Lock()
		s.activeToken = token
		s.tokenMu.Unlock()
		log.Warn("Running without Kubernetes client; generated standalone in-memory API token (redacted from logs)")
		return nil
	}

	secret, err := s.k8sClient.Clientset.CoreV1().Secrets(ns).Get(ctx, defaultAuthSecretName, metav1.GetOptions{})
	if err == nil && secret != nil && len(secret.Data[authSecretKey]) > 0 {
		token := strings.TrimSpace(string(secret.Data[authSecretKey]))
		s.tokenMu.Lock()
		s.activeToken = token
		s.tokenMu.Unlock()
		log.Info("Loaded existing API token from Kubernetes Secret",
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
			s.activeToken = strings.TrimSpace(string(sec.Data[authSecretKey]))
			s.tokenMu.Unlock()
			return nil
		}
		return fmt.Errorf("failed to create auth secret %s/%s: %w", ns, defaultAuthSecretName, err)
	}

	s.tokenMu.Lock()
	s.activeToken = newToken
	s.tokenMu.Unlock()

	log.Info("Successfully generated initial API token and persisted to Kubernetes Secret",
		slog.String("namespace", ns),
		slog.String("secret", defaultAuthSecretName),
	)
	return nil
}

// handleRotateToken generates a new token and updates the Kubernetes Secret without leaking the secret in HTTP response.
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
		log.Error("Failed to generate token", slog.String("error", err.Error()))
		http.Error(w, "internal server error", http.StatusInternalServerError)
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
				http.Error(w, "failed to rotate auth secret", http.StatusInternalServerError)
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
				http.Error(w, "failed to rotate auth secret", http.StatusInternalServerError)
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
		"message":    "API token rotated and persisted to Kubernetes Secret",
		"secret_ref": fmt.Sprintf("%s/%s", ns, defaultAuthSecretName),
	})
}

// authMiddleware enforces fail-closed constant-time API key validation and per-IP brute-force protection.
func (s *Server) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if (r.URL.Path == "/healthz" || r.URL.Path == "/readyz" || r.URL.Path == "/metrics") && (r.Method == http.MethodGet || r.Method == http.MethodHead) {
			next.ServeHTTP(w, r)
			return
		}

		clientIP := extractClientIP(r)

		s.tokenMu.RLock()
		expectedKey := s.activeToken
		s.tokenMu.RUnlock()

		// Fail-closed: if server has no active token loaded, reject all requests.
		if expectedKey == "" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusServiceUnavailable)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"error": "authentication service unavailable",
			})
			return
		}

		reqKey := r.Header.Get("Api-Key")
		if reqKey == "" {
			authHeader := r.Header.Get("Authorization")
			if strings.HasPrefix(authHeader, "Bearer ") {
				reqKey = strings.TrimPrefix(authHeader, "Bearer ")
			}
		}

		// Constant-time comparison in memory (~20ns).
		// Checking token validity before IP lockout prevents attackers from DoS-ing legitimate CI/CD runners
		// behind a shared Ingress Controller or via X-Forwarded-For spoofing.
		if reqKey == "" || subtle.ConstantTimeCompare([]byte(reqKey), []byte(expectedKey)) != 1 {
			if s.authTracker != nil {
				if s.authTracker.isBlocked(clientIP) {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusTooManyRequests)
					_ = json.NewEncoder(w).Encode(map[string]string{
						"error": "too many failed authentication attempts; try again later",
					})
					return
				}
				s.authTracker.recordFailure(clientIP)
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"error": "unauthorized",
			})
			return
		}

		next.ServeHTTP(w, r)
	})
}
