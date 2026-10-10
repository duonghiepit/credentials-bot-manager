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
	"time"

	"github.com/duonghiepit/platform-controller/pkg/logger"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	defaultAuthSecretName = "platform-controller-auth"
	authSecretKey         = "api_key"
)

func generateSecureToken() (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "vtt_sec_" + hex.EncodeToString(b), nil
}

// ensureAuthToken loads an existing token from K8s Secret or generates and persists a new one (ArgoCD style).
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

// handleRotateToken generates a new token and updates the Kubernetes Secret.
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

// authMiddleware enforces API key validation for incoming requests.
func (s *Server) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
