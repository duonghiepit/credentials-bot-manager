package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestGenerateSecureToken(t *testing.T) {
	token1, err := generateSecureToken()
	if err != nil {
		t.Fatalf("failed to generate token: %v", err)
	}

	if !strings.HasPrefix(token1, "vtt_sec_") {
		t.Errorf("expected token to start with 'vtt_sec_', got: %s", token1)
	}

	if len(token1) < 40 {
		t.Errorf("token length too short (%d chars)", len(token1))
	}

	token2, err := generateSecureToken()
	if err != nil {
		t.Fatalf("failed to generate token 2: %v", err)
	}

	if token1 == token2 {
		t.Errorf("expected distinct tokens, got collision: %s", token1)
	}
}

func TestAuthMiddleware(t *testing.T) {
	s := &Server{
		activeToken: "vtt_sec_test_valid_token_12345",
	}

	okHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	handler := s.authMiddleware(okHandler)

	// 1. Healthcheck should bypass auth
	reqHealth := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rrHealth := httptest.NewRecorder()
	handler.ServeHTTP(rrHealth, reqHealth)
	if rrHealth.Code != http.StatusOK {
		t.Errorf("expected 200 for /healthz, got %d", rrHealth.Code)
	}

	// 2. Request without token should return 401
	reqNoAuth := httptest.NewRequest(http.MethodGet, "/api/v1/secret/unmatched", nil)
	rrNoAuth := httptest.NewRecorder()
	handler.ServeHTTP(rrNoAuth, reqNoAuth)
	if rrNoAuth.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 without auth, got %d", rrNoAuth.Code)
	}

	// 3. Request with wrong token should return 401
	reqWrongAuth := httptest.NewRequest(http.MethodGet, "/api/v1/secret/unmatched", nil)
	reqWrongAuth.Header.Set("Api-Key", "wrong-token")
	rrWrongAuth := httptest.NewRecorder()
	handler.ServeHTTP(rrWrongAuth, reqWrongAuth)
	if rrWrongAuth.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 with wrong Api-Key, got %d", rrWrongAuth.Code)
	}

	// 4. Request with valid Api-Key should succeed
	reqValidAuth := httptest.NewRequest(http.MethodGet, "/api/v1/secret/unmatched", nil)
	reqValidAuth.Header.Set("Api-Key", "vtt_sec_test_valid_token_12345")
	rrValidAuth := httptest.NewRecorder()
	handler.ServeHTTP(rrValidAuth, reqValidAuth)
	if rrValidAuth.Code != http.StatusOK {
		t.Errorf("expected 200 with valid Api-Key, got %d", rrValidAuth.Code)
	}

	// 5. Request with valid Authorization: Bearer should succeed
	reqBearerAuth := httptest.NewRequest(http.MethodGet, "/api/v1/secret/unmatched", nil)
	reqBearerAuth.Header.Set("Authorization", "Bearer vtt_sec_test_valid_token_12345")
	rrBearerAuth := httptest.NewRecorder()
	handler.ServeHTTP(rrBearerAuth, reqBearerAuth)
	if rrBearerAuth.Code != http.StatusOK {
		t.Errorf("expected 200 with Bearer token, got %d", rrBearerAuth.Code)
	}
}
