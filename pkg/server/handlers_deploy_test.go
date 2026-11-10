package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/duonghiepit/platform-controller/pkg/deployer"
)

func TestDeployHandlers(t *testing.T) {
	// Prepare a temporary cluster directory with a sample deployment manifest
	tmpDir, err := os.MkdirTemp("", "deploy-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	clusterName := "dev-business-cluster"
	clusterDir := filepath.Join(tmpDir, clusterName)
	if err := os.MkdirAll(clusterDir, 0755); err != nil {
		t.Fatalf("failed to create cluster dir: %v", err)
	}

	initialYAML := `apiVersion: apps/v1
kind: Deployment
metadata:
  name: demo-service
  namespace: business-dev
spec:
  replicas: 1
  template:
    spec:
      containers:
        - name: app
          image: infra-registry.devops.pro/business/demo-service:v1.0.0
`
	appYamlPath := "demo-service.yaml"
	if err := os.WriteFile(filepath.Join(clusterDir, appYamlPath), []byte(initialYAML), 0644); err != nil {
		t.Fatalf("failed to write initial yaml: %v", err)
	}

	cfg := Config{
		Port:          8080,
		ClustersDir:   tmpDir,
		DefaultBranch: "main",
	}

	deployMgr := deployer.NewManager(deployer.Config{
		ClustersDir:   tmpDir,
		DefaultBranch: "main",
	}, nil)

	s := &Server{
		cfg:           cfg,
		deployManager: deployMgr,
		activeToken:   "test-secret-token",
		authTracker:   newAuthAttemptTracker(),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/deploy", s.handleDeployContainerImages)
	mux.HandleFunc("/api/v1/deploy/status", s.handleReloadDeployStatus)
	mux.HandleFunc("/configsManager/deployContainerImages", s.handleDeployContainerImages)
	mux.HandleFunc("/configsManager/reloadDeployStatus", s.handleReloadDeployStatus)

	handler := s.authMiddleware(mux)

	t.Run("Deploy rejected without auth token", func(t *testing.T) {
		reqBody := `{"targetDeploymentCluster":"dev-business-cluster","imageUrls":"infra-registry.devops.pro/business/demo-service:v1.1.0"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/deploy", bytes.NewBufferString(reqBody))
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401 Unauthorized, got %d", w.Code)
		}
	})

	t.Run("Deploy rejected on path traversal", func(t *testing.T) {
		reqBody := `{"targetDeploymentCluster":"dev-business-cluster","imageUrls":"infra-registry.devops.pro/business/demo-service:v1.1.0","appYamlPath":"../etc/passwd"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/deploy", bytes.NewBufferString(reqBody))
		req.Header.Set("Api-Key", "test-secret-token")
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("expected 401 BadRequest, got %d", w.Code)
		}
	})

	var eventID string

	t.Run("Deploy accepted via KV endpoint", func(t *testing.T) {
		payload := deployer.DeployRequest{
			TargetCluster: clusterName,
			AppName:       "demo-service",
			AppYAMLPath:   appYamlPath,
			ImageURL:      "infra-registry.devops.pro/business/demo-service:v1.1.0",
			GitCommit:     "abc1234",
		}
		data, _ := json.Marshal(payload)

		req := httptest.NewRequest(http.MethodPost, "/configsManager/deployContainerImages", bytes.NewBuffer(data))
		req.Header.Set("Authorization", "Bearer test-secret-token")
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200 OK, got %d: %s", w.Code, w.Body.String())
		}

		var resp struct {
			Code int                     `json:"code"`
			Data deployer.DeployResponse `json:"data"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("failed to decode response: %v", err)
		}
		if resp.Data.EventID == "" {
			t.Fatalf("expected eventId, got empty")
		}
		eventID = resp.Data.EventID
	})

	t.Run("Check status until success via KV reload endpoint", func(t *testing.T) {
		statusPayload := deployer.DeployStatusRequest{
			EventID: eventID,
		}
		data, _ := json.Marshal(statusPayload)

		// Give background worker time to complete filesystem patch
		for i := 0; i < 30; i++ {
			time.Sleep(20 * time.Millisecond)

			req := httptest.NewRequest(http.MethodPost, "/configsManager/reloadDeployStatus", bytes.NewBuffer(data))
			req.Header.Set("Api-Key", "test-secret-token")
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			handler.ServeHTTP(w, req)
			if w.Code != http.StatusOK {
				t.Fatalf("expected 200 OK, got %d", w.Code)
			}

			var resp struct {
				Data struct {
					EventID      string                `json:"eventId"`
					DeployStatus deployer.DeployStatus `json:"deployStatus"`
				} `json:"data"`
			}
			if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
				t.Fatalf("failed to unmarshal: %v", err)
			}

			if resp.Data.DeployStatus == deployer.StatusSuccess {
				break
			}
		}

		// Verify file content was patched on disk
		content, err := os.ReadFile(filepath.Join(clusterDir, appYamlPath))
		if err != nil {
			t.Fatalf("failed to read patched file: %v", err)
		}
		if !bytes.Contains(content, []byte("infra-registry.devops.pro/business/demo-service:v1.1.0")) {
			t.Fatalf("expected patched image v1.1.0 in manifest, got:\n%s", string(content))
		}
	})
}
