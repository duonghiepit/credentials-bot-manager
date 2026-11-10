package deployer

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/duonghiepit/platform-controller/pkg/logger"
	"github.com/google/uuid"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// Config configures the GitOps Deployer
type Config struct {
	GitLabURL      string // e.g. "https://infra-gitlab.devops.pro"
	GitLabToken    string // Token with write access to GitOps repositories
	ClustersDir    string // Optional local directory containing cluster configs
	DefaultBranch  string // Default Git branch, e.g. "main"
	ArgoCDURL      string // Optional ArgoCD API URL
	ArgoCDToken    string // Optional ArgoCD API Token
}

// Manager coordinates GitOps updates, rollout monitoring, and deployment event tracking.
type Manager struct {
	cfg        Config
	k8sClient  kubernetes.Interface
	httpClient *http.Client

	mu     sync.RWMutex
	events map[string]*DeployEvent
}

// NewManager creates a new GitOps deployer manager.
func NewManager(cfg Config, k8sClient kubernetes.Interface) *Manager {
	if cfg.DefaultBranch == "" {
		cfg.DefaultBranch = "main"
	}
	if cfg.GitLabURL == "" {
		cfg.GitLabURL = os.Getenv("GITLAB_URL")
		if cfg.GitLabURL == "" {
			cfg.GitLabURL = "https://infra-gitlab.devops.pro"
		}
	}
	if cfg.GitLabToken == "" {
		cfg.GitLabToken = os.Getenv("GITLAB_TOKEN")
	}

	// HTTP client with TLS skip verify for private internal domain
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	return &Manager{
		cfg:        cfg,
		k8sClient:  k8sClient,
		httpClient: &http.Client{Transport: tr, Timeout: 30 * time.Second},
		events:     make(map[string]*DeployEvent),
	}
}

// StartDeployment validates request, registers a new event, and starts async execution.
func (m *Manager) StartDeployment(ctx context.Context, req DeployRequest) (*DeployResponse, error) {
	log := logger.L()

	if req.TargetCluster == "" {
		return nil, fmt.Errorf("targetDeploymentCluster is required")
	}
	if req.ImageURL == "" {
		return nil, fmt.Errorf("imageUrls is required")
	}

	// Parse image repository and tag
	imageRepo, imageTag, err := parseImageURL(req.ImageURL)
	if err != nil {
		return nil, fmt.Errorf("invalid imageUrls %q: %w", req.ImageURL, err)
	}

	// Auto-infer app yaml path if not provided
	if req.AppYAMLPath == "" {
		if req.AppName != "" {
			req.AppYAMLPath = fmt.Sprintf("%s.yaml", req.AppName)
		} else {
			// Infer from git repo or image repo name
			parts := strings.Split(imageRepo, "/")
			appName := parts[len(parts)-1]
			req.AppName = appName
			req.AppYAMLPath = fmt.Sprintf("%s/%s.yaml", appName, appName)
		}
	}

	// Prevent path traversal
	cleanedPath := filepath.Clean(req.AppYAMLPath)
	if strings.HasPrefix(cleanedPath, "..") || strings.HasPrefix(cleanedPath, "/") {
		return nil, fmt.Errorf("invalid appYamlPath: path traversal is not permitted")
	}

	eventID := fmt.Sprintf("dep-%s", uuid.New().String()[:8])
	event := &DeployEvent{
		EventID:       eventID,
		DeployStatus:  StatusPending,
		DeployMessage: fmt.Sprintf("Deployment queued for %s to %s", req.AppYAMLPath, imageTag),
		TargetCluster: req.TargetCluster,
		ImageURL:      req.ImageURL,
		ImageTag:      imageTag,
		GitCommit:     req.GitCommit,
		CreatedAt:     time.Now().UTC(),
		UpdatedAt:     time.Now().UTC(),
	}

	m.mu.Lock()
	m.events[eventID] = event
	m.mu.Unlock()

	log.Info("Deployment event initiated",
		slog.String("eventId", eventID),
		slog.String("targetCluster", req.TargetCluster),
		slog.String("appYamlPath", req.AppYAMLPath),
		slog.String("imageTag", imageTag))

	// Run rollout asynchronously in background
	go m.executeDeployment(eventID, req, imageRepo, imageTag)

	return &DeployResponse{
		EventID:       eventID,
		DeployStatus:  StatusRunning,
		DeployMessage: "Deployment event accepted and is being processed",
	}, nil
}

// GetEventStatus retrieves current state of a deployment event.
func (m *Manager) GetEventStatus(eventID string) (*DeployEvent, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	ev, exists := m.events[eventID]
	if !exists {
		return nil, false
	}
	// Return a copy to avoid data races
	cp := *ev
	return &cp, true
}

func (m *Manager) executeDeployment(eventID string, req DeployRequest, imageRepo, imageTag string) {
	log := logger.L().With(slog.String("eventId", eventID))

	m.updateEventStatus(eventID, StatusRunning, "Patching GitOps configuration repository...")

	// 1. Execute GitOps Patch
	err := m.patchGitOpsRepo(req.TargetCluster, req.AppYAMLPath, imageRepo, imageTag, req.GitCommit)
	if err != nil {
		log.Error("GitOps patch failed", slog.String("error", err.Error()))
		m.updateEventStatus(eventID, StatusFailed, fmt.Sprintf("GitOps patch failed: %v", err))
		return
	}

	log.Info("GitOps repository updated successfully",
		slog.String("cluster", req.TargetCluster),
		slog.String("file", req.AppYAMLPath),
		slog.String("tag", imageTag))

	// 2. Trigger ArgoCD sync if configured
	if m.cfg.ArgoCDURL != "" && m.cfg.ArgoCDToken != "" {
		m.updateEventStatus(eventID, StatusRunning, "Triggering ArgoCD application sync...")
		if syncErr := m.triggerArgoSync(req.AppName); syncErr != nil {
			log.Warn("ArgoCD trigger sync returned error", slog.String("error", syncErr.Error()))
		}
	}

	// 3. Monitor K8s Rollout
	if m.k8sClient != nil && req.Namespace != "" && req.AppName != "" {
		m.updateEventStatus(eventID, StatusRunning, fmt.Sprintf("Monitoring Kubernetes rollout for %s in %s...", req.AppName, req.Namespace))
		if rolloutErr := m.waitForRollout(req.Namespace, req.AppName, 90*time.Second); rolloutErr != nil {
			log.Error("Rollout check failed", slog.String("error", rolloutErr.Error()))
			m.updateEventStatus(eventID, StatusFailed, fmt.Sprintf("Rollout failed: %v", rolloutErr))
			return
		}
	}

	m.updateEventStatus(eventID, StatusSuccess, fmt.Sprintf("Successfully deployed %s:%s to %s", imageRepo, imageTag, req.TargetCluster))
}

func (m *Manager) updateEventStatus(eventID string, status DeployStatus, msg string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if ev, ok := m.events[eventID]; ok {
		ev.DeployStatus = status
		ev.DeployMessage = msg
		ev.UpdatedAt = time.Now().UTC()
	}
}

// patchGitOpsRepo performs atomic update on target GitOps repo either via GitLab API or local filesystem.
func (m *Manager) patchGitOpsRepo(targetCluster, appYamlPath, imageRepo, newTag, commitSHA string) error {
	// If GitLab token is present, use GitLab API for atomic single-commit updates without local disk dependency
	if m.cfg.GitLabToken != "" && m.cfg.GitLabURL != "" {
		return m.patchViaGitLabAPI(targetCluster, appYamlPath, imageRepo, newTag, commitSHA)
	}

	// Fallback to local filesystem if clusters directory is mounted
	if m.cfg.ClustersDir != "" {
		return m.patchViaFilesystem(targetCluster, appYamlPath, imageRepo, newTag)
	}

	return fmt.Errorf("no GitLab token or local clusters directory configured for GitOps writes")
}

func (m *Manager) patchViaGitLabAPI(projectPath, filePath, imageRepo, newTag, commitSHA string) error {
	encodedProject := url.PathEscape(projectPath)
	encodedFile := url.PathEscape(filePath)

	// 1. Fetch current file content
	getURL := fmt.Sprintf("%s/api/v4/projects/%s/repository/files/%s/raw?ref=%s",
		m.cfg.GitLabURL, encodedProject, encodedFile, m.cfg.DefaultBranch)

	req, err := http.NewRequest(http.MethodGet, getURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("PRIVATE-TOKEN", m.cfg.GitLabToken)

	resp, err := m.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to fetch current file from GitLab: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("GitLab get file error (%d): %s", resp.StatusCode, string(body))
	}

	oldContent, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read file content: %w", err)
	}

	// 2. Patch AST
	patchedContent, err := PatchImageTag(oldContent, imageRepo, newTag)
	if err != nil {
		return fmt.Errorf("failed to patch yaml content: %w", err)
	}

	// 3. Commit change via GitLab Commits API
	commitURL := fmt.Sprintf("%s/api/v4/projects/%s/repository/commits", m.cfg.GitLabURL, encodedProject)
	commitPayload := map[string]interface{}{
		"branch":         m.cfg.DefaultBranch,
		"commit_message": fmt.Sprintf("chore(deploy): update %s image to %s [commit %s] [skip ci]", filepath.Base(filePath), newTag, commitSHA),
		"actions": []map[string]string{
			{
				"action":    "update",
				"file_path": filePath,
				"content":   string(patchedContent),
			},
		},
	}

	payloadBytes, err := json.Marshal(commitPayload)
	if err != nil {
		return err
	}

	postReq, err := http.NewRequest(http.MethodPost, commitURL, bytes.NewReader(payloadBytes))
	if err != nil {
		return err
	}
	postReq.Header.Set("PRIVATE-TOKEN", m.cfg.GitLabToken)
	postReq.Header.Set("Content-Type", "application/json")

	postResp, err := m.httpClient.Do(postReq)
	if err != nil {
		return fmt.Errorf("failed to post commit to GitLab: %w", err)
	}
	defer postResp.Body.Close()

	if postResp.StatusCode != http.StatusOK && postResp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(postResp.Body)
		return fmt.Errorf("GitLab commit error (%d): %s", postResp.StatusCode, string(body))
	}

	return nil
}

func (m *Manager) patchViaFilesystem(targetCluster, appYamlPath, imageRepo, newTag string) error {
	fullPath := filepath.Join(m.cfg.ClustersDir, targetCluster, appYamlPath)
	content, err := os.ReadFile(fullPath)
	if err != nil {
		return fmt.Errorf("failed to read local cluster file %s: %w", fullPath, err)
	}

	patched, err := PatchImageTag(content, imageRepo, newTag)
	if err != nil {
		return err
	}

	return os.WriteFile(fullPath, patched, 0644)
}

func (m *Manager) triggerArgoSync(appName string) error {
	if appName == "" {
		return nil
	}
	syncURL := fmt.Sprintf("%s/api/v1/applications/%s/sync", strings.TrimSuffix(m.cfg.ArgoCDURL, "/"), appName)
	req, err := http.NewRequest(http.MethodPost, syncURL, bytes.NewBufferString("{}"))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+m.cfg.ArgoCDToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := m.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return nil
}

func (m *Manager) waitForRollout(namespace, appName string, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("timed out waiting for deployment %s rollout in %s", appName, namespace)
		case <-ticker.C:
			deploy, err := m.k8sClient.AppsV1().Deployments(namespace).Get(ctx, appName, metav1.GetOptions{})
			if err != nil {
				return err
			}
			var desiredReplicas int32 = 1
			if deploy.Spec.Replicas != nil {
				desiredReplicas = *deploy.Spec.Replicas
			}
			if deploy.Generation <= deploy.Status.ObservedGeneration &&
				deploy.Status.UpdatedReplicas == desiredReplicas &&
				deploy.Status.AvailableReplicas == desiredReplicas {
				return nil
			}
		}
	}
}

func parseImageURL(raw string) (repo, tag string, err error) {
	idx := strings.LastIndex(raw, ":")
	if idx == -1 {
		return "", "", fmt.Errorf("missing tag separator ':' in image %s", raw)
	}
	return raw[:idx], raw[idx+1:], nil
}
