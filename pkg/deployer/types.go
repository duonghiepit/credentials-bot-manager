package deployer

import (
	"time"
)

// DeployStatus represents deployment lifecycle state.
type DeployStatus int

const (
	StatusSuccess DeployStatus = 0
	StatusFailed  DeployStatus = -1
	StatusRunning DeployStatus = 1
	StatusPending DeployStatus = 2
)

// DeployRequest payload for POST /api/v1/deploy
type DeployRequest struct {
	TargetCluster   string `json:"targetDeploymentCluster"`
	ImageURL        string `json:"imageUrls"` // Format: <repo>:<tag>
	GitCommit       string `json:"gitCommit"`
	GitBranch       string `json:"gitBranch"`
	GitRepo         string `json:"gitRepo"`
	AppYAMLPath     string `json:"appYamlPath,omitempty"`
	AppName         string `json:"appName,omitempty"`
	Namespace       string `json:"namespace,omitempty"`
}

// DeployResponse data returned on initiate
type DeployResponse struct {
	EventID       string       `json:"eventId"`
	DeployStatus  DeployStatus `json:"deployStatus"`
	DeployMessage string       `json:"deployMessage"`
}

// DeployStatusRequest payload for POST /api/v1/deploy/status
type DeployStatusRequest struct {
	EventID string `json:"eventId"`
}

// DeployEvent stores the in-memory state of an ongoing or finished deployment
type DeployEvent struct {
	EventID       string       `json:"eventId"`
	DeployStatus  DeployStatus `json:"deployStatus"`
	DeployMessage string       `json:"deployMessage"`
	TargetCluster string       `json:"targetCluster"`
	ImageURL      string       `json:"imageUrl"`
	ImageTag      string       `json:"imageTag"`
	GitCommit     string       `json:"gitCommit"`
	CreatedAt     time.Time    `json:"createdAt"`
	UpdatedAt     time.Time    `json:"updatedAt"`
	Error         string       `json:"error,omitempty"`
}
