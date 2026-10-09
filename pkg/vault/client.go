package vault

import (
	"context"
	"fmt"
	"os"
	"time"

	vaultapi "github.com/hashicorp/vault/api"
)

// Client wraps the HashiCorp Vault API client.
type Client struct {
	client *vaultapi.Client
}

// NewClient initializes a new Vault API client with automatic retries and timeout.
func NewClient(address, token string) (*Client, error) {
	config := vaultapi.DefaultConfig()
	config.MaxRetries = 3
	config.Timeout = 30 * time.Second
	if address != "" {
		config.Address = address
	}

	client, err := vaultapi.NewClient(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create vault client: %w", err)
	}

	if token != "" {
		client.SetToken(token)
	} else {
		// Attempt in-cluster Kubernetes ServiceAccount authentication if running in a Pod
		jwtPath := "/var/run/secrets/kubernetes.io/serviceaccount/token"
		if _, err := os.Stat(jwtPath); err == nil {
			jwtBytes, err := os.ReadFile(jwtPath)
			if err == nil {
				role := os.Getenv("VAULT_K8S_ROLE")
				if role == "" {
					role = "platform-controller"
				}
				mount := os.Getenv("VAULT_K8S_MOUNT")
				if mount == "" {
					mount = "kubernetes"
				}
				path := fmt.Sprintf("auth/%s/login", mount)
				data := map[string]interface{}{
					"role": role,
					"jwt":  string(jwtBytes),
				}
				secret, err := client.Logical().Write(path, data)
				if err == nil && secret != nil && secret.Auth != nil {
					client.SetToken(secret.Auth.ClientToken)
				}
			}
		}
	}

	return &Client{client: client}, nil
}

// K8sAuthConfigPayload contains the fields needed by Vault's auth/kubernetes/config endpoint.
type K8sAuthConfigPayload struct {
	KubernetesHost       string `json:"kubernetes_host"`
	KubernetesCACert     string `json:"kubernetes_ca_cert"`
	TokenReviewerJWT     string `json:"token_reviewer_jwt"`
	DisableLocalCAJWT    bool   `json:"disable_local_ca_jwt"`
	DisableISSValidation bool   `json:"disable_iss_validation"`
}

// ConfigureKubernetesAuth configures a Kubernetes auth backend mount with the cluster credentials.
func (c *Client) ConfigureKubernetesAuth(ctx context.Context, mountPath string, payload K8sAuthConfigPayload) error {
	path := fmt.Sprintf("auth/%s/config", mountPath)

	data := map[string]interface{}{
		"kubernetes_host":        payload.KubernetesHost,
		"kubernetes_ca_cert":     payload.KubernetesCACert,
		"token_reviewer_jwt":     payload.TokenReviewerJWT,
		"disable_local_ca_jwt":   payload.DisableLocalCAJWT,
		"disable_iss_validation": payload.DisableISSValidation,
	}

	_, err := c.client.Logical().WriteWithContext(ctx, path, data)
	if err != nil {
		return fmt.Errorf("failed to write vault k8s auth config at %s: %w", path, err)
	}

	return nil
}

// VerifyHealth checks if the Vault instance is reachable.
func (c *Client) VerifyHealth(ctx context.Context) error {
	health, err := c.client.Sys().HealthWithContext(ctx)
	if err != nil {
		return fmt.Errorf("vault health check failed: %w", err)
	}
	if !health.Initialized {
		return fmt.Errorf("vault is not initialized")
	}
	if health.Sealed {
		return fmt.Errorf("vault is sealed")
	}
	return nil
}

// ListSecretKeys lists all secret keys in a KV-v2 engine under mountPath/metadata/folderPath.
func (c *Client) ListSecretKeys(ctx context.Context, mountPath, folderPath string) ([]string, error) {
	if c == nil || c.client == nil {
		return nil, fmt.Errorf("vault client is not initialized")
	}
	path := fmt.Sprintf("%s/metadata/%s", mountPath, folderPath)
	secret, err := c.client.Logical().ListWithContext(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("failed to list vault secret keys at %s: %w", path, err)
	}
	if secret == nil || secret.Data == nil {
		return nil, nil
	}
	rawKeys, ok := secret.Data["keys"].([]interface{})
	if !ok {
		return nil, nil
	}
	var keys []string
	for _, k := range rawKeys {
		if str, ok := k.(string); ok {
			keys = append(keys, str)
		}
	}
	return keys, nil
}

// PurgeSecretMetadata permanently purges secret metadata and all historical versions in Vault KV-v2.
func (c *Client) PurgeSecretMetadata(ctx context.Context, mountPath, folderPath, secretName string) error {
	if c == nil || c.client == nil {
		return fmt.Errorf("vault client is not initialized")
	}
	path := fmt.Sprintf("%s/metadata/%s/%s", mountPath, folderPath, secretName)
	_, err := c.client.Logical().DeleteWithContext(ctx, path)
	if err != nil {
		return fmt.Errorf("failed to purge vault secret metadata at %s: %w", path, err)
	}
	return nil
}
