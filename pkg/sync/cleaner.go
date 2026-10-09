package sync

import (
	"context"
	"fmt"
	"strings"

	"github.com/duonghiepit/platform-controller/pkg/model"
	"github.com/duonghiepit/platform-controller/pkg/vault"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
)

var externalSecretGVR = schema.GroupVersionResource{
	Group:    "external-secrets.io",
	Version:  "v1",
	Resource: "externalsecrets",
}

// NamespaceUnmatchedReport holds unmatched/orphaned secret keys for a single namespace.
type NamespaceUnmatchedReport struct {
	Namespace      string   `json:"namespace"`
	VaultMount     string   `json:"vault_mount,omitempty"`
	VaultUnmatched []string `json:"vault_unmatched"`
	K8sUnmatched   []string `json:"k8s_unmatched"`
}

// UnmatchedReport aggregates unmatched secrets across namespaces.
type UnmatchedReport struct {
	ClusterName         string                      `json:"cluster_name"`
	Reports             []*NamespaceUnmatchedReport `json:"reports"`
	TotalVaultUnmatched int                         `json:"total_vault_unmatched"`
	TotalK8sUnmatched   int                         `json:"total_k8s_unmatched"`
}

// CleanupResult details which orphaned items were purged.
type CleanupResult struct {
	ClusterName         string   `json:"cluster_name"`
	DryRun              bool     `json:"dry_run"`
	Target              string   `json:"target"`
	DeletedVaultSecrets []string `json:"deleted_vault_secrets"`
	DeletedK8sSecrets   []string `json:"deleted_k8s_secrets"`
}

// DetectUnmatchedSecrets compares declared secrets against Vault and Kubernetes.
func DetectUnmatchedSecrets(
	ctx context.Context,
	clusterName string,
	cfg *model.NamespaceConfig,
	vaultClient *vault.Client,
	dynamicClient dynamic.Interface,
) (*NamespaceUnmatchedReport, error) {
	report := &NamespaceUnmatchedReport{
		Namespace:      cfg.Namespace,
		VaultUnmatched: make([]string, 0),
		K8sUnmatched:   make([]string, 0),
	}

	// 1. Build declared secret sets from GitOps configuration
	declaredVaultSecrets := make(map[string]bool)
	declaredK8sExternalSecrets := make(map[string]bool)

	for _, s := range cfg.Secrets.ES {
		declaredVaultSecrets[s] = true
		declaredK8sExternalSecrets[strings.ReplaceAll(s, "_", "-")] = true
	}
	for _, s := range cfg.Secrets.CSI {
		declaredVaultSecrets[s] = true
	}

	// 2. Query Vault KV-v2 secret keys if Vault client is configured
	if vaultClient != nil {
		mount := fmt.Sprintf("kv2-%s", clusterName)
		if strings.HasPrefix(clusterName, "kv2-") {
			mount = clusterName
		}
		report.VaultMount = mount

		vaultKeys, err := vaultClient.ListSecretKeys(ctx, mount, cfg.Namespace)
		if err == nil {
			for _, k := range vaultKeys {
				if !declaredVaultSecrets[k] {
					report.VaultUnmatched = append(report.VaultUnmatched, k)
				}
			}
		}
	}

	// 3. Query Kubernetes ExternalSecrets if DynamicClient is configured
	if dynamicClient != nil {
		list, err := dynamicClient.Resource(externalSecretGVR).Namespace(cfg.Namespace).List(ctx, metav1.ListOptions{})
		if err == nil && list != nil {
			for _, item := range list.Items {
				name := item.GetName()
				if !declaredK8sExternalSecrets[name] {
					report.K8sUnmatched = append(report.K8sUnmatched, name)
				}
			}
		}
	}

	return report, nil
}

// PurgeUnmatchedSecrets removes unmatched secrets from Kubernetes and/or Vault.
func PurgeUnmatchedSecrets(
	ctx context.Context,
	clusterName string,
	report *NamespaceUnmatchedReport,
	vaultClient *vault.Client,
	dynamicClient dynamic.Interface,
	target string,
	dryRun bool,
) (*CleanupResult, error) {
	if target == "" {
		target = "all"
	}

	res := &CleanupResult{
		ClusterName:         clusterName,
		DryRun:              dryRun,
		Target:              target,
		DeletedVaultSecrets: make([]string, 0),
		DeletedK8sSecrets:   make([]string, 0),
	}

	shouldCleanK8s := target == "all" || target == "k8s"
	shouldCleanVault := target == "all" || target == "vault"

	// 1. Purge orphaned Kubernetes ExternalSecrets
	if shouldCleanK8s && dynamicClient != nil {
		for _, name := range report.K8sUnmatched {
			identifier := fmt.Sprintf("%s/%s", report.Namespace, name)
			if !dryRun {
				err := dynamicClient.Resource(externalSecretGVR).Namespace(report.Namespace).Delete(ctx, name, metav1.DeleteOptions{})
				if err != nil {
					return res, fmt.Errorf("failed to delete ExternalSecret %s: %w", identifier, err)
				}
			}
			res.DeletedK8sSecrets = append(res.DeletedK8sSecrets, identifier)
		}
	}

	// 2. Purge orphaned Vault secret metadata and versions (Permanent Purge)
	if shouldCleanVault && vaultClient != nil && report.VaultMount != "" {
		for _, sec := range report.VaultUnmatched {
			identifier := fmt.Sprintf("%s/%s/%s", report.VaultMount, report.Namespace, sec)
			if !dryRun {
				err := vaultClient.PurgeSecretMetadata(ctx, report.VaultMount, report.Namespace, sec)
				if err != nil {
					return res, fmt.Errorf("failed to purge Vault secret %s: %w", identifier, err)
				}
			}
			res.DeletedVaultSecrets = append(res.DeletedVaultSecrets, identifier)
		}
	}

	return res, nil
}

// DetectConfigsUnmatchedSecrets compares a slice of namespace configs against Vault and Kubernetes.
func DetectConfigsUnmatchedSecrets(
	ctx context.Context,
	clusterName string,
	configs []*model.NamespaceConfig,
	checkClusterWide bool,
	vaultClient *vault.Client,
	dynamicClient dynamic.Interface,
) (*UnmatchedReport, error) {
	report := &UnmatchedReport{
		ClusterName: clusterName,
		Reports:     make([]*NamespaceUnmatchedReport, 0),
	}

	configByNs := make(map[string]*model.NamespaceConfig)
	for _, cfg := range configs {
		configByNs[cfg.Namespace] = cfg
		nsReport, err := DetectUnmatchedSecrets(ctx, clusterName, cfg, vaultClient, dynamicClient)
		if err != nil {
			return nil, err
		}
		if len(nsReport.VaultUnmatched) > 0 || len(nsReport.K8sUnmatched) > 0 {
			report.Reports = append(report.Reports, nsReport)
			report.TotalVaultUnmatched += len(nsReport.VaultUnmatched)
			report.TotalK8sUnmatched += len(nsReport.K8sUnmatched)
		}
	}

	// If checkClusterWide is true, also check for orphaned namespaces (present in Vault/K8s but deleted from GitOps)
	if checkClusterWide {
		mount := fmt.Sprintf("kv2-%s", clusterName)
		if strings.HasPrefix(clusterName, "kv2-") {
			mount = clusterName
		}

		if vaultClient != nil {
			vaultFolders, err := vaultClient.ListSecretKeys(ctx, mount, "")
			if err == nil {
				for _, folder := range vaultFolders {
					ns := strings.TrimSuffix(folder, "/")
					if _, declared := configByNs[ns]; !declared && ns != "" {
						keys, err := vaultClient.ListSecretKeys(ctx, mount, ns)
						if err == nil && len(keys) > 0 {
							var nsReport *NamespaceUnmatchedReport
							for _, r := range report.Reports {
								if r.Namespace == ns {
									nsReport = r
									break
								}
							}
							if nsReport == nil {
								nsReport = &NamespaceUnmatchedReport{
									Namespace:      ns,
									VaultMount:     mount,
									VaultUnmatched: make([]string, 0),
									K8sUnmatched:   make([]string, 0),
								}
								report.Reports = append(report.Reports, nsReport)
							}
							nsReport.VaultMount = mount
							nsReport.VaultUnmatched = append(nsReport.VaultUnmatched, keys...)
							report.TotalVaultUnmatched += len(keys)
						}
					}
				}
			}
		}

		if dynamicClient != nil {
			list, err := dynamicClient.Resource(externalSecretGVR).List(ctx, metav1.ListOptions{})
			if err == nil && list != nil {
				for _, item := range list.Items {
					ns := item.GetNamespace()
					name := item.GetName()
					if _, declared := configByNs[ns]; !declared {
						var nsReport *NamespaceUnmatchedReport
						for _, r := range report.Reports {
							if r.Namespace == ns {
								nsReport = r
								break
							}
						}
						if nsReport == nil {
							nsReport = &NamespaceUnmatchedReport{
								Namespace:      ns,
								VaultMount:     mount,
								VaultUnmatched: make([]string, 0),
								K8sUnmatched:   make([]string, 0),
							}
							report.Reports = append(report.Reports, nsReport)
						}
						nsReport.K8sUnmatched = append(nsReport.K8sUnmatched, name)
						report.TotalK8sUnmatched++
					}
				}
			}
		}
	}

	return report, nil
}

// DetectClusterUnmatchedSecrets scans all declared configs in registry and discovers orphaned secrets in Vault and K8s.
func DetectClusterUnmatchedSecrets(
	ctx context.Context,
	registryPath string,
	clusterName string,
	nsFilter string,
	vaultClient *vault.Client,
	dynamicClient dynamic.Interface,
) (*UnmatchedReport, error) {
	configs, err := LoadClusterConfigs(registryPath, clusterName, nsFilter)
	if err != nil {
		return nil, fmt.Errorf("failed to load cluster configs: %w", err)
	}

	return DetectConfigsUnmatchedSecrets(ctx, clusterName, configs, nsFilter == "", vaultClient, dynamicClient)
}

// PurgeClusterUnmatchedSecrets iterates through all namespace reports and purges orphaned items.
func PurgeClusterUnmatchedSecrets(
	ctx context.Context,
	report *UnmatchedReport,
	vaultClient *vault.Client,
	dynamicClient dynamic.Interface,
	target string,
	dryRun bool,
) (*CleanupResult, error) {
	if target == "" {
		target = "all"
	}

	result := &CleanupResult{
		ClusterName:         report.ClusterName,
		DryRun:              dryRun,
		Target:              target,
		DeletedVaultSecrets: make([]string, 0),
		DeletedK8sSecrets:   make([]string, 0),
	}

	for _, nsReport := range report.Reports {
		res, err := PurgeUnmatchedSecrets(ctx, report.ClusterName, nsReport, vaultClient, dynamicClient, target, dryRun)
		if err != nil {
			return result, err
		}
		result.DeletedVaultSecrets = append(result.DeletedVaultSecrets, res.DeletedVaultSecrets...)
		result.DeletedK8sSecrets = append(result.DeletedK8sSecrets, res.DeletedK8sSecrets...)
	}

	return result, nil
}
