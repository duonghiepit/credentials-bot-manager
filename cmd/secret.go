package cmd

import (
	"context"
	"fmt"
	"time"

	"github.com/duonghiepit/platform-controller/pkg/k8s"
	"github.com/duonghiepit/platform-controller/pkg/sync"
	"github.com/duonghiepit/platform-controller/pkg/vault"
	"github.com/spf13/cobra"
	"k8s.io/client-go/dynamic"
)

var (
	registryPath   string
	nsFilter       string
	k8sVaultServer string
	syncDryRun     bool

	cleanupUnmatched bool
	cleanupTarget    string
	unmatchedDryRun  bool
)

var secretCmd = &cobra.Command{
	Use:   "secret",
	Short: "Manage and synchronize secrets (External Secrets & CSI Driver)",
}

var secretSyncCmd = &cobra.Command{
	Use:   "sync",
	Short: "Sync secrets from GitOps Registry into Kubernetes cluster (ES & CSI)",
	Long: `Reads declarative namespace manifests from the GitOps Registry (registry/clusters/<cluster>/<namespace>.yaml).
Automatically classifies and generates:
1. SecretStore: Namespaced Vault backend (Least Privilege).
2. ExternalSecret: For all secrets under 'secrets.es' (synced to Native K8s Secret).
3. SecretProviderClass: For all secrets under 'secrets.csi' (RAM tmpfs only - Zero etcd).`,
	RunE: runSecretSync,
}

var secretUnmatchedCmd = &cobra.Command{
	Use:   "unmatched",
	Short: "Detect and purge unmatched/orphaned secrets (in Vault KV-v2 and Kubernetes ExternalSecrets)",
	Long: `Scans GitOps registry definitions against live Vault KV-v2 secret engines and Kubernetes ExternalSecrets.
Detects secrets or namespaces that exist in infrastructure but are not declared in GitOps (or lack retention).
Allows safe dry-run inspection and permanent purging of metadata and versions.`,
	RunE: runSecretUnmatched,
}

func init() {
	secretSyncCmd.Flags().StringVarP(&clusterName, "cluster", "c", "", "Target Kubernetes cluster name (required)")
	secretSyncCmd.Flags().StringVarP(&registryPath, "registry", "r", "./registry", "Path to GitOps registry folder")
	secretSyncCmd.Flags().StringVarP(&nsFilter, "namespace", "n", "", "Filter specific namespace (optional)")
	secretSyncCmd.Flags().StringVar(&kubeconfigPath, "kubeconfig", "", "Path to kubeconfig file (defaults to ~/.kube/config)")
	secretSyncCmd.Flags().StringVar(&kubeContext, "context", "", "Kubernetes context to use")
	secretSyncCmd.Flags().StringVar(&k8sVaultServer, "vault-server", "http://vault.external-secrets.svc:8200", "Vault server endpoint reachable within the K8s cluster")
	secretSyncCmd.Flags().BoolVar(&syncDryRun, "dry-run", false, "Output rendered manifests to stdout without applying to Kubernetes")

	_ = secretSyncCmd.MarkFlagRequired("cluster")

	secretUnmatchedCmd.Flags().StringVarP(&clusterName, "cluster", "c", "", "Target Kubernetes cluster name (required)")
	secretUnmatchedCmd.Flags().StringVarP(&registryPath, "registry", "r", "./registry", "Path to GitOps registry folder")
	secretUnmatchedCmd.Flags().StringVarP(&nsFilter, "namespace", "n", "", "Filter specific namespace (optional)")
	secretUnmatchedCmd.Flags().StringVar(&kubeconfigPath, "kubeconfig", "", "Path to kubeconfig file (defaults to ~/.kube/config)")
	secretUnmatchedCmd.Flags().StringVar(&kubeContext, "context", "", "Kubernetes context to use")
	secretUnmatchedCmd.Flags().BoolVar(&cleanupUnmatched, "cleanup", false, "Purge unmatched secrets permanently")
	secretUnmatchedCmd.Flags().StringVar(&cleanupTarget, "target", "all", "Cleanup target: 'all', 'k8s', or 'vault'")
	secretUnmatchedCmd.Flags().BoolVar(&unmatchedDryRun, "dry-run", false, "Simulate purge without deleting secrets")

	_ = secretUnmatchedCmd.MarkFlagRequired("cluster")

	secretCmd.AddCommand(secretSyncCmd)
	secretCmd.AddCommand(secretUnmatchedCmd)
	RootCmd.AddCommand(secretCmd)
}

func runSecretSync(cmd *cobra.Command, args []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	fmt.Printf("📦 Loading registry for cluster '%s' from %s...\n", clusterName, registryPath)
	configs, err := sync.LoadClusterConfigs(registryPath, clusterName, nsFilter)
	if err != nil {
		return fmt.Errorf("failed to load cluster configs: %w", err)
	}

	if len(configs) == 0 {
		fmt.Printf("ℹ️  No namespace configurations found for cluster '%s'.\n", clusterName)
		return nil
	}

	fmt.Printf("   Found %d namespace configuration(s):\n", len(configs))
	for _, cfg := range configs {
		fmt.Printf("   ├─ Namespace: %-15s (ES: %d, TLS: %d, Registry: %d, CSI: %d)\n",
			cfg.Namespace, len(cfg.Secrets.ES), len(cfg.Secrets.TLS), len(cfg.Secrets.Registry), len(cfg.Secrets.CSI))
	}
	fmt.Println()

	var applier *sync.Applier
	if !syncDryRun {
		fmt.Print("⏳ Connecting to Kubernetes cluster... ")
		k8sClient, err := k8s.NewClient(kubeconfigPath, kubeContext)
		if err != nil {
			return fmt.Errorf("failed to connect to kubernetes: %w", err)
		}
		applier = sync.NewApplier(k8sClient.DynamicClient)
		fmt.Println("✅ Connected")
	}

	for _, cfg := range configs {
		fmt.Printf("\n⚙️  Processing namespace: %s\n", cfg.Namespace)

		manifests, err := sync.RenderAllForNamespace(cfg, k8sVaultServer)
		if err != nil {
			return fmt.Errorf("failed to render manifests for namespace %s: %w", cfg.Namespace, err)
		}

		for _, m := range manifests {
			if syncDryRun {
				yamlStr, err := sync.ToYAML(m)
				if err != nil {
					return err
				}
				fmt.Printf("---\n# Resource: %s/%s\n%s\n", m.GetKind(), m.GetName(), yamlStr)
			} else {
				action, err := applier.ApplyObject(ctx, m)
				if err != nil {
					return fmt.Errorf("failed to apply %s/%s: %w", m.GetKind(), m.GetName(), err)
				}
				switch action {
				case sync.ActionCreated:
					fmt.Println("✨ Created")
				case sync.ActionUpdated:
					fmt.Println("🔄 Updated")
				case sync.ActionUnchanged:
					fmt.Println("⏭️  Unchanged (Skipped)")
				}
			}
		}
	}

	if syncDryRun {
		fmt.Println("\n🔍 [DRY RUN] All manifests rendered successfully.")
	} else {
		fmt.Printf("\n🎉 All secrets successfully synced for cluster '%s'!\n", clusterName)
	}

	return nil
}

func runSecretUnmatched(cmd *cobra.Command, args []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	fmt.Printf("🔍 Scanning for unmatched secrets in cluster '%s'...\n", clusterName)

	var dynamicClient dynamic.Interface
	k8sClient, err := k8s.NewClient(kubeconfigPath, kubeContext)
	if err != nil {
		fmt.Printf("⚠️  Warning: Failed to connect to Kubernetes (%v). Skipping K8s inspection.\n", err)
	} else {
		dynamicClient = k8sClient.DynamicClient
	}

	var vaultClient *vault.Client
	if vaultAddr != "" {
		vaultClient, err = vault.NewClient(vaultAddr, vaultToken)
		if err != nil {
			fmt.Printf("⚠️  Warning: Failed to connect to Vault (%v). Skipping Vault inspection.\n", err)
		}
	} else {
		fmt.Println("⚠️  Warning: VAULT_ADDR not specified. Skipping Vault inspection.")
	}

	report, err := sync.DetectClusterUnmatchedSecrets(ctx, registryPath, clusterName, nsFilter, vaultClient, dynamicClient)
	if err != nil {
		return fmt.Errorf("failed to detect unmatched secrets: %w", err)
	}

	if report.TotalVaultUnmatched == 0 && report.TotalK8sUnmatched == 0 {
		fmt.Println("✅ All secrets are synchronized and match GitOps declarations. No orphaned secrets found.")
		return nil
	}

	fmt.Printf("\n⚠️  Found %d unmatched secret(s) across %d namespace(s):\n",
		report.TotalVaultUnmatched+report.TotalK8sUnmatched, len(report.Reports))
	fmt.Printf("   ├─ Vault KV-v2 unmatched:       %d\n", report.TotalVaultUnmatched)
	fmt.Printf("   └─ Kubernetes ExternalSecrets: %d\n\n", report.TotalK8sUnmatched)

	for _, nsReport := range report.Reports {
		fmt.Printf("📂 Namespace: %s\n", nsReport.Namespace)
		if len(nsReport.VaultUnmatched) > 0 {
			fmt.Printf("   ├─ Vault Mount: %s\n", nsReport.VaultMount)
			for _, k := range nsReport.VaultUnmatched {
				fmt.Printf("   │  ├─ ❌ Orphaned Vault key: %s/%s/%s\n", nsReport.VaultMount, nsReport.Namespace, k)
			}
		}
		if len(nsReport.K8sUnmatched) > 0 {
			for _, k := range nsReport.K8sUnmatched {
				fmt.Printf("   │  ├─ ❌ Orphaned ExternalSecret: %s/%s\n", nsReport.Namespace, k)
			}
		}
	}
	fmt.Println()

	if !cleanupUnmatched {
		fmt.Println("ℹ️  To purge these unmatched secrets, rerun with: --cleanup [--target all|k8s|vault] [--dry-run]")
		return nil
	}

	if unmatchedDryRun {
		fmt.Println("🔍 [DRY RUN] Simulating purge of unmatched secrets...")
	} else {
		fmt.Printf("🗑️  Purging unmatched secrets (target: %s)...\n", cleanupTarget)
	}

	result, err := sync.PurgeClusterUnmatchedSecrets(ctx, report, vaultClient, dynamicClient, cleanupTarget, unmatchedDryRun)
	if err != nil {
		return fmt.Errorf("cleanup failed: %w", err)
	}

	if len(result.DeletedVaultSecrets) > 0 {
		fmt.Println("✨ Vault Secrets Purged (Metadata & Versions permanently destroyed):")
		for _, s := range result.DeletedVaultSecrets {
			fmt.Printf("   ├─ %s\n", s)
		}
	}
	if len(result.DeletedK8sSecrets) > 0 {
		fmt.Println("✨ Kubernetes ExternalSecrets Purged:")
		for _, s := range result.DeletedK8sSecrets {
			fmt.Printf("   ├─ %s\n", s)
		}
	}

	if unmatchedDryRun {
		fmt.Println("\n🔍 [DRY RUN] Simulation complete. No changes were made.")
	} else {
		fmt.Println("\n🎉 Unmatched secrets successfully purged!")
	}

	return nil
}
