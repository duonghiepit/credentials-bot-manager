package cmd

import (
	"context"
	"fmt"
	"time"

	"github.com/duonghiepit/platform-controller/pkg/k8s"
	"github.com/duonghiepit/platform-controller/pkg/sync"
	"github.com/spf13/cobra"
)

var (
	registryPath    string
	nsFilter        string
	k8sVaultServer  string
	syncDryRun      bool
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

func init() {
	secretSyncCmd.Flags().StringVarP(&clusterName, "cluster", "c", "", "Target Kubernetes cluster name (required)")
	secretSyncCmd.Flags().StringVarP(&registryPath, "registry", "r", "./registry", "Path to GitOps registry folder")
	secretSyncCmd.Flags().StringVarP(&nsFilter, "namespace", "n", "", "Filter specific namespace (optional)")
	secretSyncCmd.Flags().StringVar(&kubeconfigPath, "kubeconfig", "", "Path to kubeconfig file (defaults to ~/.kube/config)")
	secretSyncCmd.Flags().StringVar(&kubeContext, "context", "", "Kubernetes context to use")
	secretSyncCmd.Flags().StringVar(&k8sVaultServer, "vault-server", "http://vault.external-secrets.svc:8200", "Vault server endpoint reachable within the K8s cluster")
	secretSyncCmd.Flags().BoolVar(&syncDryRun, "dry-run", false, "Output rendered manifests to stdout without applying to Kubernetes")

	_ = secretSyncCmd.MarkFlagRequired("cluster")

	secretCmd.AddCommand(secretSyncCmd)
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
		fmt.Printf("   ├─ Namespace: %-15s (ES secrets: %d, CSI secrets: %d)\n",
			cfg.Namespace, len(cfg.Secrets.ES), len(cfg.Secrets.CSI))
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
