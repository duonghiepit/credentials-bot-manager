package cmd

import (
	"context"
	"fmt"
	"time"

	"github.com/duonghiepit/credentials-bot-manager/pkg/k8s"
	"github.com/duonghiepit/credentials-bot-manager/pkg/vault"
	"github.com/spf13/cobra"
)

var (
	clusterName     string
	kubeconfigPath  string
	kubeContext     string
	k8sNamespace    string
	vaultMountPath  string
	k8sHostOverride string
	dryRun          bool
)

var clusterCmd = &cobra.Command{
	Use:   "cluster",
	Short: "Manage Kubernetes cluster registrations and auth handshakes",
}

var clusterJoinCmd = &cobra.Command{
	Use:   "join",
	Short: "Join a Kubernetes satellite cluster to HashiCorp Vault (Zero Secrets in Git)",
	Long: `Performs a zero-secret runtime authentication handshake:
1. Connects to the satellite cluster using kubeconfig.
2. Bootstraps the TokenReviewer ServiceAccount, ClusterRoleBinding, and Token Secret.
3. Extracts the Reviewer JWT and CA certificate directly in memory.
4. Directly invokes HashiCorp Vault API (POST /v1/auth/<cluster>-kubernetes/config)
   without ever writing tokens, CA certificates, or cluster endpoints to Git.`,
	RunE: runClusterJoin,
}

func init() {
	clusterJoinCmd.Flags().StringVarP(&clusterName, "cluster", "c", "", "Target Kubernetes cluster name (required)")
	clusterJoinCmd.Flags().StringVar(&kubeconfigPath, "kubeconfig", "", "Path to kubeconfig file (defaults to ~/.kube/config)")
	clusterJoinCmd.Flags().StringVar(&kubeContext, "context", "", "Kubernetes context to use")
	clusterJoinCmd.Flags().StringVarP(&k8sNamespace, "namespace", "n", "external-secrets", "Namespace for TokenReviewer ServiceAccount")
	clusterJoinCmd.Flags().StringVar(&vaultMountPath, "vault-mount", "", "Vault Kubernetes auth mount path (defaults to <cluster>-kubernetes)")
	clusterJoinCmd.Flags().StringVar(&k8sHostOverride, "k8s-host", "", "Kubernetes API host reachable by Vault (overrides kubeconfig cluster.server)")
	clusterJoinCmd.Flags().BoolVar(&dryRun, "dry-run", false, "Preview actions without configuring Vault")

	_ = clusterJoinCmd.MarkFlagRequired("cluster")

	clusterCmd.AddCommand(clusterJoinCmd)
	RootCmd.AddCommand(clusterCmd)
}

func runClusterJoin(cmd *cobra.Command, args []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	if vaultAddr == "" {
		vaultAddr = "http://127.0.0.1:8200"
	}
	if vaultToken == "" {
		return fmt.Errorf("vault token is required (specify --vault-token or set VAULT_TOKEN)")
	}

	if vaultMountPath == "" {
		vaultMountPath = fmt.Sprintf("%s-kubernetes", clusterName)
	}

	fmt.Printf("🚀 Starting Zero-Secret Handshake for cluster: %s\n", clusterName)
	fmt.Printf("   ├─ Kube Context:  %s\n", kubeContext)
	fmt.Printf("   ├─ Reviewer NS:   %s\n", k8sNamespace)
	fmt.Printf("   └─ Vault Mount:   auth/%s\n\n", vaultMountPath)

	// 1. Connect to Kubernetes
	fmt.Print("⏳ [1/4] Connecting to satellite Kubernetes cluster... ")
	k8sClient, err := k8s.NewClient(kubeconfigPath, kubeContext)
	if err != nil {
		return fmt.Errorf("failed to connect to kubernetes: %w", err)
	}
	fmt.Println("✅ Connected")

	// Determine Kubernetes Host
	k8sHost := k8sClient.Host
	if k8sHostOverride != "" {
		k8sHost = k8sHostOverride
	}
	fmt.Printf("   └─ Target K8s API Host: %s\n", k8sHost)

	// 2. Bootstrap TokenReviewer
	fmt.Print("⏳ [2/4] Ensuring TokenReviewer RBAC and token secret... ")
	creds, err := k8sClient.EnsureTokenReviewer(ctx, k8sNamespace)
	if err != nil {
		return fmt.Errorf("failed to bootstrap token reviewer: %w", err)
	}
	fmt.Printf("✅ OK (Token length: %d bytes, CA cert: %d bytes)\n", len(creds.Token), len(creds.CACert))

	if dryRun {
		fmt.Println("\n🔍 [DRY RUN] Would configure Vault Auth endpoint:")
		fmt.Printf("   Endpoint: %s/v1/auth/%s/config\n", vaultAddr, vaultMountPath)
		fmt.Printf("   Host:     %s\n", k8sHost)
		fmt.Println("   Token and CA cert extracted successfully.")
		return nil
	}

	// 3. Connect to Vault
	fmt.Print("⏳ [3/4] Connecting to HashiCorp Vault... ")
	vaultClient, err := vault.NewClient(vaultAddr, vaultToken)
	if err != nil {
		return fmt.Errorf("failed to initialize vault client: %w", err)
	}
	if err := vaultClient.VerifyHealth(ctx); err != nil {
		return fmt.Errorf("vault health check failed: %w", err)
	}
	fmt.Println("✅ Connected & Healthy")

	// 4. Configure K8s Auth Backend
	fmt.Printf("⏳ [4/4] Writing K8s Auth config to auth/%s/config... ", vaultMountPath)
	payload := vault.K8sAuthConfigPayload{
		KubernetesHost:       k8sHost,
		KubernetesCACert:     creds.CACert,
		TokenReviewerJWT:     creds.Token,
		DisableLocalCAJWT:    true,
		DisableISSValidation: true,
	}

	if err := vaultClient.ConfigureKubernetesAuth(ctx, vaultMountPath, payload); err != nil {
		return fmt.Errorf("failed to configure vault kubernetes auth: %w", err)
	}
	fmt.Println("✅ Success!")

	fmt.Printf("\n🎉 Cluster '%s' successfully joined HashiCorp Vault with Least Privilege!\n", clusterName)
	fmt.Println("   Zero secrets were written to Git or disk.")
	return nil
}
