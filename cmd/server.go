package cmd

import (
	"context"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/duonghiepit/platform-controller/pkg/server"
	"github.com/spf13/cobra"
)

var (
	serverPort          int
	serverRegistry      string
	serverCluster       string
	serverSyncInterval  time.Duration
	serverVaultServer   string
	serverAuthNamespace string
	serverGitLabURL     string
	serverGitLabToken   string
	serverClustersDir   string
	serverDefaultBranch string
	serverArgoCDURL     string
	serverArgoCDToken   string
)

var serverCmd = &cobra.Command{
	Use:   "server",
	Short: "Run the HTTP API daemon and background reconciler",
	Long: `Starts the platform-controller as an HTTP REST daemon inside Kubernetes.
Provides REST endpoints:
- GET  /healthz
- GET  /readyz
- POST /api/v1/cluster/join
- POST /api/v1/secret/sync
- GET/DELETE /api/v1/secret/unmatched
- POST /api/v1/auth/rotate-token
- POST /api/v1/deploy (alias /configsManager/deployContainerImages)
- POST /api/v1/deploy/status (alias /configsManager/reloadDeployStatus)
Optionally runs a continuous secret reconciliation loop.`,
	RunE: runServer,
}

func init() {
	serverCmd.Flags().IntVarP(&serverPort, "port", "p", 8080, "HTTP server listening port")
	serverCmd.Flags().StringVarP(&serverRegistry, "registry", "r", "/etc/platform-controller/registry", "Path to GitOps registry folder")
	serverCmd.Flags().StringVarP(&serverCluster, "cluster", "c", "", "Cluster name for auto-reconciliation loop")
	serverCmd.Flags().DurationVar(&serverSyncInterval, "sync-interval", 0, "Periodic secret sync interval (e.g. 5m). 0 disables auto-sync")
	serverCmd.Flags().StringVar(&serverVaultServer, "vault-server", "http://vault.external-secrets.svc:8200", "Vault server endpoint reachable within K8s")
	serverCmd.Flags().StringVar(&serverAuthNamespace, "auth-namespace", "platform-system", "Kubernetes namespace where auth token secret is persisted (ArgoCD style)")
	serverCmd.Flags().StringVar(&serverGitLabURL, "gitlab-url", "https://infra-gitlab.devops.pro", "GitLab API Base URL for GitOps commits")
	serverCmd.Flags().StringVar(&serverGitLabToken, "gitlab-token", "", "GitLab API Token for GitOps commits")
	serverCmd.Flags().StringVar(&serverClustersDir, "clusters-dir", "", "Path to local clusters directory for GitOps patches")
	serverCmd.Flags().StringVar(&serverDefaultBranch, "default-branch", "main", "Default Git branch for GitOps commits")
	serverCmd.Flags().StringVar(&serverArgoCDURL, "argocd-url", "", "ArgoCD API URL for app sync triggering")
	serverCmd.Flags().StringVar(&serverArgoCDToken, "argocd-token", "", "ArgoCD API Token for authentication")

	RootCmd.AddCommand(serverCmd)
}

func runServer(cmd *cobra.Command, args []string) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if serverGitLabToken == "" {
		serverGitLabToken = os.Getenv("GITLAB_TOKEN")
	}
	if serverArgoCDURL == "" {
		serverArgoCDURL = os.Getenv("ARGOCD_URL")
	}
	if serverArgoCDToken == "" {
		serverArgoCDToken = os.Getenv("ARGOCD_TOKEN")
	}

	cfg := server.Config{
		Port:          serverPort,
		RegistryPath:  serverRegistry,
		VaultAddr:     vaultAddr,
		VaultToken:    vaultToken,
		SyncInterval:  serverSyncInterval,
		ClusterName:   serverCluster,
		VaultServer:   serverVaultServer,
		AuthNamespace: serverAuthNamespace,
		GitLabURL:     serverGitLabURL,
		GitLabToken:   serverGitLabToken,
		ClustersDir:   serverClustersDir,
		DefaultBranch: serverDefaultBranch,
		ArgoCDURL:     serverArgoCDURL,
		ArgoCDToken:   serverArgoCDToken,
	}

	srv, err := server.NewServer(cfg)
	if err != nil {
		return err
	}

	return srv.Start(ctx)
}
