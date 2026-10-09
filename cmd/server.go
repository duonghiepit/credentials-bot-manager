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
	serverPort         int
	serverRegistry     string
	serverCluster      string
	serverSyncInterval time.Duration
	serverVaultServer  string
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
Optionally runs a continuous secret reconciliation loop.`,
	RunE: runServer,
}

func init() {
	serverCmd.Flags().IntVarP(&serverPort, "port", "p", 8080, "HTTP server listening port")
	serverCmd.Flags().StringVarP(&serverRegistry, "registry", "r", "/etc/platform-controller/registry", "Path to GitOps registry folder")
	serverCmd.Flags().StringVarP(&serverCluster, "cluster", "c", "", "Cluster name for auto-reconciliation loop")
	serverCmd.Flags().DurationVar(&serverSyncInterval, "sync-interval", 0, "Periodic secret sync interval (e.g. 5m). 0 disables auto-sync")
	serverCmd.Flags().StringVar(&serverVaultServer, "vault-server", "http://vault.external-secrets.svc:8200", "Vault server endpoint reachable within K8s")

	RootCmd.AddCommand(serverCmd)
}

func runServer(cmd *cobra.Command, args []string) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	cfg := server.Config{
		Port:         serverPort,
		RegistryPath: serverRegistry,
		VaultAddr:    vaultAddr,
		VaultToken:   vaultToken,
		SyncInterval: serverSyncInterval,
		ClusterName:  serverCluster,
		VaultServer:  serverVaultServer,
	}

	srv, err := server.NewServer(cfg)
	if err != nil {
		return err
	}

	return srv.Start(ctx)
}
