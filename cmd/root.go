package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var (
	vaultAddr  string
	vaultToken string
	verbose    bool
)

// RootCmd represents the base command when called without any subcommands.
var RootCmd = &cobra.Command{
	Use:   "platform-controller",
	Short: "Platform Controller — Cloud-Native Multi-Cluster & Secret Orchestrator",
	Long: `Platform Controller is a lightweight, high-performance platform orchestrator.
It automates Kubernetes multi-cluster authentication handshakes with HashiCorp Vault
and synchronizes External Secrets (ES) and Secrets Store CSI Driver (CSI) configurations.`,
}

func Execute() {
	if err := RootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func init() {
	RootCmd.PersistentFlags().StringVar(&vaultAddr, "vault-addr", os.Getenv("VAULT_ADDR"), "HashiCorp Vault endpoint (or env VAULT_ADDR)")
	RootCmd.PersistentFlags().StringVar(&vaultToken, "vault-token", os.Getenv("VAULT_TOKEN"), "HashiCorp Vault token (or env VAULT_TOKEN)")
	RootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Enable verbose logging")
}
