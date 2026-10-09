package cmd

import (
	"fmt"
	"os"

	"github.com/duonghiepit/platform-controller/pkg/logger"
	"github.com/spf13/cobra"
)

var (
	vaultAddr  string
	vaultToken string
	logFormat  string
	logLevel   string
	verbose    bool
)

// RootCmd represents the base command when called without any subcommands.
var RootCmd = &cobra.Command{
	Use:   "platform-controller",
	Short: "Platform Controller — Cloud-Native Multi-Cluster & Secret Orchestrator",
	Long: `Platform Controller is a lightweight, high-performance platform orchestrator.
It automates Kubernetes multi-cluster authentication handshakes with HashiCorp Vault
and synchronizes External Secrets (ES) and Secrets Store CSI Driver (CSI) configurations.`,
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		level := logLevel
		if verbose && level == "info" {
			level = "debug"
		}
		logger.Init(logFormat, level)
	},
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
	RootCmd.PersistentFlags().StringVar(&logFormat, "log-format", getEnvOrDefault("LOG_FORMAT", "json"), "Log format: json or text")
	RootCmd.PersistentFlags().StringVar(&logLevel, "log-level", getEnvOrDefault("LOG_LEVEL", "info"), "Log level: debug, info, warn, error")
	RootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Enable verbose debug logging")
}

func getEnvOrDefault(key, fallback string) string {
	if v, exists := os.LookupEnv(key); exists && v != "" {
		return v
	}
	return fallback
}
