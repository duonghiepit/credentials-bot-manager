package sync

import (
	"context"
	"testing"

	"github.com/duonghiepit/platform-controller/pkg/model"
)

func TestDetectUnmatchedSecrets_EmptyDeclared(t *testing.T) {
	ctx := context.Background()
	cfg := &model.NamespaceConfig{
		ClusterName: "dev-cluster",
		Namespace:   "test-ns",
		Secrets: model.SecretsConfig{
			ES:  []string{"app_config", "redis"},
			CSI: []string{"database"},
		},
	}

	report, err := DetectUnmatchedSecrets(ctx, "dev-cluster", cfg, nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if report.Namespace != "test-ns" {
		t.Errorf("expected namespace test-ns, got %s", report.Namespace)
	}
	if len(report.VaultUnmatched) != 0 {
		t.Errorf("expected 0 vault unmatched, got %d", len(report.VaultUnmatched))
	}
	if len(report.K8sUnmatched) != 0 {
		t.Errorf("expected 0 k8s unmatched, got %d", len(report.K8sUnmatched))
	}
}

func TestDetectConfigsUnmatchedSecrets_Aggregation(t *testing.T) {
	ctx := context.Background()
	configs := []*model.NamespaceConfig{
		{
			ClusterName: "dev-cluster",
			Namespace:   "ns-1",
			Secrets: model.SecretsConfig{
				ES: []string{"sec-1"},
			},
		},
		{
			ClusterName: "dev-cluster",
			Namespace:   "ns-2",
			Secrets: model.SecretsConfig{
				CSI: []string{"sec-2"},
			},
		},
	}

	report, err := DetectConfigsUnmatchedSecrets(ctx, "dev-cluster", configs, false, nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if report.ClusterName != "dev-cluster" {
		t.Errorf("expected dev-cluster, got %s", report.ClusterName)
	}
	if report.TotalVaultUnmatched != 0 || report.TotalK8sUnmatched != 0 {
		t.Errorf("expected 0 total unmatched without live clients, got vault=%d, k8s=%d",
			report.TotalVaultUnmatched, report.TotalK8sUnmatched)
	}
}

func TestPurgeClusterUnmatchedSecrets_DryRun(t *testing.T) {
	ctx := context.Background()
	report := &UnmatchedReport{
		ClusterName: "dev-cluster",
		Reports: []*NamespaceUnmatchedReport{
			{
				Namespace:      "ecommerce",
				VaultMount:     "kv2-dev-cluster",
				VaultUnmatched: []string{"old_vault_key"},
				K8sUnmatched:   []string{"old-es-crd"},
			},
		},
		TotalVaultUnmatched: 1,
		TotalK8sUnmatched:   1,
	}

	res, err := PurgeClusterUnmatchedSecrets(ctx, report, nil, nil, "all", true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !res.DryRun {
		t.Errorf("expected DryRun=true, got false")
	}
	if res.ClusterName != "dev-cluster" {
		t.Errorf("expected ClusterName=dev-cluster, got %s", res.ClusterName)
	}
}
