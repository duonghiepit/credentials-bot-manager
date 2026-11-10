package deployer

import (
	"strings"
	"testing"
)

func TestPatchImageTag(t *testing.T) {
	inputYAML := `# Application deployment configuration
image:
  repository: registry.citigo.net/kms/api
  tag: d-284c887b # Current active dev tag

imagePullSecrets:
  - name: kms-private-registry

deploys:
  - name: public
    replicasCount: 1
`

	patched, err := PatchImageTag([]byte(inputYAML), "infra-registry.devops.pro/kms/api", "m-99999999")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	result := string(patched)
	if !strings.Contains(result, "m-99999999") {
		t.Errorf("expected new tag m-99999999 in output, got:\n%s", result)
	}

	if !strings.Contains(result, "infra-registry.devops.pro/kms/api") {
		t.Errorf("expected updated repository in output, got:\n%s", result)
	}

	if !strings.Contains(result, "# Application deployment configuration") {
		t.Errorf("expected header comment to be preserved, got:\n%s", result)
	}

	if !strings.Contains(result, "# Current active dev tag") {
		t.Errorf("expected inline comment to be preserved, got:\n%s", result)
	}
}
