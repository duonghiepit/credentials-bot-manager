package sync

import (
	"fmt"
	"strings"

	"github.com/duonghiepit/platform-controller/pkg/model"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/yaml"
)

// GVR definitions for custom resources
var (
	SecretStoreGVR = schema.GroupVersionResource{
		Group:    "external-secrets.io",
		Version:  "v1",
		Resource: "secretstores",
	}
	ExternalSecretGVR = schema.GroupVersionResource{
		Group:    "external-secrets.io",
		Version:  "v1",
		Resource: "externalsecrets",
	}
	SecretProviderClassGVR = schema.GroupVersionResource{
		Group:    "secrets-store.csi.x-k8s.io",
		Version:  "v1",
		Resource: "secretproviderclasses",
	}
)

// RenderSecretStore generates a namespaced SecretStore object.
func RenderSecretStore(clusterName, namespace, vaultServer string) *unstructured.Unstructured {
	obj := &unstructured.Unstructured{}
	obj.SetAPIVersion("external-secrets.io/v1")
	obj.SetKind("SecretStore")
	obj.SetName("vault-backend")
	obj.SetNamespace(namespace)

	spec := map[string]interface{}{
		"provider": map[string]interface{}{
			"vault": map[string]interface{}{
				"server":  vaultServer,
				"path":    fmt.Sprintf("kv2-%s", clusterName),
				"version": "v2",
				"auth": map[string]interface{}{
					"kubernetes": map[string]interface{}{
						"mountPath": fmt.Sprintf("%s-kubernetes", clusterName),
						"role":      fmt.Sprintf("r-%s-%s", clusterName, namespace),
						"serviceAccountRef": map[string]interface{}{
							"name": "default",
						},
					},
				},
			},
		},
	}
	obj.Object["spec"] = spec
	return obj
}

// RenderExternalSecret generates an ExternalSecret object for a specific secret.
func RenderExternalSecret(namespace, secretName string) *unstructured.Unstructured {
	k8sSecretName := strings.ReplaceAll(secretName, "_", "-")

	obj := &unstructured.Unstructured{}
	obj.SetAPIVersion("external-secrets.io/v1")
	obj.SetKind("ExternalSecret")
	obj.SetName(k8sSecretName)
	obj.SetNamespace(namespace)

	spec := map[string]interface{}{
		"refreshInterval": "1h",
		"secretStoreRef": map[string]interface{}{
			"name": "vault-backend",
			"kind": "SecretStore",
		},
		"target": map[string]interface{}{
			"name":           k8sSecretName,
			"creationPolicy": "Owner",
		},
		"dataFrom": []interface{}{
			map[string]interface{}{
				"extract": map[string]interface{}{
					"key": fmt.Sprintf("%s/%s", namespace, secretName),
				},
			},
		},
	}
	obj.Object["spec"] = spec
	return obj
}

// RenderSecretProviderClass generates a SecretProviderClass object for CSI secrets.
func RenderSecretProviderClass(clusterName, namespace, vaultServer string, secrets []string) *unstructured.Unstructured {
	spcName := fmt.Sprintf("vault-%s-csi", namespace)

	var objectsYaml strings.Builder
	for _, sec := range secrets {
		objectsYaml.WriteString(fmt.Sprintf("  - objectName: \"%s\"\n", sec))
		objectsYaml.WriteString(fmt.Sprintf("    secretPath: \"kv2-%s/data/%s/%s\"\n", clusterName, namespace, sec))
	}

	obj := &unstructured.Unstructured{}
	obj.SetAPIVersion("secrets-store.csi.x-k8s.io/v1")
	obj.SetKind("SecretProviderClass")
	obj.SetName(spcName)
	obj.SetNamespace(namespace)

	spec := map[string]interface{}{
		"provider": "vault",
		"parameters": map[string]interface{}{
			"vaultAddress":             vaultServer,
			"vaultKubernetesMountPath": fmt.Sprintf("%s-kubernetes", clusterName),
			"roleName":                 fmt.Sprintf("r-%s-%s", clusterName, namespace),
			"objects":                  objectsYaml.String(),
		},
	}
	obj.Object["spec"] = spec
	return obj
}

// RenderAllForNamespace renders all manifests for a given NamespaceConfig.
func RenderAllForNamespace(cfg *model.NamespaceConfig, vaultServer string) ([]*unstructured.Unstructured, error) {
	var manifests []*unstructured.Unstructured

	// Always render SecretStore
	manifests = append(manifests, RenderSecretStore(cfg.ClusterName, cfg.Namespace, vaultServer))

	// Render ExternalSecrets for each ES secret
	for _, sec := range cfg.Secrets.ES {
		manifests = append(manifests, RenderExternalSecret(cfg.Namespace, sec))
	}

	// Render SecretProviderClass if CSI secrets are present
	if len(cfg.Secrets.CSI) > 0 {
		manifests = append(manifests, RenderSecretProviderClass(cfg.ClusterName, cfg.Namespace, vaultServer, cfg.Secrets.CSI))
	}

	return manifests, nil
}

// ToYAML converts an Unstructured object to YAML string.
func ToYAML(obj *unstructured.Unstructured) (string, error) {
	bytes, err := yaml.Marshal(obj.Object)
	if err != nil {
		return "", err
	}
	return string(bytes), nil
}
