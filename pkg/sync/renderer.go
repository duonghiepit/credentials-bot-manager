package sync

import (
	"fmt"
	"strings"

	"github.com/duonghiepit/credentials-bot-manager/pkg/model"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/yaml"
)

// GVR definitions for custom resources
var (
	SecretStoreGVR = schema.GroupVersionResource{
		Group:    "external-secrets.io",
		Version:  "v1beta1",
		Resource: "secretstores",
	}
	ExternalSecretGVR = schema.GroupVersionResource{
		Group:    "external-secrets.io",
		Version:  "v1beta1",
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
	obj.SetAPIVersion("external-secrets.io/v1beta1")
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

// RenderExternalSecret generates an ExternalSecret object for a specific secret and optional target K8s Secret type.
func RenderExternalSecret(namespace, secretName, secretType string) *unstructured.Unstructured {
	k8sSecretName := strings.ReplaceAll(secretName, "_", "-")

	obj := &unstructured.Unstructured{}
	obj.SetAPIVersion("external-secrets.io/v1beta1")
	obj.SetKind("ExternalSecret")
	obj.SetName(k8sSecretName)
	obj.SetNamespace(namespace)

	target := map[string]interface{}{
		"name":           k8sSecretName,
		"creationPolicy": "Owner",
	}
	if secretType != "" {
		target["template"] = map[string]interface{}{
			"type": secretType,
		}
	}

	spec := map[string]interface{}{
		"refreshInterval": "1h",
		"secretStoreRef": map[string]interface{}{
			"name": "vault-backend",
			"kind": "SecretStore",
		},
		"target": target,
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

// RenderAllForNamespace renders all manifests for a given NamespaceConfig.
func RenderAllForNamespace(cfg *model.NamespaceConfig, vaultServer string) ([]*unstructured.Unstructured, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	var manifests []*unstructured.Unstructured

	// Always render SecretStore
	manifests = append(manifests, RenderSecretStore(cfg.ClusterName, cfg.Namespace, vaultServer))

	// Render ExternalSecrets for standard Opaque ES secrets
	for _, sec := range cfg.Secrets.ES {
		manifests = append(manifests, RenderExternalSecret(cfg.Namespace, sec, ""))
	}

	// Render ExternalSecrets for TLS secrets (kubernetes.io/tls)
	for _, sec := range cfg.Secrets.TLS {
		manifests = append(manifests, RenderExternalSecret(cfg.Namespace, sec, "kubernetes.io/tls"))
	}

	// Render ExternalSecrets for Docker Registry secrets (kubernetes.io/dockerconfigjson)
	for _, sec := range cfg.Secrets.Registry {
		manifests = append(manifests, RenderExternalSecret(cfg.Namespace, sec, "kubernetes.io/dockerconfigjson"))
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
