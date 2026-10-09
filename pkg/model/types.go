package model

import (
	"encoding/json"
	"fmt"
	"gopkg.in/yaml.v3"
)

// SecretsConfig encapsulates secret definitions separated by consumption driver.
type SecretsConfig struct {
	ES  []string `yaml:"es" json:"es"`
	CSI []string `yaml:"csi" json:"csi"`
}

// UnmarshalYAML implements custom unmarshaling to support both:
// 1. Map format: secrets: { es: [...], csi: [...] }
// 2. Legacy flat list: secrets: [...] (automatically classified as ES)
func (s *SecretsConfig) UnmarshalYAML(value *yaml.Node) error {
	switch value.Kind {
	case yaml.SequenceNode:
		// Flat list: treat all items as External Secrets (ES)
		var list []string
		if err := value.Decode(&list); err != nil {
			return err
		}
		s.ES = list
		s.CSI = nil
		return nil

	case yaml.MappingNode:
		// Map format with "es" and "csi"
		type alias SecretsConfig
		var aux alias
		if err := value.Decode(&aux); err != nil {
			return err
		}
		s.ES = aux.ES
		s.CSI = aux.CSI
		return nil

	default:
		return fmt.Errorf("unexpected yaml node kind for secrets: %v", value.Kind)
	}
}

// UnmarshalJSON implements custom JSON unmarshaling to support both:
// 1. Map format: {"es": [...], "csi": [...]}
// 2. Flat list: [...] (automatically classified as ES)
func (s *SecretsConfig) UnmarshalJSON(data []byte) error {
	var list []string
	if err := json.Unmarshal(data, &list); err == nil {
		s.ES = list
		s.CSI = nil
		return nil
	}

	type alias SecretsConfig
	var aux alias
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	s.ES = aux.ES
	s.CSI = aux.CSI
	return nil
}

// AllSecrets returns a consolidated list of all secret names.
func (s *SecretsConfig) AllSecrets() []string {
	var all []string
	all = append(all, s.ES...)
	all = append(all, s.CSI...)
	return all
}

// NamespaceConfig represents a single namespace/service YAML file in the registry.
type NamespaceConfig struct {
	ClusterName string        `yaml:"-" json:"cluster_name"`
	Namespace   string        `yaml:"-" json:"namespace"`
	Editors     []string      `yaml:"editors,omitempty" json:"editors,omitempty"`
	Viewers     []string      `yaml:"viewers,omitempty" json:"viewers,omitempty"`
	Secrets     SecretsConfig `yaml:"secrets" json:"secrets"`
}

// ClusterJoinConfig holds parameters required to handshake a satellite cluster with Vault.
type ClusterJoinConfig struct {
	ClusterName       string
	KubeconfigPath    string
	KubeContext       string
	Namespace         string
	VaultAddress      string
	VaultToken        string
	VaultMountPath    string
	K8sHostOverride   string
	DryRun            bool
}

// SecretSyncConfig holds parameters required to synchronize secrets into a cluster.
type SecretSyncConfig struct {
	RegistryPath   string
	ClusterName    string
	NamespaceFilter string
	KubeconfigPath string
	KubeContext    string
	VaultServer    string
	DryRun         bool
}
