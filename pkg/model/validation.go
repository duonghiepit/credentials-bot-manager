package model

import (
	"fmt"
	"regexp"
	"strings"
)

var (
	// dns1123LabelRegex enforces strict Kubernetes DNS-1123 label format (cluster names, namespaces).
	dns1123LabelRegex = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$`)

	// secretKeyRegex enforces safe Vault/K8s secret identifiers (no slashes, no path traversal).
	secretKeyRegex = regexp.MustCompile(`^[a-zA-Z0-9]([-_a-zA-Z0-9.]{0,126}[a-zA-Z0-9])?$`)
)

// ValidateIdentifier validates a cluster name or namespace name against DNS-1123 label rules.
func ValidateIdentifier(kind, val string) error {
	if val == "" {
		return fmt.Errorf("%s cannot be empty", kind)
	}
	if strings.Contains(val, "..") || strings.ContainsAny(val, `/\`) {
		return fmt.Errorf("invalid %s: path traversal or separator characters are forbidden", kind)
	}
	if !dns1123LabelRegex.MatchString(val) {
		return fmt.Errorf("invalid %s %q: must match DNS-1123 label format", kind, val)
	}
	return nil
}

// ValidateSecretName validates a secret name to prevent path traversal or injection in Vault/K8s paths.
func ValidateSecretName(name string) error {
	if name == "" {
		return fmt.Errorf("secret name cannot be empty")
	}
	if strings.Contains(name, "..") || strings.ContainsAny(name, `/\`) {
		return fmt.Errorf("invalid secret name %q: path traversal or slashes are forbidden", name)
	}
	if !secretKeyRegex.MatchString(name) {
		return fmt.Errorf("invalid secret name %q: contains illegal characters", name)
	}
	return nil
}

// Validate checks that NamespaceConfig has safe ClusterName, Namespace, and secret names.
func (c *NamespaceConfig) Validate() error {
	if err := ValidateIdentifier("cluster_name", c.ClusterName); err != nil {
		return err
	}
	if err := ValidateIdentifier("namespace", c.Namespace); err != nil {
		return err
	}
	return c.Secrets.Validate()
}

// Validate checks all secret names in SecretsConfig.
func (s *SecretsConfig) Validate() error {
	for _, sec := range s.ES {
		if err := ValidateSecretName(sec); err != nil {
			return err
		}
	}
	for _, sec := range s.TLS {
		if err := ValidateSecretName(sec); err != nil {
			return err
		}
	}
	for _, sec := range s.Registry {
		if err := ValidateSecretName(sec); err != nil {
			return err
		}
	}
	for _, sec := range s.CSI {
		if err := ValidateSecretName(sec); err != nil {
			return err
		}
	}
	return nil
}
