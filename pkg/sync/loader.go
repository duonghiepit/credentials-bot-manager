package sync

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/duonghiepit/credentials-bot-manager/pkg/model"
	"gopkg.in/yaml.v3"
)

// LoadClusterConfigs loads all namespace configs for a cluster from the registry path.
func LoadClusterConfigs(registryPath, clusterName, nsFilter string) ([]*model.NamespaceConfig, error) {
	if err := model.ValidateIdentifier("cluster_name", clusterName); err != nil {
		return nil, err
	}
	if nsFilter != "" {
		if err := model.ValidateIdentifier("namespace", nsFilter); err != nil {
			return nil, err
		}
	}

	cleanBase := filepath.Clean(registryPath)
	clusterDir := filepath.Clean(filepath.Join(cleanBase, "clusters", clusterName))
	if !strings.HasPrefix(clusterDir, cleanBase+string(filepath.Separator)) {
		return nil, fmt.Errorf("invalid cluster path: path traversal detected")
	}

	if _, err := os.Stat(clusterDir); err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to stat cluster directory: %w", err)
	}

	files, err := os.ReadDir(clusterDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read cluster directory: %w", err)
	}

	var configs []*model.NamespaceConfig
	for _, f := range files {
		if f.IsDir() {
			continue
		}
		ext := filepath.Ext(f.Name())
		if ext != ".yaml" && ext != ".yml" {
			continue
		}

		ns := strings.TrimSuffix(f.Name(), ext)
		if strings.HasPrefix(ns, "_") {
			continue
		}

		if nsFilter != "" && ns != nsFilter {
			continue
		}

		if err := model.ValidateIdentifier("namespace", ns); err != nil {
			return nil, err
		}

		filePath := filepath.Clean(filepath.Join(clusterDir, f.Name()))
		if !strings.HasPrefix(filePath, clusterDir+string(filepath.Separator)) {
			return nil, fmt.Errorf("invalid file path: path traversal detected")
		}

		data, err := os.ReadFile(filePath)
		if err != nil {
			return nil, fmt.Errorf("failed to read file: %w", err)
		}

		var cfg model.NamespaceConfig
		if err := yaml.Unmarshal(data, &cfg); err != nil {
			return nil, fmt.Errorf("failed to parse yaml: %w", err)
		}

		cfg.ClusterName = clusterName
		cfg.Namespace = ns

		if err := cfg.Validate(); err != nil {
			return nil, err
		}

		configs = append(configs, &cfg)
	}

	return configs, nil
}
