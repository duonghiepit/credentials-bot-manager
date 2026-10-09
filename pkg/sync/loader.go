package sync

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/duonghiepit/platform-controller/pkg/model"
	"gopkg.in/yaml.v3"
)

// LoadClusterConfigs loads all namespace configs for a cluster from the registry path.
func LoadClusterConfigs(registryPath, clusterName, nsFilter string) ([]*model.NamespaceConfig, error) {
	clusterDir := filepath.Join(registryPath, "clusters", clusterName)
	if _, err := os.Stat(clusterDir); err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to stat cluster directory %s: %w", clusterDir, err)
	}

	files, err := os.ReadDir(clusterDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read cluster directory %s: %w", clusterDir, err)
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

		filePath := filepath.Join(clusterDir, f.Name())
		data, err := os.ReadFile(filePath)
		if err != nil {
			return nil, fmt.Errorf("failed to read file %s: %w", filePath, err)
		}

		var cfg model.NamespaceConfig
		if err := yaml.Unmarshal(data, &cfg); err != nil {
			return nil, fmt.Errorf("failed to parse yaml in %s: %w", filePath, err)
		}

		cfg.ClusterName = clusterName
		cfg.Namespace = ns

		configs = append(configs, &cfg)
	}

	return configs, nil
}
