package deployer

import (
	"bytes"
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

// PatchImageTag parses YAML content using yaml.Node AST to find and update
// image tags. Supports both:
// 1. Helm values format (KiotViet GitOps style):
//    image:
//      repository: ...
//      tag: ...
// 2. Standard Kubernetes Deployment/Pod manifest:
//    containers:
//      - name: app
//        image: repo:tag
// Strictly preserves comments, ordering, and indentation.
func PatchImageTag(content []byte, imageRepo, newTag string) ([]byte, error) {
	var root yaml.Node
	if err := yaml.Unmarshal(content, &root); err != nil {
		return nil, fmt.Errorf("failed to parse yaml AST: %w", err)
	}

	if len(root.Content) == 0 {
		return nil, fmt.Errorf("empty yaml document")
	}

	docNode := root.Content[0]
	if docNode.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("root of yaml must be a mapping")
	}

	patched := false

	// Try 1: Helm values format
	imageNode := findMapValue(docNode, "image")
	if imageNode != nil && imageNode.Kind == yaml.MappingNode {
		tagNode := findMapValue(imageNode, "tag")
		if tagNode != nil {
			tagNode.Value = newTag
			if imageRepo != "" {
				repoNode := findMapValue(imageNode, "repository")
				if repoNode != nil {
					repoNode.Value = imageRepo
				}
			}
			patched = true
		}
	}

	// Try 2: Standard Kubernetes container image scalar
	if !patched {
		patched = patchK8sContainerImage(docNode, imageRepo, newTag)
	}

	if !patched {
		return nil, fmt.Errorf("could not find image configuration in yaml (neither Helm 'image' mapping nor K8s container image scalar)")
	}

	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(&root); err != nil {
		return nil, fmt.Errorf("failed to encode patched yaml: %w", err)
	}

	return buf.Bytes(), nil
}

func patchK8sContainerImage(node *yaml.Node, imageRepo, newTag string) bool {
	if node == nil {
		return false
	}

	if node.Kind == yaml.MappingNode {
		for i := 0; i < len(node.Content); i += 2 {
			k := node.Content[i]
			v := node.Content[i+1]
			if k.Kind == yaml.ScalarNode && k.Value == "image" && v.Kind == yaml.ScalarNode {
				parts := strings.Split(v.Value, ":")
				repo := parts[0]
				if imageRepo != "" {
					repo = imageRepo
				}
				v.Value = fmt.Sprintf("%s:%s", repo, newTag)
				return true
			}
			if patchK8sContainerImage(v, imageRepo, newTag) {
				return true
			}
		}
	} else if node.Kind == yaml.SequenceNode {
		for _, item := range node.Content {
			if patchK8sContainerImage(item, imageRepo, newTag) {
				return true
			}
		}
	}

	return false
}

// findMapValue searches a yaml.MappingNode for a given string key and returns the corresponding value node.
func findMapValue(mapNode *yaml.Node, key string) *yaml.Node {
	if mapNode == nil || mapNode.Kind != yaml.MappingNode {
		return nil
	}

	for i := 0; i < len(mapNode.Content); i += 2 {
		k := mapNode.Content[i]
		if k.Kind == yaml.ScalarNode && strings.TrimSpace(k.Value) == key {
			if i+1 < len(mapNode.Content) {
				return mapNode.Content[i+1]
			}
		}
	}
	return nil
}
