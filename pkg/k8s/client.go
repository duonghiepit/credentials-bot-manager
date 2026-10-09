package k8s

import (
	"fmt"
	"os"
	"path/filepath"

	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
)

// Client wraps Kubernetes typed and dynamic clients.
type Client struct {
	Clientset     kubernetes.Interface
	DynamicClient dynamic.Interface
	RestConfig    *rest.Config
	RawConfig     clientcmdapi.Config
	Host          string
}

// NewClient builds a Kubernetes client from kubeconfig and an optional context name.
func NewClient(kubeconfigPath, contextName string) (*Client, error) {
	if kubeconfigPath == "" {
		home, err := os.UserHomeDir()
		if err == nil {
			defaultPath := filepath.Join(home, ".kube", "config")
			if _, err := os.Stat(defaultPath); err == nil {
				kubeconfigPath = defaultPath
			}
		}
	}

	var restConfig *rest.Config
	var rawConfig clientcmdapi.Config
	var err error

	if kubeconfigPath != "" {
		loadingRules := &clientcmd.ClientConfigLoadingRules{ExplicitPath: kubeconfigPath}
		configOverrides := &clientcmd.ConfigOverrides{}
		if contextName != "" {
			configOverrides.CurrentContext = contextName
		}

		clientConfig := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loadingRules, configOverrides)
		restConfig, err = clientConfig.ClientConfig()
		if err != nil {
			return nil, fmt.Errorf("failed to load kubeconfig from %s: %w", kubeconfigPath, err)
		}
		rawConfig, err = clientConfig.RawConfig()
		if err != nil {
			return nil, fmt.Errorf("failed to get raw config: %w", err)
		}
	} else {
		// Fallback to in-cluster config
		restConfig, err = rest.InClusterConfig()
		if err != nil {
			return nil, fmt.Errorf("no kubeconfig provided and not in-cluster: %w", err)
		}
	}

	clientset, err := kubernetes.NewForConfig(restConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create kubernetes clientset: %w", err)
	}

	dynamicClient, err := dynamic.NewForConfig(restConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create kubernetes dynamic client: %w", err)
	}

	return &Client{
		Clientset:     clientset,
		DynamicClient: dynamicClient,
		RestConfig:    restConfig,
		RawConfig:     rawConfig,
		Host:          restConfig.Host,
	}, nil
}
