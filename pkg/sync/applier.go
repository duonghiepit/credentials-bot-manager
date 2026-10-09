package sync

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
)

// Applier handles applying unstructured Kubernetes resources to the cluster.
type Applier struct {
	client dynamic.Interface
}

// NewApplier creates a new Applier instance.
func NewApplier(client dynamic.Interface) *Applier {
	return &Applier{client: client}
}

// ApplyObject creates or updates an unstructured object in the cluster.
func (a *Applier) ApplyObject(ctx context.Context, obj *unstructured.Unstructured) error {
	gvr := getGVRForObject(obj)
	if gvr.Resource == "" {
		return fmt.Errorf("unknown GVR for object %s/%s", obj.GetKind(), obj.GetName())
	}

	namespace := obj.GetNamespace()
	name := obj.GetName()

	resClient := a.client.Resource(gvr).Namespace(namespace)

	existing, err := resClient.Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		if errors.IsNotFound(err) {
			_, err := resClient.Create(ctx, obj, metav1.CreateOptions{})
			if err != nil {
				return fmt.Errorf("failed to create %s/%s: %w", obj.GetKind(), name, err)
			}
			return nil
		}
		return fmt.Errorf("failed to get existing %s/%s: %w", obj.GetKind(), name, err)
	}

	// Update existing resource
	obj.SetResourceVersion(existing.GetResourceVersion())
	_, err = resClient.Update(ctx, obj, metav1.UpdateOptions{})
	if err != nil {
		return fmt.Errorf("failed to update %s/%s: %w", obj.GetKind(), name, err)
	}

	return nil
}

func getGVRForObject(obj *unstructured.Unstructured) schema.GroupVersionResource {
	switch obj.GetKind() {
	case "SecretStore":
		return SecretStoreGVR
	case "ExternalSecret":
		return ExternalSecretGVR
	case "SecretProviderClass":
		return SecretProviderClassGVR
	default:
		return schema.GroupVersionResource{}
	}
}
