package sync

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/util/retry"
)

// Applier handles applying unstructured Kubernetes resources to the cluster.
type Applier struct {
	client dynamic.Interface
}

// NewApplier creates a new Applier instance.
func NewApplier(client dynamic.Interface) *Applier {
	return &Applier{client: client}
}

// ApplyObject creates or updates an unstructured object in the cluster with automatic retry on conflict.
func (a *Applier) ApplyObject(ctx context.Context, obj *unstructured.Unstructured) error {
	gvr := getGVRForObject(obj)
	if gvr.Resource == "" {
		return fmt.Errorf("unknown GVR for object %s/%s", obj.GetKind(), obj.GetName())
	}

	namespace := obj.GetNamespace()
	name := obj.GetName()

	resClient := a.client.Resource(gvr).Namespace(namespace)

	return retry.RetryOnConflict(retry.DefaultBackoff, func() error {
		existing, err := resClient.Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			if errors.IsNotFound(err) {
				_, createErr := resClient.Create(ctx, obj, metav1.CreateOptions{})
				if createErr != nil {
					return fmt.Errorf("failed to create %s/%s: %w", obj.GetKind(), name, createErr)
				}
				return nil
			}
			return fmt.Errorf("failed to get existing %s/%s: %w", obj.GetKind(), name, err)
		}

		// Update existing resource with latest resourceVersion
		toUpdate := obj.DeepCopy()
		toUpdate.SetResourceVersion(existing.GetResourceVersion())
		_, err = resClient.Update(ctx, toUpdate, metav1.UpdateOptions{})
		if err != nil {
			return err // Triggers retry if conflict (409)
		}

		return nil
	})
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
