package sync

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"reflect"

	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/util/retry"
)

// SpecHashAnnotation stores the desired spec hash to detect changes regardless of server-side defaulting.
const SpecHashAnnotation = "platform.io/spec-hash"

// ApplyAction represents the resulting action of ApplyObject.
type ApplyAction string

const (
	ActionCreated   ApplyAction = "created"
	ActionUpdated   ApplyAction = "updated"
	ActionUnchanged ApplyAction = "unchanged"
)

// Applier handles applying unstructured Kubernetes resources to the cluster.
type Applier struct {
	client dynamic.Interface
}

// NewApplier creates a new Applier instance.
func NewApplier(client dynamic.Interface) *Applier {
	return &Applier{client: client}
}

// computeSpecHash calculates a deterministic SHA-256 hash of the object's spec.
func computeSpecHash(obj *unstructured.Unstructured) string {
	spec, found, _ := unstructured.NestedMap(obj.Object, "spec")
	if !found {
		return ""
	}
	bytes, err := json.Marshal(spec)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(bytes)
	return hex.EncodeToString(sum[:16])
}

// ApplyObject creates or updates an unstructured object in the cluster with automatic retry on conflict and spec-diff detection.
func (a *Applier) ApplyObject(ctx context.Context, obj *unstructured.Unstructured) (ApplyAction, error) {
	gvr := getGVRForObject(obj)
	if gvr.Resource == "" {
		return "", fmt.Errorf("unknown GVR for object %s/%s", obj.GetKind(), obj.GetName())
	}

	namespace := obj.GetNamespace()
	name := obj.GetName()

	desiredHash := computeSpecHash(obj)
	if desiredHash != "" {
		annotations := obj.GetAnnotations()
		if annotations == nil {
			annotations = make(map[string]string)
		}
		annotations[SpecHashAnnotation] = desiredHash
		obj.SetAnnotations(annotations)
	}

	resClient := a.client.Resource(gvr).Namespace(namespace)

	existing, err := resClient.Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		if errors.IsNotFound(err) {
			_, createErr := resClient.Create(ctx, obj, metav1.CreateOptions{})
			if createErr != nil {
				if errors.IsNotFound(createErr) {
					// Namespace might not exist yet: auto-create and retry creation
					if nsErr := a.EnsureNamespace(ctx, namespace); nsErr == nil {
						_, retryCreateErr := resClient.Create(ctx, obj, metav1.CreateOptions{})
						if retryCreateErr == nil {
							return ActionCreated, nil
						}
					}
				}
				return "", fmt.Errorf("failed to create %s/%s: %w", obj.GetKind(), name, createErr)
			}
			return ActionCreated, nil
		}
		return "", fmt.Errorf("failed to get existing %s/%s: %w", obj.GetKind(), name, err)
	}

	// 1. Check spec hash first (immune to server-side webhook defaulting)
	existingHash := existing.GetAnnotations()[SpecHashAnnotation]
	if existingHash != "" && desiredHash != "" && existingHash == desiredHash {
		return ActionUnchanged, nil
	}

	// 2. Fallback to semantic deep equal
	existingSpec, hasExistingSpec, _ := unstructured.NestedMap(existing.Object, "spec")
	desiredSpec, hasDesiredSpec, _ := unstructured.NestedMap(obj.Object, "spec")

	if hasExistingSpec && hasDesiredSpec && reflect.DeepEqual(existingSpec, desiredSpec) {
		// Nothing changed in spec! Skip write to Kubernetes.
		return ActionUnchanged, nil
	}

	// Spec has changed: Update existing resource with automatic conflict retry
	action := ActionUpdated
	err = retry.RetryOnConflict(retry.DefaultBackoff, func() error {
		latest, getErr := resClient.Get(ctx, name, metav1.GetOptions{})
		if getErr != nil {
			return getErr
		}

		// Double check latest spec in retry loop in case a concurrent update already aligned it
		latestSpec, _, _ := unstructured.NestedMap(latest.Object, "spec")
		if reflect.DeepEqual(latestSpec, desiredSpec) {
			action = ActionUnchanged
			return nil
		}

		toUpdate := obj.DeepCopy()
		toUpdate.SetResourceVersion(latest.GetResourceVersion())
		_, updateErr := resClient.Update(ctx, toUpdate, metav1.UpdateOptions{})
		return updateErr
	})
	if err != nil {
		return "", fmt.Errorf("failed to update %s/%s: %w", obj.GetKind(), name, err)
	}

	return action, nil
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

// EnsureNamespace ensures that the target namespace exists in Kubernetes, creating it if missing.
func (a *Applier) EnsureNamespace(ctx context.Context, namespace string) error {
	if namespace == "" || namespace == "default" {
		return nil
	}
	nsGVR := schema.GroupVersionResource{Group: "", Version: "v1", Resource: "namespaces"}
	_, err := a.client.Resource(nsGVR).Get(ctx, namespace, metav1.GetOptions{})
	if err == nil {
		return nil
	}
	if errors.IsNotFound(err) {
		nsObj := &unstructured.Unstructured{}
		nsObj.SetAPIVersion("v1")
		nsObj.SetKind("Namespace")
		nsObj.SetName(namespace)
		_, createErr := a.client.Resource(nsGVR).Create(ctx, nsObj, metav1.CreateOptions{})
		if createErr != nil && !errors.IsAlreadyExists(createErr) {
			return fmt.Errorf("failed to auto-create namespace %s: %w", namespace, createErr)
		}
		return nil
	}
	return err
}
