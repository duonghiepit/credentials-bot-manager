package k8s

import (
	"context"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
)

const (
	TokenReviewerServiceAccount = "vault-token-reviewer"
	TokenReviewerBinding        = "vault-token-reviewer-binding"
	TokenReviewerSecret         = "vault-token-reviewer-token"
)

// ReviewerCredentials contains the extracted credentials for Vault K8s auth config.
type ReviewerCredentials struct {
	Token  string
	CACert string
}

// EnsureTokenReviewer creates or updates the TokenReviewer ServiceAccount, ClusterRoleBinding, and Token Secret.
func (c *Client) EnsureTokenReviewer(ctx context.Context, namespace string) (*ReviewerCredentials, error) {
	// 1. Ensure Namespace exists
	_, err := c.Clientset.CoreV1().Namespaces().Get(ctx, namespace, metav1.GetOptions{})
	if err != nil {
		if apierrors.IsNotFound(err) {
			ns := &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{Name: namespace},
			}
			if _, err := c.Clientset.CoreV1().Namespaces().Create(ctx, ns, metav1.CreateOptions{}); err != nil {
				return nil, fmt.Errorf("failed to create namespace %s: %w", namespace, err)
			}
		} else {
			return nil, fmt.Errorf("failed to check namespace %s: %w", namespace, err)
		}
	}

	// 2. Ensure ServiceAccount
	sa, err := c.Clientset.CoreV1().ServiceAccounts(namespace).Get(ctx, TokenReviewerServiceAccount, metav1.GetOptions{})
	if err != nil {
		if apierrors.IsNotFound(err) {
			sa = &corev1.ServiceAccount{
				ObjectMeta: metav1.ObjectMeta{
					Name:      TokenReviewerServiceAccount,
					Namespace: namespace,
				},
			}
			if _, err := c.Clientset.CoreV1().ServiceAccounts(namespace).Create(ctx, sa, metav1.CreateOptions{}); err != nil {
				return nil, fmt.Errorf("failed to create service account %s: %w", TokenReviewerServiceAccount, err)
			}
		} else {
			return nil, fmt.Errorf("failed to check service account: %w", err)
		}
	}

	// 3. Ensure ClusterRoleBinding (system:auth-delegator)
	crb, err := c.Clientset.RbacV1().ClusterRoleBindings().Get(ctx, TokenReviewerBinding, metav1.GetOptions{})
	if err != nil {
		if apierrors.IsNotFound(err) {
			crb = &rbacv1.ClusterRoleBinding{
				ObjectMeta: metav1.ObjectMeta{
					Name: TokenReviewerBinding,
				},
				RoleRef: rbacv1.RoleRef{
					APIGroup: "rbac.authorization.k8s.io",
					Kind:     "ClusterRole",
					Name:     "system:auth-delegator",
				},
				Subjects: []rbacv1.Subject{
					{
						Kind:      "ServiceAccount",
						Name:      TokenReviewerServiceAccount,
						Namespace: namespace,
					},
				},
			}
			if _, err := c.Clientset.RbacV1().ClusterRoleBindings().Create(ctx, crb, metav1.CreateOptions{}); err != nil {
				return nil, fmt.Errorf("failed to create cluster role binding: %w", err)
			}
		} else {
			return nil, fmt.Errorf("failed to check cluster role binding: %w", err)
		}
	}

	// 4. Ensure Token Secret (kubernetes.io/service-account-token)
	secret, err := c.Clientset.CoreV1().Secrets(namespace).Get(ctx, TokenReviewerSecret, metav1.GetOptions{})
	if err != nil {
		if apierrors.IsNotFound(err) {
			secret = &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      TokenReviewerSecret,
					Namespace: namespace,
					Annotations: map[string]string{
						"kubernetes.io/service-account.name": TokenReviewerServiceAccount,
					},
				},
				Type: corev1.SecretTypeServiceAccountToken,
			}
			if _, err := c.Clientset.CoreV1().Secrets(namespace).Create(ctx, secret, metav1.CreateOptions{}); err != nil {
				return nil, fmt.Errorf("failed to create token secret: %w", err)
			}
		} else {
			return nil, fmt.Errorf("failed to check token secret: %w", err)
		}
	}

	// 5. Poll until Token and CA are populated
	var token, caCert string
	pollErr := wait.PollUntilContextTimeout(ctx, 500*time.Millisecond, 15*time.Second, true, func(ctx context.Context) (bool, error) {
		s, err := c.Clientset.CoreV1().Secrets(namespace).Get(ctx, TokenReviewerSecret, metav1.GetOptions{})
		if err != nil {
			return false, err
		}
		rawToken, hasToken := s.Data["token"]
		rawCA, hasCA := s.Data["ca.crt"]
		if hasToken && len(rawToken) > 0 && hasCA && len(rawCA) > 0 {
			token = string(rawToken)
			caCert = string(rawCA)
			return true, nil
		}
		return false, nil
	})

	if pollErr != nil {
		return nil, fmt.Errorf("timed out waiting for token and ca.crt in secret %s: %w", TokenReviewerSecret, pollErr)
	}

	return &ReviewerCredentials{
		Token:  token,
		CACert: caCert,
	}, nil
}
