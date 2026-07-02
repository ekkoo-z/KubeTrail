package collectors

import (
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	"github.com/ekkoo-z/KubeTrail/internal/kube"
)

func TestServiceAccountTokenSecretsExtractsLegacyTokens(t *testing.T) {
	client := &kube.Client{Typed: fake.NewSimpleClientset(
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "builder-token",
				Namespace: "ml-platform",
				Annotations: map[string]string{
					corev1.ServiceAccountNameKey: "builder",
				},
			},
			Type: corev1.SecretTypeServiceAccountToken,
			Data: map[string][]byte{corev1.ServiceAccountTokenKey: []byte("header.payload.sig")},
		},
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "opaque", Namespace: "ml-platform"},
			Type:       corev1.SecretTypeOpaque,
			Data:       map[string][]byte{"token": []byte("ignored")},
		},
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "missing-token", Namespace: "ml-platform"},
			Type:       corev1.SecretTypeServiceAccountToken,
		},
	)}

	secrets, errs := serviceAccountTokenSecrets(context.Background(), client, "ml-platform")
	if len(secrets) != 1 {
		t.Fatalf("expected one token secret, got %#v", secrets)
	}
	if secrets[0].Name != "builder-token" || secrets[0].ServiceAccount != "builder" || secrets[0].Token != "header.payload.sig" {
		t.Fatalf("unexpected token secret: %#v", secrets[0])
	}
	if len(errs) != 1 || !strings.Contains(errs[0].Message, "no token data") {
		t.Fatalf("expected missing token error, got %#v", errs)
	}
}

func TestServiceAccountTokenAuditNamespacesFallsBackOnDeniedList(t *testing.T) {
	typed := fake.NewSimpleClientset()
	typed.Fake.PrependReactor("list", "namespaces", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New("forbidden")
	})
	client := &kube.Client{Typed: typed}

	namespaces, errs := serviceAccountTokenAuditNamespaces(context.Background(), client, "ml-platform")
	if len(namespaces) != 1 || namespaces[0] != "ml-platform" {
		t.Fatalf("unexpected namespaces: %#v", namespaces)
	}
	if len(errs) != 1 || !strings.Contains(errs[0].Message, "forbidden") {
		t.Fatalf("expected namespace list error, got %#v", errs)
	}
}

func TestJWTClaimsParsesPayloadAndReportsMalformedToken(t *testing.T) {
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"system:serviceaccount:ml-platform:builder","kubernetes.io/serviceaccount/service-account.name":"builder"}`))
	claims, err := jwtClaims("header." + payload + ".sig")
	if err != nil {
		t.Fatalf("jwtClaims failed: %v", err)
	}
	if got := claims["sub"]; got != "system:serviceaccount:ml-platform:builder" {
		t.Fatalf("unexpected sub claim: %#v", got)
	}
	if _, err := jwtClaims("not-a-jwt"); err == nil {
		t.Fatalf("expected malformed token error")
	}
}
