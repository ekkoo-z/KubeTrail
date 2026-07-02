package kube

import (
	"testing"
	"time"

	"k8s.io/client-go/rest"
)

func TestGroupVersionResource(t *testing.T) {
	got := groupVersionResource(APIResource{Group: "apps", Version: "v1", Name: "deployments"})
	if got.Group != "apps" || got.Version != "v1" || got.Resource != "deployments" {
		t.Fatalf("unexpected group version resource: %#v", got)
	}
}

func TestCanListWildcard(t *testing.T) {
	rules := []ResourceRule{
		{Verbs: []string{"get", "list"}, APIGroups: []string{"apps"}, Resources: []string{"deployments"}},
	}
	if !CanList(rules, APIResource{Group: "apps", Name: "deployments"}) {
		t.Fatalf("expected list to be allowed")
	}
	if CanList(rules, APIResource{Group: "", Name: "pods"}) {
		t.Fatalf("did not expect pods to be allowed")
	}
}

func TestConfigureRESTClientUsesHigherDefaults(t *testing.T) {
	cfg := &rest.Config{}
	configureRESTClient(cfg, Options{})

	if cfg.QPS != defaultQPS {
		t.Fatalf("unexpected default qps: %v", cfg.QPS)
	}
	if cfg.Burst != defaultBurst {
		t.Fatalf("unexpected default burst: %v", cfg.Burst)
	}
	if cfg.Timeout != 15*time.Second {
		t.Fatalf("unexpected timeout: %v", cfg.Timeout)
	}
	if cfg.UserAgent != "kubetrail-server" {
		t.Fatalf("unexpected user agent: %q", cfg.UserAgent)
	}
}

func TestConfigureRESTClientAllowsRateLimitOverride(t *testing.T) {
	cfg := &rest.Config{}
	configureRESTClient(cfg, Options{QPS: 12.5, Burst: 25})

	if cfg.QPS != 12.5 {
		t.Fatalf("unexpected qps override: %v", cfg.QPS)
	}
	if cfg.Burst != 25 {
		t.Fatalf("unexpected burst override: %v", cfg.Burst)
	}
}

func TestNewClientWithBearerTokenClearsOtherAuth(t *testing.T) {
	base := &Client{Config: &rest.Config{
		Host:            "https://kubernetes.default.svc",
		Username:        "old-user",
		Password:        "old-pass",
		BearerToken:     "old-token",
		BearerTokenFile: "/var/run/secrets/kubernetes.io/serviceaccount/token",
		TLSClientConfig: rest.TLSClientConfig{
			Insecure: true,
			CertFile: "/tmp/client.crt",
			KeyFile:  "/tmp/client.key",
			CertData: []byte("cert"),
			KeyData:  []byte("key"),
		},
	}}

	client, err := NewClientWithBearerToken(base, "new-token", "default", Options{})
	if err != nil {
		t.Fatalf("NewClientWithBearerToken failed: %v", err)
	}
	cfg := client.Config
	if cfg.BearerToken != "new-token" {
		t.Fatalf("unexpected bearer token: %q", cfg.BearerToken)
	}
	if cfg.BearerTokenFile != "" || cfg.Username != "" || cfg.Password != "" {
		t.Fatalf("old auth was not cleared: %#v", cfg)
	}
	if cfg.TLSClientConfig.CertFile != "" || cfg.TLSClientConfig.KeyFile != "" || cfg.TLSClientConfig.CertData != nil || cfg.TLSClientConfig.KeyData != nil {
		t.Fatalf("client certificate auth was not cleared: %#v", cfg.TLSClientConfig)
	}
}
