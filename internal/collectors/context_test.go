package collectors

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/ekkoo-z/KubeTrail/internal/model"
	"k8s.io/client-go/rest"
)

func TestNamespaceFromResolvConf(t *testing.T) {
	root := t.TempDir()
	etc := filepath.Join(root, "etc")
	if err := os.MkdirAll(etc, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(etc, "resolv.conf"), []byte("search local-path-storage.svc.cluster.local svc.cluster.local cluster.local\nnameserver 10.96.0.10\noptions ndots:5\n"), 0644); err != nil {
		t.Fatal(err)
	}

	cctx := NewContext(model.Options{Root: root})
	if got := cctx.Namespace(); got != "local-path-storage" {
		t.Fatalf("unexpected namespace: %q", got)
	}
}

func TestContextWithKubeConfigUsesExternalTarget(t *testing.T) {
	cfg := &rest.Config{Host: "https://cluster.example.test/"}
	cctx := NewContextWithKubeConfig(model.Options{}, cfg, "audit")

	if got := cctx.Namespace(); got != "audit" {
		t.Fatalf("unexpected namespace: %q", got)
	}
	if got := cctx.APIServer(); got != "https://cluster.example.test" {
		t.Fatalf("unexpected API server: %q", got)
	}

	client, err := cctx.KubeClient()
	if err != nil {
		t.Fatalf("KubeClient failed: %v", err)
	}
	if client.Namespace != "audit" {
		t.Fatalf("unexpected client namespace: %q", client.Namespace)
	}
	if client.BaseURL != "https://cluster.example.test" {
		t.Fatalf("unexpected client base URL: %q", client.BaseURL)
	}
}
