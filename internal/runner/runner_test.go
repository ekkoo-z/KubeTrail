package runner

import (
	"context"
	"testing"

	"github.com/ekkoo-z/KubeTrail/internal/model"
	"k8s.io/client-go/rest"
)

func TestRunWithKubeConfigUsesExternalTarget(t *testing.T) {
	doc := RunWithKubeConfig(context.Background(), model.Options{
		Mode:  model.ModeSafe,
		Root:  t.TempDir(),
		Scans: []string{"identity"},
	}, "test", &rest.Config{Host: "https://cluster.example.test/"}, "audit")

	if doc.Target.Namespace != "audit" {
		t.Fatalf("unexpected namespace: %q", doc.Target.Namespace)
	}
	if doc.Target.APIServer != "https://cluster.example.test" {
		t.Fatalf("unexpected API server: %q", doc.Target.APIServer)
	}
}
