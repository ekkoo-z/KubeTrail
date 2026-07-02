package collectors

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ekkoo-z/KubeTrail/internal/model"
)

func TestCollectServiceAccountMissingIsFactNotError(t *testing.T) {
	cctx := NewContext(model.Options{Root: t.TempDir()})
	facts, errs := collectServiceAccount(context.Background(), cctx)
	if len(errs) != 0 {
		t.Fatalf("missing service account should not be an error: %#v", errs)
	}
	if len(facts) != 1 || facts[0].ID != "serviceaccount.not_found" {
		t.Fatalf("unexpected facts: %#v", facts)
	}
}

func TestCollectServiceAccountDeduplicatesPathAliases(t *testing.T) {
	root := t.TempDir()
	for _, dir := range []string{
		"/run/secrets/kubernetes.io/serviceaccount",
		"/var/run/secrets/kubernetes.io/serviceaccount",
	} {
		rooted := filepath.Join(root, strings.TrimPrefix(dir, "/"))
		if err := os.MkdirAll(rooted, 0o700); err != nil {
			t.Fatalf("mkdir %s: %v", dir, err)
		}
		for name, value := range map[string]string{
			"namespace": "default",
			"token":     "token-value",
			"ca.crt":    "ca-value",
		} {
			if err := os.WriteFile(filepath.Join(rooted, name), []byte(value), 0o600); err != nil {
				t.Fatalf("write %s/%s: %v", dir, name, err)
			}
		}
	}

	cctx := NewContext(model.Options{Root: root})
	facts, errs := collectServiceAccount(context.Background(), cctx)
	if len(errs) != 0 {
		t.Fatalf("unexpected errors: %#v", errs)
	}
	if len(facts) != 1 || facts[0].ID != "serviceaccount.mounted" {
		t.Fatalf("expected one deduplicated mounted fact, got %#v", facts)
	}
	value, _ := facts[0].Value.(map[string]any)
	aliases, _ := value["aliases"].([]string)
	if len(aliases) != 2 {
		t.Fatalf("expected both path aliases, got %#v", value)
	}
}
