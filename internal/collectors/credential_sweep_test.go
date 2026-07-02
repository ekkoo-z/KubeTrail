package collectors

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/ekkoo-z/KubeTrail/internal/model"
)

func TestCollectCredentialSweepReadsCommonCredentialFiles(t *testing.T) {
	root := t.TempDir()
	awsPath := filepath.Join(root, "root", ".aws", "credentials")
	if err := os.MkdirAll(filepath.Dir(awsPath), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(awsPath, []byte("[default]\naws_access_key_id=AKIA_TEST\naws_secret_access_key=secret\n"), 0600); err != nil {
		t.Fatal(err)
	}

	cctx := NewContext(model.Options{Root: root})
	facts, errs := collectCredentialSweep(context.Background(), cctx)
	if len(errs) != 0 {
		t.Fatalf("unexpected errors: %#v", errs)
	}
	if len(facts) != 1 {
		t.Fatalf("expected one fact, got %d", len(facts))
	}
	if !facts[0].Sensitive {
		t.Fatalf("credential sweep fact must be sensitive")
	}

	value, ok := facts[0].Value.(map[string]any)
	if !ok {
		t.Fatalf("unexpected fact value: %#v", facts[0].Value)
	}
	files, ok := value["files"].([]map[string]any)
	if !ok {
		t.Fatalf("unexpected files value: %#v", value["files"])
	}
	if len(files) != 1 {
		t.Fatalf("expected one credential file, got %#v", files)
	}
	if files[0]["path"] != "/root/.aws/credentials" {
		t.Fatalf("unexpected credential path: %#v", files[0]["path"])
	}
	if files[0]["content"] == "" {
		t.Fatalf("expected file content")
	}
}
