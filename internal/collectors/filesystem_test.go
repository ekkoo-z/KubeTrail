package collectors

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSummarizeDevicesOmitsLowSignalTTYEntries(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{"tty1", "tty10", "ttyS0", "null", "kvm", "fuse"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte{}, 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}

	got, err := summarizeDevices(root, 512)
	if err != nil {
		t.Fatalf("summarize devices: %v", err)
	}

	summary, ok := got["summary"].(map[string]any)
	if !ok {
		t.Fatalf("missing summary: %#v", got)
	}
	if summary["ttyDevices"] != 3 {
		t.Fatalf("expected ttyDevices=3, got %#v", summary["ttyDevices"])
	}

	items, ok := got["items"].([]map[string]any)
	if !ok {
		t.Fatalf("missing items: %#v", got)
	}
	names := map[string]bool{}
	for _, item := range items {
		name, _ := item["name"].(string)
		names[name] = true
	}
	for _, name := range []string{"tty1", "tty10", "ttyS0", "null"} {
		if names[name] {
			t.Fatalf("low-signal device %s should not be emitted: %#v", name, items)
		}
	}
	for _, name := range []string{"kvm", "fuse"} {
		if !names[name] {
			t.Fatalf("interesting device %s should be emitted: %#v", name, items)
		}
	}
}
