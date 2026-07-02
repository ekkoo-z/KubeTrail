package collectors

import "testing"

func TestCompactRuntimeSocketSearchDropsDebugLists(t *testing.T) {
	got := compactRuntimeSocketSearch(map[string]any{
		"roots":          []string{"/run", "/var/run"},
		"knownPaths":     []string{"/run/containerd/containerd.sock"},
		"socketNames":    []string{"containerd.sock"},
		"scannedEntries": 42,
		"truncated":      false,
	}, 0)

	if got["matchedCount"] != 0 || got["scannedEntries"] != 42 {
		t.Fatalf("unexpected compact search summary: %#v", got)
	}
	for _, key := range []string{"roots", "knownPaths", "socketNames"} {
		if _, ok := got[key]; ok {
			t.Fatalf("debug list %s should not be emitted: %#v", key, got)
		}
	}
}
