package sysprobe

import (
	"context"
	"testing"
)

func TestRunMatrixDoesNotMarkCompletedProbeAsCanceled(t *testing.T) {
	results := RunMatrix(context.Background())
	if len(results) == 0 {
		t.Fatalf("expected syscall probe results")
	}
	for _, result := range results {
		if result.Error == context.Canceled.Error() {
			t.Fatalf("completed probe was marked canceled: %#v", result)
		}
	}
}
