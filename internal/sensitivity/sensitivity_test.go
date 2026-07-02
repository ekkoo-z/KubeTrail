package sensitivity

import (
	"testing"

	"github.com/ekkoo-z/KubeTrail/internal/model"
)

func TestApplyRedact(t *testing.T) {
	doc := model.Document{
		Facts: []model.Fact{
			{ID: "plain", Value: "visible"},
			{ID: "secret", Sensitive: true, Value: "token-value"},
		},
		Collectors: []model.CollectorResult{
			{
				ID: "collector",
				Facts: []model.Fact{
					{ID: "nested-secret", Sensitive: true, Value: "nested-token"},
				},
			},
		},
	}

	Apply(&doc, model.SensitiveRedact)

	if doc.Facts[0].Value != "visible" {
		t.Fatalf("plain value was modified: %#v", doc.Facts[0].Value)
	}
	if doc.Facts[1].Value != "[redacted]" {
		t.Fatalf("sensitive value was not redacted: %#v", doc.Facts[1].Value)
	}
	if doc.Collectors[0].Facts[0].Value != "[redacted]" {
		t.Fatalf("nested sensitive value was not redacted: %#v", doc.Collectors[0].Facts[0].Value)
	}
}

func TestApplyMetadata(t *testing.T) {
	doc := model.Document{
		Facts: []model.Fact{
			{ID: "secret", Sensitive: true, Value: "token-value"},
		},
	}

	Apply(&doc, model.SensitiveMetadata)

	meta, ok := doc.Facts[0].Value.(map[string]any)
	if !ok {
		t.Fatalf("expected metadata map, got %#v", doc.Facts[0].Value)
	}
	if meta["present"] != true {
		t.Fatalf("expected present=true, got %#v", meta["present"])
	}
	if meta["bytes"] != 11 {
		t.Fatalf("expected byte count, got %#v", meta["bytes"])
	}
	if meta["sha256"] == "" {
		t.Fatalf("expected sha256")
	}
}
