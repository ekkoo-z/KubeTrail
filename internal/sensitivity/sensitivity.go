package sensitivity

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/ekkoo-z/KubeTrail/internal/model"
)

func Apply(doc *model.Document, mode model.SensitiveMode) {
	if mode == model.SensitiveRaw {
		return
	}
	for i := range doc.Facts {
		if doc.Facts[i].Sensitive {
			doc.Facts[i].Value = transform(doc.Facts[i].Value, mode)
		}
	}
	for i := range doc.Collectors {
		for j := range doc.Collectors[i].Facts {
			if doc.Collectors[i].Facts[j].Sensitive {
				doc.Collectors[i].Facts[j].Value = transform(doc.Collectors[i].Facts[j].Value, mode)
			}
		}
	}
}

func transform(value any, mode model.SensitiveMode) any {
	switch mode {
	case model.SensitiveRedact:
		return "[redacted]"
	case model.SensitiveMetadata:
		return metadata(value)
	default:
		return value
	}
}

func metadata(value any) map[string]any {
	text := fmt.Sprintf("%v", value)
	sum := sha256.Sum256([]byte(text))
	return map[string]any{
		"present": true,
		"bytes":   len(text),
		"sha256":  hex.EncodeToString(sum[:]),
	}
}
