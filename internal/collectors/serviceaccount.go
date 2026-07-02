package collectors

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/ekkoo-z/KubeTrail/internal/kube"
	"github.com/ekkoo-z/KubeTrail/internal/model"
)

func collectServiceAccount(_ context.Context, cctx *Context) ([]model.Fact, []model.ErrorEntry) {
	var facts []model.Fact
	var errs []model.ErrorEntry
	seen := map[string]int{}

	for _, dir := range kube.ServiceAccountPaths() {
		rooted := cctx.RootPath(dir)
		info, err := os.Stat(rooted)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			errs = append(errs, errEntry(dir, err))
			continue
		}
		if !info.IsDir() {
			continue
		}

		values := map[string]any{
			"path":    dir,
			"aliases": []string{dir},
			"mode":    info.Mode().String(),
		}
		for _, name := range []string{"namespace", "token", "ca.crt"} {
			path := filepath.Join(rooted, name)
			data, err := os.ReadFile(path)
			if err != nil {
				values[name] = map[string]any{"present": false, "error": err.Error()}
				continue
			}
			values[name] = map[string]any{
				"present": true,
				"path":    filepath.Join(dir, name),
				"bytes":   len(data),
				"content": string(data),
			}
		}

		signature := serviceAccountMaterialSignature(values)
		if index, ok := seen[signature]; ok {
			appendServiceAccountAlias(&facts[index], dir)
			continue
		}
		seen[signature] = len(facts)
		facts = append(facts, fact("serviceaccount.mounted", "kubernetes", dir, true, values))
	}

	if len(facts) == 0 {
		facts = append(facts, fact("serviceaccount.not_found", "kubernetes", "filesystem", false, map[string]any{
			"paths":  kube.ServiceAccountPaths(),
			"reason": "service account token directory is not mounted",
		}))
	}
	return facts, errs
}

func serviceAccountMaterialSignature(values map[string]any) string {
	var b strings.Builder
	for _, name := range []string{"namespace", "token", "ca.crt"} {
		entry, _ := values[name].(map[string]any)
		b.WriteString(name)
		b.WriteString("\x00")
		if content, ok := entry["content"].(string); ok {
			b.WriteString(sha256HexString(content))
		} else if present, ok := entry["present"].(bool); ok {
			b.WriteString(boolString(present))
			if msg, _ := entry["error"].(string); msg != "" {
				b.WriteString("\x00")
				b.WriteString(msg)
			}
		}
		b.WriteString("\x00")
	}
	return sha256HexString(b.String())
}

func appendServiceAccountAlias(fact *model.Fact, alias string) {
	values, ok := fact.Value.(map[string]any)
	if !ok {
		return
	}
	aliases, _ := values["aliases"].([]string)
	for _, existing := range aliases {
		if existing == alias {
			return
		}
	}
	values["aliases"] = append(aliases, alias)
}

func boolString(value bool) string {
	if value {
		return "true"
	}
	return "false"
}
