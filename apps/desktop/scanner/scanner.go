package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/ekkoo-z/KubeTrail/internal/model"
	"github.com/ekkoo-z/KubeTrail/internal/runner"
	"github.com/ekkoo-z/KubeTrail/internal/sensitivity"
	"github.com/google/uuid"
	"k8s.io/client-go/rest"
)

type ScanResult struct {
	ID         string          `json:"id"`
	Source     string          `json:"source"`
	SourcePath string          `json:"sourcePath,omitempty"`
	Document   *model.Document `json:"document"`
	LoadedAt   string          `json:"loadedAt"`
	FactCount  int             `json:"factCount"`
	ErrorCount int             `json:"errorCount"`
}

type ScanOptions struct {
	Mode            string `json:"mode"`
	Timeout         int    `json:"timeout"`
	Sensitive       string `json:"sensitive"`
	RBACMode        string `json:"rbacMode"`
	CredentialSweep bool   `json:"credentialSweep"`
	MaxItems        int    `json:"maxItems"`
}

type ScanProgress struct {
	Phase   string `json:"phase"`
	Message string `json:"message"`
	Percent int    `json:"percent"`
}

type Scanner struct {
	mu      sync.Mutex
	results map[string]*ScanResult
}

func NewScanner() *Scanner {
	return &Scanner{results: map[string]*ScanResult{}}
}

func (s *Scanner) ImportResult(path string) (*ScanResult, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read file: %w", err)
	}
	var doc model.Document
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("parse json: %w", err)
	}
	if doc.SchemaVersion != model.SchemaVersion {
		return nil, fmt.Errorf("unsupported schema: %s (expected %s)", doc.SchemaVersion, model.SchemaVersion)
	}
	result := &ScanResult{
		ID:         uuid.NewString(),
		Source:     "import",
		SourcePath: path,
		Document:   &doc,
		LoadedAt:   formatTimestamp(time.Now()),
		FactCount:  len(doc.Facts),
		ErrorCount: len(doc.Errors),
	}
	s.mu.Lock()
	s.results[result.ID] = result
	s.mu.Unlock()
	return result, nil
}

func (s *Scanner) StartScan(ctx context.Context, cfg *rest.Config, namespace string, opts ScanOptions) (*ScanResult, error) {
	if cfg == nil {
		return nil, fmt.Errorf("kubernetes config is required")
	}
	mode := model.ModeSafe
	if opts.Mode == "full" {
		mode = model.ModeFull
	}
	sensitiveMode := model.SensitiveRedact
	switch opts.Sensitive {
	case "raw":
		sensitiveMode = model.SensitiveRaw
	case "metadata":
		sensitiveMode = model.SensitiveMetadata
	}
	rbacMode := model.RBACModeFocused
	if opts.RBACMode == string(model.RBACModeFull) {
		rbacMode = model.RBACModeFull
	}
	timeout := time.Duration(opts.Timeout) * time.Second
	if timeout == 0 {
		timeout = 60 * time.Second
	}
	maxItems := opts.MaxItems
	if maxItems == 0 {
		maxItems = 100
	}

	runOpts := model.Options{
		Mode:            mode,
		Timeout:         timeout,
		SensitiveMode:   sensitiveMode,
		RBACMode:        rbacMode,
		CredentialSweep: opts.CredentialSweep,
		MaxItems:        maxItems,
		APIScope:        model.APIScopePermitted,
		Kubeconfig:      "",
		KubeQPS:         cfg.QPS,
		KubeBurst:       cfg.Burst,
		RemoteOnly:      true,
	}

	scanCtx, cancel := context.WithTimeout(ctx, timeout+10*time.Second)
	defer cancel()

	doc := runner.RunWithKubeConfig(scanCtx, runOpts, "desktop/0.1", cfg, namespace)
	sensitivity.Apply(&doc, sensitiveMode)

	result := &ScanResult{
		ID:         uuid.NewString(),
		Source:     "live",
		Document:   &doc,
		LoadedAt:   formatTimestamp(time.Now()),
		FactCount:  len(doc.Facts),
		ErrorCount: len(doc.Errors),
	}
	s.mu.Lock()
	s.results[result.ID] = result
	s.mu.Unlock()
	return result, nil
}

func (s *Scanner) GetResult(id string) *ScanResult {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.results[id]
}

func (s *Scanner) ListResults() []*ScanResult {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*ScanResult, 0, len(s.results))
	for _, r := range s.results {
		out = append(out, r)
	}
	return out
}

func (s *Scanner) ExportResult(id, path string) error {
	s.mu.Lock()
	r := s.results[id]
	s.mu.Unlock()
	if r == nil {
		return fmt.Errorf("scan result %s not found", id)
	}
	data, err := json.MarshalIndent(r.Document, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

func (s *Scanner) DeleteResult(id string) {
	s.mu.Lock()
	delete(s.results, id)
	s.mu.Unlock()
}

func (s *Scanner) ResultToTempFile(id string) (string, error) {
	s.mu.Lock()
	r := s.results[id]
	s.mu.Unlock()
	if r == nil {
		return "", fmt.Errorf("scan result %s not found", id)
	}
	if r.Source == "import" && r.SourcePath != "" {
		return r.SourcePath, nil
	}
	f, err := os.CreateTemp("", "kubetrail-scan-*.json")
	if err != nil {
		return "", err
	}
	data, err := json.Marshal(r.Document)
	if err != nil {
		f.Close()
		os.Remove(f.Name())
		return "", err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(f.Name())
		return "", err
	}
	f.Close()
	return f.Name(), nil
}

func formatTimestamp(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339Nano)
}
