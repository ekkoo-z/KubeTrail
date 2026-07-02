package command

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ekkoo-z/KubeTrail/internal/model"
	"github.com/ekkoo-z/KubeTrail/internal/runner"
)

func TestCollectWritesJSON(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	root := t.TempDir()
	output := filepath.Join(root, "out.json")

	code := Run([]string{"kubetrail-server", "--timeout", "2s", "--sensitive", "metadata", "--credential-sweep=false", "--output", output}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("collect failed with code %d: %s", code, stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("expected default file output, got stdout: %s", stdout.String())
	}

	var doc map[string]any
	data, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("output is not json: %v\n%s", err, string(data))
	}
	if doc["schemaVersion"] != "kubetrail.server/v1" {
		t.Fatalf("unexpected schema version: %#v", doc["schemaVersion"])
	}
	if doc["mode"] != "safe" {
		t.Fatalf("unexpected mode: %#v", doc["mode"])
	}
	if findings, ok := doc["findings"].([]any); !ok {
		t.Fatalf("expected findings array in output JSON, got %#v", doc["findings"])
	} else if findings == nil {
		t.Fatalf("expected findings to be an empty array, got nil")
	}
	if strings.Contains(string(data), "\n  \"schemaVersion\"") {
		t.Fatalf("default output should be compact; use --pretty for indented JSON")
	}
	collectors, _ := doc["collectors"].([]any)
	for _, raw := range collectors {
		collector, _ := raw.(map[string]any)
		if _, ok := collector["facts"]; ok {
			t.Fatalf("default output should not duplicate facts under collectors: %#v", collector)
		}
	}
}

func TestCollectPrettyOutput(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	root := t.TempDir()
	output := filepath.Join(root, "out.json")

	code := Run([]string{"kubetrail-server", "--timeout", "2s", "--pretty", "--credential-sweep=false", "--output", output}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("collect failed with code %d: %s", code, stderr.String())
	}

	data, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "\n  \"schemaVersion\"") {
		t.Fatalf("--pretty output was not indented: %s", string(data[:min(len(data), 120)]))
	}
	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("output is not json: %v\n%s", err, string(data))
	}
	collectors, _ := doc["collectors"].([]any)
	for _, raw := range collectors {
		collector, _ := raw.(map[string]any)
		if _, ok := collector["facts"]; ok {
			t.Fatalf("collector facts should not be duplicated in CLI output: %#v", collector)
		}
	}
}

func TestCollectShortFlags(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	root := t.TempDir()
	output := filepath.Join(root, "short.json")

	code := Run([]string{
		"kubetrail-server",
		"-m", "safe",
		"-t", "2s",
		"-v", "metadata",
		"-r", "focused",
		"-s", "lpe",
		"-c=false",
		"-n", "10",
		"-k", filepath.Join(root, "unused-kubeconfig"),
		"-p",
		"-o", output,
	}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("collect failed with code %d: %s", code, stderr.String())
	}

	data, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "\n  \"schemaVersion\"") {
		t.Fatalf("-p output was not indented: %s", string(data[:min(len(data), 120)]))
	}
	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("output is not json: %v\n%s", err, string(data))
	}
	if doc["mode"] != "safe" {
		t.Fatalf("unexpected mode: %#v", doc["mode"])
	}
}

func TestCredentialSweepOptionAddsCollector(t *testing.T) {
	root := t.TempDir()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	doc := runner.Run(ctx, model.Options{
		Mode:            model.ModeSafe,
		SensitiveMode:   model.SensitiveMetadata,
		APIScope:        model.APIScopePermitted,
		RBACMode:        model.RBACModeFocused,
		Timeout:         2 * time.Second,
		KubeQPS:         50,
		KubeBurst:       100,
		Root:            root,
		MaxItems:        100,
		CredentialSweep: true,
		Scans:           []string{"lpe"},
	}, "test")

	for _, collector := range doc.Collectors {
		if collector.ID == "credential_sweep" {
			return
		}
	}
	t.Fatalf("credential_sweep collector was not present: %#v", doc.Collectors)
}

func TestSATokenAuditOutputValidation(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
	}{
		{
			name: "short flag stdout is not accepted",
			args: []string{"kubetrail-server", "-secret", "-"},
			want: "--secretoutput must be a file path",
		},
		{
			name: "long flag must not overwrite main output",
			args: []string{"kubetrail-server", "--output", "same.json", "--secretoutput", "same.json"},
			want: "--secretoutput must be different from --output",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout bytes.Buffer
			var stderr bytes.Buffer

			code := Run(tt.args, &stdout, &stderr)
			if code != 2 {
				t.Fatalf("expected code 2, got %d", code)
			}
			if !strings.Contains(stderr.String(), tt.want) {
				t.Fatalf("expected stderr to contain %q, got %s", tt.want, stderr.String())
			}
		})
	}
}

func TestDefaultOutputIsDBusJSON(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	dir := t.TempDir()
	oldWd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(oldWd)

	code := Run([]string{"kubetrail-server", "--timeout", "2s", "--credential-sweep=false"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("collect failed with code %d: %s", code, stderr.String())
	}
	if _, err := os.Stat(filepath.Join(dir, "dbus.json")); err != nil {
		t.Fatalf("expected default dbus.json output: %v", err)
	}
}

func TestCollectSubcommandIsNotSupported(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := Run([]string{"kubetrail-server", "collect", "--mode", "safe"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("expected unsupported collect subcommand to return 2, got %d", code)
	}
}

func TestSyscallProbeCommandIsNotSupported(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := Run([]string{"kubetrail-server", "__syscall-probe", "getpid"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("expected unsupported syscall probe command to return 2, got %d", code)
	}
	if !strings.Contains(stderr.String(), "unknown command") {
		t.Fatalf("expected unknown command error, got %s", stderr.String())
	}
}

func TestInvalidRBACModeFlag(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
	}{
		{name: "rbac mode", args: []string{"kubetrail-server", "--rbac-mode", "deep"}, want: "invalid --rbac-mode"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout bytes.Buffer
			var stderr bytes.Buffer

			code := Run(tt.args, &stdout, &stderr)
			if code != 2 {
				t.Fatalf("expected code 2, got %d", code)
			}
			if !strings.Contains(stderr.String(), tt.want) {
				t.Fatalf("expected stderr to contain %q, got %s", tt.want, stderr.String())
			}
		})
	}
}

func TestRemovedServerFlagsAreRejected(t *testing.T) {
	tests := []string{
		"--api-scope",
		"--kube-qps",
		"--kube-burst",
		"--root",
		"--include-collector-facts",
		"--quiet",
		"--token-audit",
		"--sa-token-audit-output",
		"--sa",
		"-sa",
		"-S",
		"-x",
		"-so",
		"-mask",
		"-rbac",
		"-only",
		"-creds",
		"-kc",
		"-limit",
	}

	for _, flagName := range tests {
		t.Run(flagName, func(t *testing.T) {
			var stdout bytes.Buffer
			var stderr bytes.Buffer

			code := Run([]string{"kubetrail-server", flagName, "x"}, &stdout, &stderr)
			if code != 2 {
				t.Fatalf("expected code 2, got %d", code)
			}
			if !strings.Contains(stderr.String(), "flag provided but not defined") {
				t.Fatalf("expected undefined flag error, got %s", stderr.String())
			}
		})
	}
}

func TestValidateOptionsAllowsLPEScan(t *testing.T) {
	opts := model.Options{
		Mode:          model.ModeSafe,
		SensitiveMode: model.SensitiveMetadata,
		APIScope:      model.APIScopePermitted,
		RBACMode:      model.RBACModeFocused,
		Timeout:       2 * time.Second,
		MaxItems:      1,
		KubeQPS:       1,
		KubeBurst:     1,
		Scans:         []string{"lpe"},
	}
	if err := validateOptions(opts); err != nil {
		t.Fatalf("expected lpe scan to validate: %v", err)
	}
}

func TestValidateOptionsAllowsFullRBACMode(t *testing.T) {
	opts := model.Options{
		Mode:          model.ModeSafe,
		SensitiveMode: model.SensitiveMetadata,
		APIScope:      model.APIScopePermitted,
		RBACMode:      model.RBACModeFull,
		Timeout:       2 * time.Second,
		MaxItems:      1,
		KubeQPS:       1,
		KubeBurst:     1,
	}
	if err := validateOptions(opts); err != nil {
		t.Fatalf("expected full rbac mode to validate: %v", err)
	}
}
