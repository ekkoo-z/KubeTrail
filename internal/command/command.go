package command

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ekkoo-z/KubeTrail/internal/findings"
	"github.com/ekkoo-z/KubeTrail/internal/model"
	"github.com/ekkoo-z/KubeTrail/internal/runner"
)

var version = "dev"

func Run(args []string, stdout, stderr io.Writer) int {
	if len(args) < 2 {
		return runCollect(nil, stdout, stderr)
	}

	switch args[1] {
	case "version":
		fmt.Fprintln(stdout, version)
		return 0
	default:
		if len(args[1]) > 0 && args[1][0] == '-' {
			return runCollect(args[1:], stdout, stderr)
		}
		fmt.Fprintf(stderr, "unknown command %q\n\n", args[1])
		usage(stderr)
		return 2
	}
}

func runCollect(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("kubetrail-server", flag.ContinueOnError)
	fs.SetOutput(stderr)

	var mode string
	var output string
	var saTokenAuditOutput string
	var timeout time.Duration
	var sensitive string
	var rbacMode string
	var kubeconfig string
	var maxItems int
	var pretty bool
	var credentialSweep bool
	var scan string

	fs.StringVar(&mode, "mode", string(model.ModeSafe), "collection mode: safe or full")
	fs.StringVar(&mode, "m", string(model.ModeSafe), "shorthand for --mode")
	fs.StringVar(&output, "output", "dbus.json", "output file path, or - for stdout")
	fs.StringVar(&output, "o", "dbus.json", "shorthand for --output")
	fs.StringVar(&saTokenAuditOutput, "secretoutput", "", "write visible ServiceAccount token Secrets and per-token permission audit JSON to this file")
	fs.StringVar(&saTokenAuditOutput, "secret", "", "shorthand for --secretoutput")
	fs.BoolVar(&pretty, "pretty", false, "pretty-print output JSON")
	fs.BoolVar(&pretty, "p", false, "shorthand for --pretty")
	fs.DurationVar(&timeout, "timeout", 60*time.Second, "overall collection timeout")
	fs.DurationVar(&timeout, "t", 60*time.Second, "shorthand for --timeout")
	fs.StringVar(&sensitive, "sensitive", string(model.SensitiveRaw), "sensitive value handling: raw, redact, or metadata")
	fs.StringVar(&sensitive, "v", string(model.SensitiveRaw), "shorthand for --sensitive")
	fs.StringVar(&rbacMode, "rbac-mode", string(model.RBACModeFocused), "Kubernetes RBAC access review mode: focused or full")
	fs.StringVar(&rbacMode, "r", string(model.RBACModeFocused), "shorthand for --rbac-mode")
	fs.StringVar(&kubeconfig, "kubeconfig", "", "kubeconfig path for non-cluster testing")
	fs.StringVar(&kubeconfig, "k", "", "shorthand for --kubeconfig")
	fs.IntVar(&maxItems, "max-items", 100, "maximum items per Kubernetes list request")
	fs.IntVar(&maxItems, "n", 100, "shorthand for --max-items")
	fs.BoolVar(&credentialSweep, "credential-sweep", true, "read common credential files and include their contents in output; use --credential-sweep=false to disable")
	fs.BoolVar(&credentialSweep, "c", true, "shorthand for --credential-sweep")
	fs.StringVar(&scan, "scan", "all", "scan categories: all, lpe, escape, rbac (comma-separated)")
	fs.StringVar(&scan, "s", "all", "shorthand for --scan")

	if err := fs.Parse(args); err != nil {
		return 2
	}

	scans := parseScans(scan)

	opts := model.Options{
		Mode:               model.Mode(mode),
		Output:             output,
		OutputPretty:       pretty,
		SATokenAuditOutput: saTokenAuditOutput,
		Timeout:            timeout,
		SensitiveMode:      model.SensitiveMode(sensitive),
		APIScope:           model.APIScopePermitted,
		RBACMode:           model.RBACMode(rbacMode),
		Kubeconfig:         kubeconfig,
		KubeQPS:            50,
		KubeBurst:          100,
		Root:               "/",
		MaxItems:           maxItems,
		CredentialSweep:    credentialSweep,
		Scans:              scans,
		Args:               args,
	}

	if err := validateOptions(opts); err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	var audit *model.SATokenAuditDocument
	if opts.SATokenAuditOutput != "" {
		auditDoc := runner.RunServiceAccountTokenAudit(ctx, opts, version)
		audit = &auditDoc
	}

	doc := runner.Run(ctx, opts, version)
	var data []byte
	var err error
	if opts.OutputPretty {
		data, err = json.MarshalIndent(doc, "", "  ")
	} else {
		data, err = json.Marshal(doc)
	}
	if err != nil {
		fmt.Fprintf(stderr, "marshal result: %v\n", err)
		return 1
	}
	data = append(data, '\n')

	if output == "-" {
		if _, err := stdout.Write(data); err != nil {
			fmt.Fprintf(stderr, "write stdout: %v\n", err)
			return 1
		}
	} else if err := os.WriteFile(output, data, 0600); err != nil {
		fmt.Fprintf(stderr, "write %s: %v\n", output, err)
		return 1
	}

	if audit != nil {
		var auditData []byte
		if opts.OutputPretty {
			auditData, err = json.MarshalIndent(*audit, "", "  ")
		} else {
			auditData, err = json.Marshal(*audit)
		}
		if err != nil {
			fmt.Fprintf(stderr, "marshal service account token audit: %v\n", err)
			return 1
		}
		auditData = append(auditData, '\n')
		if err := os.WriteFile(opts.SATokenAuditOutput, auditData, 0600); err != nil {
			fmt.Fprintf(stderr, "write %s: %v\n", opts.SATokenAuditOutput, err)
			return 1
		}
	}

	color := isTerminal(stderr)
	findings.Render(stderr, doc.Findings, color, output)

	return 0
}

func validateOptions(opts model.Options) error {
	switch opts.Mode {
	case model.ModeSafe, model.ModeFull:
	default:
		return fmt.Errorf("invalid --mode %q", opts.Mode)
	}
	switch opts.SensitiveMode {
	case model.SensitiveRaw, model.SensitiveRedact, model.SensitiveMetadata:
	default:
		return fmt.Errorf("invalid --sensitive %q", opts.SensitiveMode)
	}
	switch opts.RBACMode {
	case model.RBACModeFocused, model.RBACModeFull:
	default:
		return fmt.Errorf("invalid --rbac-mode %q", opts.RBACMode)
	}
	if opts.Timeout <= 0 {
		return fmt.Errorf("--timeout must be positive")
	}
	if opts.MaxItems <= 0 {
		return fmt.Errorf("--max-items must be positive")
	}
	for _, s := range opts.Scans {
		switch s {
		case "lpe", "escape", "rbac":
		default:
			return fmt.Errorf("invalid --scan category %q (valid: all, lpe, escape, rbac)", s)
		}
	}
	if opts.SATokenAuditOutput == "-" {
		return fmt.Errorf("--secretoutput must be a file path, not -")
	}
	if opts.SATokenAuditOutput != "" && opts.Output != "-" {
		outputPath, err := filepath.Abs(opts.Output)
		if err != nil {
			return fmt.Errorf("resolve --output: %w", err)
		}
		auditPath, err := filepath.Abs(opts.SATokenAuditOutput)
		if err != nil {
			return fmt.Errorf("resolve --secretoutput: %w", err)
		}
		if outputPath == auditPath {
			return fmt.Errorf("--secretoutput must be different from --output")
		}
	}
	return nil
}

func parseScans(value string) []string {
	if value == "" || value == "all" {
		return nil
	}
	var scans []string
	for _, s := range strings.Split(value, ",") {
		s = strings.TrimSpace(s)
		if s != "" {
			scans = append(scans, s)
		}
	}
	return scans
}

func isTerminal(w io.Writer) bool {
	if f, ok := w.(*os.File); ok {
		stat, err := f.Stat()
		if err != nil {
			return false
		}
		return stat.Mode()&os.ModeCharDevice != 0
	}
	return false
}

func usage(w io.Writer) {
	fmt.Fprintln(w, "usage:")
	fmt.Fprintln(w, "  kubetrail-server [-m safe|full] [-s all|lpe|escape|rbac] [-r focused|full] [-o dbus.json|-] [-p] [-t 60s] [-v raw|redact|metadata] [-c=false] [-secret secret-audit.json] [-k kubeconfig] [-n 100]")
	fmt.Fprintln(w, "  kubetrail-server version")
}
