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

const projectURL = "https://github.com/ekkoo-z/KubeTrail"

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

	color := isTerminal(stderr)
	renderServerUI(stderr, color)
	printer := newScanPrinter(stderr)
	printer.PrintPlan(runner.CollectorPlan(opts), opts.SATokenAuditOutput != "")

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

	printer.PrintSummary(doc, audit)
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

func renderServerUI(w io.Writer, color bool) {
	const banner = ` _  __     _          _____          _ _
| |/ /   _| |__   ___|_   _| __ __ _(_) |
| ' /| | | | '_ \ / _ \ | || '__/ _` + "`" + ` | | |
| . \| |_| | |_) |  __/ | || | | (_| | | |
|_|\_\\__,_|_.__/ \___| |_||_|  \__,_|_|_|
`
	if color {
		fmt.Fprintf(w, "\033[1;36m%s\033[0m", banner)
		fmt.Fprintf(w, "\033[1;32mby ekkoo\033[0m \033[2m|\033[0m \033[1;35mGitHub:\033[0m \033[4;34m%s\033[0m\n\n", projectURL)
	} else {
		fmt.Fprint(w, banner)
		fmt.Fprintf(w, "by ekkoo | GitHub: %s\n\n", projectURL)
	}
}

type scanPrinter struct {
	w io.Writer
}

func newScanPrinter(w io.Writer) *scanPrinter {
	return &scanPrinter{w: w}
}

func (p *scanPrinter) PrintPlan(plan []runner.CollectorInfo, includeSATokenAudit bool) {
	moduleNames := make([]string, 0, len(plan)+1)
	if includeSATokenAudit {
		moduleNames = append(moduleNames, "ServiceAccount token audit")
	}
	for _, item := range plan {
		moduleNames = append(moduleNames, collectorDisplayName(item.ID))
	}
	fmt.Fprintf(p.w, "[scan] 检测模块 (%d): %s\n", len(moduleNames), strings.Join(moduleNames, ", "))
	fmt.Fprintln(p.w, "[scan] 正在检测目标...")
}

func collectorDisplayName(id string) string {
	switch id {
	case "identity":
		return "Identity"
	case "environment":
		return "Environment"
	case "serviceaccount":
		return "ServiceAccount"
	case "proc":
		return "Process"
	case "proc_sys_escape":
		return "Proc sys escape"
	case "filesystem":
		return "Filesystem"
	case "node_local":
		return "Node local"
	case "runtime_local":
		return "Runtime local"
	case "lpe_local":
		return "Local privilege escalation"
	case "k8s_context":
		return "Kubernetes context"
	case "k8s_permissions":
		return "Kubernetes permissions"
	case "k8s_profile":
		return "Kubernetes profile"
	case "k8s_objects":
		return "Kubernetes objects"
	case "credential_sweep":
		return "Credential sweep"
	case "dns_services":
		return "DNS services"
	case "cloud_metadata":
		return "Cloud metadata"
	case "admission_dryrun":
		return "Admission dry-run"
	case "syscalls":
		return "Syscalls"
	default:
		return id
	}
}

func (p *scanPrinter) PrintSummary(doc model.Document, audit *model.SATokenAuditDocument) {
	errorCount := len(doc.Errors)
	extra := ""
	if audit != nil {
		errorCount += len(audit.Errors)
		extra = fmt.Sprintf(" auditItems=%d", len(audit.Items))
	}
	fmt.Fprintf(
		p.w,
		"[scan] 检测完成: collectors=%d facts=%d findings=%d errors=%d duration=%s%s\n\n",
		len(doc.Collectors),
		len(doc.Facts),
		len(doc.Findings),
		errorCount,
		formatDurationMillis(doc.Run.DurationMs),
		extra,
	)
}

func formatDurationMillis(ms int64) string {
	if ms <= 0 {
		return "0ms"
	}
	return (time.Duration(ms) * time.Millisecond).String()
}

func usage(w io.Writer) {
	fmt.Fprintln(w, "usage:")
	fmt.Fprintln(w, "  kubetrail-server [-m safe|full] [-s all|lpe|escape|rbac] [-r focused|full] [-o dbus.json|-] [-p] [-t 60s] [-v raw|redact|metadata] [-c=false] [-secret secret-audit.json] [-k kubeconfig] [-n 100]")
	fmt.Fprintln(w, "  kubetrail-server version")
}
