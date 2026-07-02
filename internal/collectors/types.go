package collectors

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"

	"github.com/ekkoo-z/KubeTrail/internal/kube"
	"github.com/ekkoo-z/KubeTrail/internal/model"
	"k8s.io/client-go/rest"
)

type Collector interface {
	ID() string
	Mode() model.Mode
	SideEffects() []string
	Collect(context.Context, *Context) ([]model.Fact, []model.ErrorEntry)
}

type Context struct {
	Options model.Options
	Env     map[string]string

	kubeConfig    *rest.Config
	kubeNamespace string
	kubeClient    *kube.Client
	kubeErr       error
}

func NewContext(opts model.Options) *Context {
	return &Context{
		Options: opts,
		Env:     envMap(os.Environ()),
	}
}

func NewContextWithKubeConfig(opts model.Options, cfg *rest.Config, namespace string) *Context {
	cctx := NewContext(opts)
	cctx.kubeConfig = cfg
	cctx.kubeNamespace = namespace
	return cctx
}

func (c *Context) RootPath(path string) string {
	if c.Options.Root == "" || c.Options.Root == "/" {
		return path
	}
	return filepath.Join(c.Options.Root, strings.TrimPrefix(path, "/"))
}

func (c *Context) InKubernetes() bool {
	return c.Env["KUBERNETES_SERVICE_HOST"] != ""
}

func (c *Context) Namespace() string {
	if c.kubeNamespace != "" {
		return c.kubeNamespace
	}
	for _, path := range kube.ServiceAccountPaths() {
		data, err := os.ReadFile(c.RootPath(filepath.Join(path, "namespace")))
		if err == nil {
			return strings.TrimSpace(string(data))
		}
	}
	if namespace := c.Env["POD_NAMESPACE"]; namespace != "" {
		return namespace
	}
	return c.namespaceFromResolvConf()
}

func (c *Context) APIServer() string {
	if c.kubeConfig != nil {
		return strings.TrimRight(c.kubeConfig.Host, "/")
	}
	host := c.Env["KUBERNETES_SERVICE_HOST"]
	if host == "" {
		return ""
	}
	port := c.Env["KUBERNETES_SERVICE_PORT_HTTPS"]
	if port == "" {
		port = c.Env["KUBERNETES_SERVICE_PORT"]
	}
	if port == "" {
		port = "443"
	}
	return "https://" + host + ":" + port
}

func (c *Context) namespaceFromResolvConf() string {
	data, err := os.ReadFile(c.RootPath("/etc/resolv.conf"))
	if err != nil {
		return ""
	}
	fields := strings.Fields(string(data))
	for i, field := range fields {
		if field != "search" {
			continue
		}
		for _, domain := range fields[i+1:] {
			if domain == "options" || domain == "nameserver" {
				break
			}
			if strings.HasSuffix(domain, ".svc.cluster.local") {
				namespace := strings.TrimSuffix(domain, ".svc.cluster.local")
				if namespace != "" && namespace != "svc" {
					return namespace
				}
			}
		}
	}
	return ""
}

func (c *Context) KubeClient() (*kube.Client, error) {
	if c.kubeClient != nil || c.kubeErr != nil {
		return c.kubeClient, c.kubeErr
	}
	if c.kubeConfig != nil {
		c.kubeClient, c.kubeErr = kube.NewClientFromRestConfig(c.kubeConfig, c.kubeNamespace, kube.Options{
			Root:       c.Options.Root,
			Env:        c.Env,
			Kubeconfig: c.Options.Kubeconfig,
			QPS:        c.Options.KubeQPS,
			Burst:      c.Options.KubeBurst,
		})
		return c.kubeClient, c.kubeErr
	}
	c.kubeClient, c.kubeErr = kube.NewClient(kube.Options{
		Root:       c.Options.Root,
		Env:        c.Env,
		Kubeconfig: c.Options.Kubeconfig,
		QPS:        c.Options.KubeQPS,
		Burst:      c.Options.KubeBurst,
	})
	return c.kubeClient, c.kubeErr
}

type simpleCollector struct {
	id          string
	mode        model.Mode
	sideEffects []string
	fn          func(context.Context, *Context) ([]model.Fact, []model.ErrorEntry)
}

func (c simpleCollector) ID() string            { return c.id }
func (c simpleCollector) Mode() model.Mode      { return c.mode }
func (c simpleCollector) SideEffects() []string { return c.sideEffects }

func (c simpleCollector) Collect(ctx context.Context, cctx *Context) ([]model.Fact, []model.ErrorEntry) {
	return c.fn(ctx, cctx)
}

func ForOptions(opts model.Options) []Collector {
	runLPE := len(opts.Scans) == 0 || scanEnabled(opts.Scans, "lpe")
	runEscape := len(opts.Scans) == 0 || scanEnabled(opts.Scans, "escape")
	runRBAC := len(opts.Scans) == 0 || scanEnabled(opts.Scans, "rbac")

	var base []Collector

	if !opts.RemoteOnly {
		base = append(base,
			simpleCollector{id: "identity", mode: model.ModeSafe, fn: collectIdentity},
			simpleCollector{id: "environment", mode: model.ModeSafe, fn: collectEnvironment},
			simpleCollector{id: "serviceaccount", mode: model.ModeSafe, fn: collectServiceAccount},
		)

		if runEscape {
			base = append(base,
				simpleCollector{id: "proc", mode: model.ModeSafe, fn: collectProc},
				simpleCollector{id: "proc_sys_escape", mode: model.ModeSafe, fn: collectProcSysEscape},
				simpleCollector{id: "filesystem", mode: model.ModeSafe, fn: collectFilesystem},
				simpleCollector{id: "node_local", mode: model.ModeSafe, fn: collectNodeLocal},
				simpleCollector{id: "runtime_local", mode: model.ModeSafe, fn: collectRuntimeLocal},
			)
		}

		if runLPE {
			base = append(base, simpleCollector{id: "lpe_local", mode: model.ModeSafe, fn: collectLPE})
		}
	}

	if runEscape || runRBAC {
		base = append(base, simpleCollector{id: "k8s_context", mode: model.ModeSafe, fn: collectKubernetesContext})
	}

	if runRBAC {
		base = append(base,
			simpleCollector{id: "k8s_permissions", mode: model.ModeSafe, fn: collectKubernetesPermissions},
			simpleCollector{id: "k8s_profile", mode: model.ModeSafe, fn: collectKubernetesProfile},
			simpleCollector{id: "k8s_objects", mode: model.ModeSafe, fn: collectKubernetesObjects},
		)
	}

	if !opts.RemoteOnly && opts.CredentialSweep {
		base = append(base, simpleCollector{id: "credential_sweep", mode: model.ModeSafe, fn: collectCredentialSweep})
	}
	if opts.Mode != model.ModeFull {
		return base
	}
	if opts.RemoteOnly {
		return append(base,
			simpleCollector{id: "admission_dryrun", mode: model.ModeFull, sideEffects: []string{"kubernetes_dry_run_create"}, fn: collectAdmissionDryRun},
		)
	}
	return append(base,
		simpleCollector{id: "dns_services", mode: model.ModeFull, sideEffects: []string{"dns_queries"}, fn: collectDNSServices},
		simpleCollector{id: "cloud_metadata", mode: model.ModeFull, sideEffects: []string{"http_requests"}, fn: collectCloudMetadata},
		simpleCollector{id: "admission_dryrun", mode: model.ModeFull, sideEffects: []string{"kubernetes_dry_run_create"}, fn: collectAdmissionDryRun},
		simpleCollector{id: "syscalls", mode: model.ModeFull, sideEffects: []string{"syscall_probes"}, fn: collectSyscalls},
	)
}

func scanEnabled(scans []string, target string) bool {
	for _, s := range scans {
		if s == target {
			return true
		}
	}
	return false
}

func ForMode(mode model.Mode) []Collector {
	return ForOptions(model.Options{Mode: mode})
}

func fact(id, category, source string, sensitive bool, value any) model.Fact {
	return model.Fact{
		ID:        id,
		Category:  category,
		Source:    source,
		Sensitive: sensitive,
		Value:     value,
	}
}

func errEntry(source string, err error) model.ErrorEntry {
	return model.ErrorEntry{Source: source, Message: err.Error()}
}

func envMap(values []string) map[string]string {
	out := make(map[string]string, len(values))
	for _, value := range values {
		key, val, ok := strings.Cut(value, "=")
		if ok {
			out[key] = val
		}
	}
	return out
}

func isSecretLike(name string) bool {
	name = strings.ToUpper(name)
	for _, marker := range []string{"TOKEN", "SECRET", "PASSWORD", "PASSWD", "PRIVATE", "CREDENTIAL", "API_KEY", "ACCESS_KEY"} {
		if strings.Contains(name, marker) {
			return true
		}
	}
	return false
}

func sha256HexString(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func sha256HexBytes(value []byte) string {
	sum := sha256.Sum256(value)
	return hex.EncodeToString(sum[:])
}
