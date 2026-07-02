package collectors

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/ekkoo-z/KubeTrail/internal/model"
)

var containerIDPattern = regexp.MustCompile(`(?i)([a-f0-9]{64}|[a-f0-9]{32})`)
var runtimeVersionPattern = regexp.MustCompile(`(?i)\bv?([0-9]+(?:\.[0-9]+){1,3}(?:[-+][0-9A-Za-z._-]+)?)`)

const runtimeSocketWalkLimit = 50000

var errRuntimeSocketWalkLimit = errors.New("runtime socket walk limit reached")

var runtimeSocketNames = map[string]string{
	"docker.sock":                 "docker",
	"docker.socket":               "docker",
	"cri-dockerd.sock":            "cri-dockerd",
	"dockershim.sock":             "dockershim",
	"containerd.sock":             "containerd",
	"containerd.sock.ttrpc":       "containerd",
	"crio.sock":                   "crio",
	"podman.sock":                 "podman",
	"kubelet.sock":                "kubelet",
	"buildkitd.sock":              "buildkit",
	"buildkit.sock":               "buildkit",
	"firecracker-containerd.sock": "firecracker-containerd",
	"frakti.sock":                 "frakti",
	"rktlet.sock":                 "rktlet",
}

var runtimeSocketSearchRoots = []string{
	"/run",
	"/var/run",
	"/var/lib",
	"/var/snap",
	"/snap",
	"/tmp",
	"/opt",
	"/mnt",
	"/host",
	"/rootfs",
}

var runtimeKnownSocketPaths = []string{
	"/var/run/docker.sock",
	"/run/docker.sock",
	"/var/run/docker.socket",
	"/run/docker.socket",
	"/var/run/cri-dockerd.sock",
	"/run/cri-dockerd.sock",
	"/var/run/dockershim.sock",
	"/run/dockershim.sock",
	"/run/containerd/containerd.sock",
	"/var/run/containerd/containerd.sock",
	"/run/containerd/containerd.sock.ttrpc",
	"/var/run/containerd/containerd.sock.ttrpc",
	"/var/run/crio/crio.sock",
	"/run/crio/crio.sock",
	"/run/podman/podman.sock",
	"/var/run/podman/podman.sock",
	"/run/user/0/podman/podman.sock",
	"/var/run/kubelet.sock",
	"/run/kubelet.sock",
	"/run/buildkit/buildkitd.sock",
	"/run/buildkit/buildkit.sock",
	"/run/firecracker-containerd/firecracker-containerd.sock",
}

func collectRuntimeLocal(ctx context.Context, cctx *Context) ([]model.Fact, []model.ErrorEntry) {
	var errs []model.ErrorEntry
	value := map[string]any{
		"runtimeHints": []string{},
		"containerIDs": []string{},
	}

	data, err := os.ReadFile(cctx.RootPath("/proc/self/cgroup"))
	if err != nil {
		errs = append(errs, errEntry("/proc/self/cgroup", err))
	} else {
		text := string(data)
		value["runtimeHints"] = runtimeHints(text)
		value["containerIDs"] = containerIDPattern.FindAllString(text, -1)
		value["cgroupEvidence"] = map[string]any{
			"rawBytes":  len(text),
			"rawSha256": sha256HexString(text),
		}
	}

	sockets, socketSearch := enumerateRuntimeSockets(ctx, cctx)
	value["socketCount"] = len(sockets)
	if len(sockets) > 0 {
		value["socketPaths"] = runtimeSocketPaths(sockets)
	}
	value["socketSearch"] = compactRuntimeSocketSearch(socketSearch, len(sockets))
	versions := collectRuntimeVersions(ctx, cctx, sockets)

	facts := []model.Fact{
		fact("runtime.local", "runtime", "proc/filesystem", false, value),
		fact("runtime.sockets", "runtime", "filesystem", false, sockets),
	}
	if len(versions) > 0 {
		facts = append(facts, fact("runtime.versions", "runtime", "runtime version probes", false, versions))
	}
	return facts, errs
}

func runtimeHints(data string) []string {
	seen := map[string]bool{}
	for _, marker := range []string{"containerd", "docker", "cri-o", "crio", "kubepods", "podman"} {
		if strings.Contains(strings.ToLower(data), marker) {
			seen[marker] = true
		}
	}
	out := make([]string, 0, len(seen))
	for marker := range seen {
		out = append(out, marker)
	}
	return out
}

func runtimeSocketPaths(sockets []map[string]any) []string {
	paths := make([]string, 0, len(sockets))
	for _, socket := range sockets {
		path, _ := socket["path"].(string)
		if path != "" {
			paths = append(paths, path)
		}
	}
	sort.Strings(paths)
	return paths
}

func enumerateRuntimeSockets(ctx context.Context, cctx *Context) ([]map[string]any, map[string]any) {
	seen := map[string]map[string]any{}
	scanned := 0
	truncated := false

	addSocket := func(logical string) {
		name := filepath.Base(logical)
		runtimeKind, interesting := runtimeSocketNames[name]
		if !interesting {
			return
		}
		if _, ok := seen[logical]; ok {
			return
		}
		info, err := os.Stat(cctx.RootPath(logical))
		if err != nil || info.Mode()&os.ModeSocket == 0 {
			return
		}
		item := describeRuntimeSocket(logical, runtimeKind, info)
		if runtimeKind == "docker" {
			if dockerInfo, err := queryDockerInfo(ctx, cctx.RootPath(logical)); err == nil {
				item["dockerInfo"] = dockerInfo
			}
		}
		seen[logical] = item
	}

	for _, path := range runtimeKnownSocketPaths {
		addSocket(path)
	}
	for _, root := range runtimeSocketSearchRoots {
		rooted := cctx.RootPath(root)
		info, err := os.Stat(rooted)
		if err != nil || !info.IsDir() {
			continue
		}
		err = filepath.WalkDir(rooted, func(path string, entry os.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if ctx.Err() != nil {
				return ctx.Err()
			}
			scanned++
			if scanned > runtimeSocketWalkLimit {
				truncated = true
				return errRuntimeSocketWalkLimit
			}
			logical := logicalPath(cctx, path)
			if entry.IsDir() {
				if shouldPruneRuntimeSocketDir(logical) {
					return filepath.SkipDir
				}
				return nil
			}
			if _, ok := runtimeSocketNames[entry.Name()]; ok {
				addSocket(logical)
			}
			return nil
		})
		if errors.Is(err, errRuntimeSocketWalkLimit) {
			break
		}
	}

	items := make([]map[string]any, 0, len(seen))
	for _, item := range seen {
		items = append(items, item)
	}
	sort.Slice(items, func(i, j int) bool {
		pi, _ := items[i]["path"].(string)
		pj, _ := items[j]["path"].(string)
		return pi < pj
	})
	return items, map[string]any{
		"roots":          runtimeSocketSearchRoots,
		"knownPaths":     runtimeKnownSocketPaths,
		"scannedEntries": scanned,
		"truncated":      truncated,
		"socketNames":    sortedRuntimeSocketNames(),
	}
}

func compactRuntimeSocketSearch(search map[string]any, matchedCount int) map[string]any {
	out := map[string]any{
		"matchedCount":    matchedCount,
		"scannedEntries":  search["scannedEntries"],
		"truncated":       search["truncated"],
		"knownPathCount":  len(runtimeKnownSocketPaths),
		"rootCount":       len(runtimeSocketSearchRoots),
		"socketNameCount": len(runtimeSocketNames),
	}
	if truncated, _ := search["truncated"].(bool); truncated {
		out["walkLimit"] = runtimeSocketWalkLimit
	}
	return out
}

func shouldPruneRuntimeSocketDir(path string) bool {
	switch path {
	case "/proc", "/sys", "/dev/fd", "/dev/pts":
		return true
	default:
		return false
	}
}

func sortedRuntimeSocketNames() []string {
	names := make([]string, 0, len(runtimeSocketNames))
	for name := range runtimeSocketNames {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func describeRuntimeSocket(path, runtimeKind string, info os.FileInfo) map[string]any {
	uid, gid, hasOwner := fileOwnerIDs(info)
	item := map[string]any{
		"path":                  path,
		"name":                  filepath.Base(path),
		"runtime":               runtimeKind,
		"mode":                  info.Mode().String(),
		"writableByCurrentUser": writableByCurrentUser(info),
		"confidence":            "high",
	}
	if hasOwner {
		item["uid"] = uid
		item["gid"] = gid
	}
	return item
}

func queryDockerInfo(ctx context.Context, socketPath string) (map[string]any, error) {
	reqCtx, cancel := context.WithTimeout(ctx, 1500*time.Millisecond)
	defer cancel()

	dialer := net.Dialer{Timeout: 1200 * time.Millisecond}
	transport := &http.Transport{
		DialContext: func(context.Context, string, string) (net.Conn, error) {
			return dialer.DialContext(reqCtx, "unix", socketPath)
		},
	}
	defer transport.CloseIdleConnections()
	client := http.Client{Transport: transport, Timeout: 1500 * time.Millisecond}
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, "http://unix/info", nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, err
	}
	out := map[string]any{
		"statusCode": resp.StatusCode,
	}
	for _, key := range []string{"Architecture", "OSType", "Name", "DockerRootDir", "NCPU", "OperatingSystem", "KernelVersion", "ServerVersion", "SecurityOptions"} {
		if value, ok := raw[key]; ok {
			out[key] = value
		}
	}
	if securityOptions, ok := raw["SecurityOptions"].([]any); ok {
		for _, option := range securityOptions {
			if strings.Contains(strings.ToLower(strings.TrimSpace(toString(option))), "rootless") {
				out["Rootless"] = true
				break
			}
		}
	}
	return out, nil
}

func collectRuntimeVersions(ctx context.Context, cctx *Context, sockets []map[string]any) []map[string]any {
	var out []map[string]any
	seen := map[string]bool{}
	add := func(item map[string]any) {
		name := toString(item["name"])
		version := toString(item["version"])
		source := toString(item["source"])
		if name == "" || version == "" {
			return
		}
		key := name + "\x00" + version + "\x00" + source + "\x00" + toString(item["socket"])
		if seen[key] {
			return
		}
		seen[key] = true
		out = append(out, item)
	}

	for _, socket := range sockets {
		info, _ := socket["dockerInfo"].(map[string]any)
		if info == nil {
			continue
		}
		version := toString(info["ServerVersion"])
		if version == "" {
			continue
		}
		add(map[string]any{
			"name":    "docker",
			"version": version,
			"source":  "docker_api",
			"socket":  socket["path"],
			"details": info,
		})
	}

	if data, ok, err := readOptionalText(cctx, "/etc/alpine-release"); err == nil && ok {
		add(map[string]any{
			"name":    "alpine",
			"version": strings.TrimSpace(data),
			"source":  "/etc/alpine-release",
		})
	}

	for _, probe := range []struct {
		name string
		cmd  string
		args []string
	}{
		{"runc", "runc", []string{"--version"}},
		{"containerd", "containerd", []string{"--version"}},
		{"docker", "docker", []string{"--version"}},
	} {
		path, err := exec.LookPath(probe.cmd)
		if err != nil {
			continue
		}
		raw, err := runtimeCommandOutput(ctx, path, probe.args...)
		if err != nil {
			add(map[string]any{
				"name":   probe.name,
				"path":   path,
				"source": "cli",
				"error":  err.Error(),
			})
			continue
		}
		version := parseRuntimeVersion(raw)
		add(map[string]any{
			"name":    probe.name,
			"path":    path,
			"source":  "cli",
			"version": version,
			"raw":     raw,
		})
	}

	sort.Slice(out, func(i, j int) bool {
		ni, nj := toString(out[i]["name"]), toString(out[j]["name"])
		if ni == nj {
			return toString(out[i]["version"]) < toString(out[j]["version"])
		}
		return ni < nj
	})
	return out
}

func runtimeCommandOutput(ctx context.Context, path string, args ...string) (string, error) {
	cmdCtx, cancel := context.WithTimeout(ctx, 1200*time.Millisecond)
	defer cancel()
	cmd := exec.CommandContext(cmdCtx, path, args...)
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	if err := cmd.Run(); err != nil {
		return cleanOptionalText(buf.String()), err
	}
	return cleanOptionalText(buf.String()), nil
}

func parseRuntimeVersion(raw string) string {
	match := runtimeVersionPattern.FindStringSubmatch(raw)
	if len(match) < 2 {
		return ""
	}
	return match[1]
}

func toString(value any) string {
	switch v := value.(type) {
	case string:
		return v
	case []byte:
		return string(v)
	default:
		return ""
	}
}
