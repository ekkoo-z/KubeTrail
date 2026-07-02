package collectors

import (
	"compress/gzip"
	"context"
	"errors"
	"io"
	"os"
	"runtime"
	"sort"
	"strings"

	"github.com/ekkoo-z/KubeTrail/internal/model"
)

func collectLPE(_ context.Context, cctx *Context) ([]model.Fact, []model.ErrorEntry) {
	status := map[string]any{
		"uid":     os.Getuid(),
		"euid":    os.Geteuid(),
		"gid":     os.Getgid(),
		"egid":    os.Getegid(),
		"goos":    runtime.GOOS,
		"goarch":  runtime.GOARCH,
		"skipped": false,
	}
	if os.Geteuid() == 0 {
		status["skipped"] = true
		status["reason"] = "effective UID is 0; Linux local privilege escalation to root is not applicable"
		return []model.Fact{fact("lpe.status", "lpe", "process", false, status)}, nil
	}

	var facts []model.Fact
	var errs []model.ErrorEntry
	facts = append(facts, fact("lpe.status", "lpe", "process", false, status))
	mounts := readLPEMounts(cctx, &errs)

	if procStatus, err := readProcStatus(cctx.RootPath("/proc/self/status")); err == nil {
		facts = append(facts, fact("lpe.process_security", "lpe", "/proc/self/status", false, map[string]any{
			"capabilities": map[string]string{
				"effective":   procStatus["CapEff"],
				"permitted":   procStatus["CapPrm"],
				"inheritable": procStatus["CapInh"],
				"bounding":    procStatus["CapBnd"],
				"ambient":     procStatus["CapAmb"],
			},
			"noNewPrivs": procStatus["NoNewPrivs"],
			"seccomp":    procStatus["Seccomp"],
			"uid":        procStatus["Uid"],
			"gid":        procStatus["Gid"],
		}))
	} else if !errors.Is(err, os.ErrNotExist) {
		errs = append(errs, errEntry("/proc/self/status", err))
	}

	kernel, kernelErrs := collectLPEKernel(cctx)
	errs = append(errs, kernelErrs...)
	facts = append(facts, fact("lpe.kernel", "lpe", "kernel metadata", false, kernel))

	config, configErrs := collectLPEKernelConfig(cctx, kernel)
	errs = append(errs, configErrs...)
	if len(config) > 0 {
		facts = append(facts, fact("lpe.kernel_config", "lpe", "kernel config", false, config))
	}

	sysctls, sysctlErrs := collectLPESysctls(cctx)
	errs = append(errs, sysctlErrs...)
	if len(sysctls) > 0 {
		facts = append(facts, fact("lpe.sysctls", "lpe", "/proc/sys", false, sysctls))
	}

	modules, moduleErrs := collectLPEModules(cctx)
	errs = append(errs, moduleErrs...)
	facts = append(facts, fact("lpe.modules", "lpe", "/proc/modules,/sys/module", false, modules))

	tools := collectLPESUIDTools(cctx, mounts)
	if len(tools) > 0 {
		facts = append(facts, fact("lpe.suid_tools", "lpe", "filesystem", false, tools))
	}

	packages, packageErrs := collectLPEPackages(cctx)
	errs = append(errs, packageErrs...)
	if len(packages) > 0 {
		facts = append(facts, fact("lpe.packages", "lpe", "/var/lib/dpkg/status", false, map[string]any{
			"manager":  "dpkg",
			"packages": packages,
		}))
	}

	filesystems := collectLPEFilesystems(mounts)
	if len(filesystems) > 0 {
		facts = append(facts, fact("lpe.filesystems", "lpe", "/proc/mounts", false, filesystems))
	}

	return facts, errs
}

func collectLPEKernel(cctx *Context) (map[string]any, []model.ErrorEntry) {
	value := map[string]any{
		"goos":   runtime.GOOS,
		"goarch": runtime.GOARCH,
	}
	var errs []model.ErrorEntry

	if release, ok, err := readOptionalText(cctx, "/proc/sys/kernel/osrelease"); err != nil {
		errs = append(errs, errEntry("/proc/sys/kernel/osrelease", err))
	} else if ok {
		value["release"] = strings.TrimSpace(release)
	}
	if version, ok, err := readOptionalText(cctx, "/proc/version"); err != nil {
		errs = append(errs, errEntry("/proc/version", err))
	} else if ok {
		value["version"] = strings.TrimSpace(version)
	}
	if osRelease, ok, err := readOptionalText(cctx, "/etc/os-release"); err != nil {
		errs = append(errs, errEntry("/etc/os-release", err))
	} else if ok {
		value["osRelease"] = parseOSRelease(osRelease)
	}

	return value, errs
}

func collectLPEKernelConfig(cctx *Context, kernel map[string]any) (map[string]any, []model.ErrorEntry) {
	release, _ := kernel["release"].(string)
	candidates := []string{"/proc/config.gz"}
	if release != "" {
		candidates = append(candidates,
			"/boot/config-"+release,
			"/lib/modules/"+release+"/config",
			"/usr/lib/modules/"+release+"/config",
		)
	}

	keys := map[string]bool{
		"CONFIG_BPF_SYSCALL":              true,
		"CONFIG_CRYPTO_AUTHENC":           true,
		"CONFIG_CRYPTO_USER_API_AEAD":     true,
		"CONFIG_FUSE_FS":                  true,
		"CONFIG_INET6_ESP":                true,
		"CONFIG_INET_ESP":                 true,
		"CONFIG_INIT_ON_ALLOC_DEFAULT_ON": true,
		"CONFIG_NF_TABLES":                true,
		"CONFIG_OVERLAY_FS":               true,
		"CONFIG_RXRPC":                    true,
		"CONFIG_USER_NS":                  true,
		"CONFIG_XFRM":                     true,
	}

	var errs []model.ErrorEntry
	for _, candidate := range candidates {
		data, ok, err := readOptionalKernelConfig(cctx, candidate)
		if err != nil {
			errs = append(errs, errEntry(candidate, err))
			continue
		}
		if !ok {
			continue
		}
		values := parseKernelConfig(data, keys)
		if len(values) == 0 {
			continue
		}
		return map[string]any{
			"source": candidate,
			"values": values,
		}, errs
	}
	return nil, errs
}

func collectLPESysctls(cctx *Context) (map[string]string, []model.ErrorEntry) {
	probes := []struct {
		key  string
		path string
	}{
		{"kernel.unprivileged_userns_clone", "/proc/sys/kernel/unprivileged_userns_clone"},
		{"user.max_user_namespaces", "/proc/sys/user/max_user_namespaces"},
		{"kernel.unprivileged_bpf_disabled", "/proc/sys/kernel/unprivileged_bpf_disabled"},
		{"kernel.kptr_restrict", "/proc/sys/kernel/kptr_restrict"},
		{"kernel.dmesg_restrict", "/proc/sys/kernel/dmesg_restrict"},
		{"kernel.yama.ptrace_scope", "/proc/sys/kernel/yama/ptrace_scope"},
	}

	values := map[string]string{}
	var errs []model.ErrorEntry
	for _, probe := range probes {
		data, ok, err := readOptionalText(cctx, probe.path)
		if err != nil {
			errs = append(errs, errEntry(probe.path, err))
			continue
		}
		if ok {
			values[probe.key] = strings.TrimSpace(data)
		}
	}
	return values, errs
}

func collectLPEModules(cctx *Context) (map[string]any, []model.ErrorEntry) {
	const maxModules = 512
	interesting := []string{
		"nf_tables",
		"overlay",
		"fuse",
		"bpf",
		"ip_tables",
		"xfrm_user",
		"algif_aead",
		"authenc",
		"crypto_user",
		"esp4",
		"esp6",
		"rxrpc",
	}
	loaded := map[string]bool{}
	var names []string
	var errs []model.ErrorEntry

	if data, ok, err := readOptionalText(cctx, "/proc/modules"); err != nil {
		errs = append(errs, errEntry("/proc/modules", err))
	} else if ok {
		names = parseModuleNames(data, maxModules)
		for _, name := range names {
			loaded[name] = true
		}
	}

	var present []string
	for _, name := range interesting {
		if loaded[name] || fileExists(cctx.RootPath("/sys/module/"+name)) {
			present = append(present, name)
		}
	}

	return map[string]any{
		"loadedNames": names,
		"present":     present,
	}, errs
}

func collectLPESUIDTools(cctx *Context, mounts []map[string]any) []map[string]any {
	probes := []struct {
		name  string
		paths []string
	}{
		{"pkexec", []string{"/usr/bin/pkexec", "/usr/local/bin/pkexec"}},
		{"sudo", []string{"/usr/bin/sudo", "/bin/sudo", "/usr/local/bin/sudo"}},
		{"sudoedit", []string{"/usr/bin/sudoedit", "/bin/sudoedit", "/usr/local/bin/sudoedit"}},
		{"fusermount", []string{"/usr/bin/fusermount", "/usr/bin/fusermount3", "/bin/fusermount"}},
		{"screen", []string{"/usr/bin/screen", "/bin/screen"}},
	}

	var out []map[string]any
	for _, probe := range probes {
		for _, path := range probe.paths {
			info, err := os.Stat(cctx.RootPath(path))
			if err != nil {
				continue
			}
			mode := info.Mode()
			item := map[string]any{
				"name":   probe.name,
				"path":   path,
				"mode":   mode.String(),
				"setuid": mode&os.ModeSetuid != 0,
				"setgid": mode&os.ModeSetgid != 0,
				"isDir":  info.IsDir(),
			}
			if mount := mostSpecificMount(path, mounts); mount != nil {
				options, _ := mount["options"].([]string)
				item["mountPath"] = mount["path"]
				item["mountFsType"] = mount["fsType"]
				item["mountOptions"] = options
				item["nosuid"] = hasOption(options, "nosuid")
			}
			out = append(out, item)
		}
	}
	return out
}

func collectLPEPackages(cctx *Context) ([]map[string]string, []model.ErrorEntry) {
	data, ok, err := readOptionalText(cctx, "/var/lib/dpkg/status")
	if err != nil {
		return nil, []model.ErrorEntry{errEntry("/var/lib/dpkg/status", err)}
	}
	if !ok {
		return nil, nil
	}

	wanted := map[string]bool{
		"policykit-1": true,
		"polkit":      true,
		"polkitd":     true,
		"packagekit":  true,
		"sudo":        true,
		"snapd":       true,
		"screen":      true,
	}
	return parseDpkgStatus(data, wanted), nil
}

func readLPEMounts(cctx *Context, errs *[]model.ErrorEntry) []map[string]any {
	data, ok, err := readOptionalText(cctx, "/proc/mounts")
	if err != nil {
		*errs = append(*errs, errEntry("/proc/mounts", err))
		return nil
	}
	if !ok {
		return nil
	}
	return parseMounts(data)
}

func collectLPEFilesystems(mounts []map[string]any) map[string]any {
	value := map[string]any{}
	for _, mount := range mounts {
		path, _ := mount["path"].(string)
		fsType, _ := mount["fsType"].(string)
		opts, _ := mount["options"].([]string)
		if path == "/" {
			value["rootFsType"] = fsType
			value["rootOptions"] = opts
			value["rootNosuid"] = hasOption(opts, "nosuid")
		}
		if fsType == "overlay" {
			value["hasOverlay"] = true
		}
		if fsType == "fuse" || strings.HasPrefix(fsType, "fuse.") {
			value["hasFuse"] = true
		}
	}
	return value
}

func readOptionalText(cctx *Context, path string) (string, bool, error) {
	data, err := os.ReadFile(cctx.RootPath(path))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", false, nil
		}
		return "", false, err
	}
	return string(data), true, nil
}

func readOptionalKernelConfig(cctx *Context, path string) (string, bool, error) {
	data, ok, err := readOptionalBytes(cctx, path)
	if err != nil || !ok {
		return "", ok, err
	}
	if strings.HasSuffix(path, ".gz") {
		r, err := gzip.NewReader(strings.NewReader(string(data)))
		if err != nil {
			return "", true, err
		}
		defer r.Close()
		decoded, err := io.ReadAll(io.LimitReader(r, 2<<20))
		if err != nil {
			return "", true, err
		}
		return string(decoded), true, nil
	}
	return string(data), true, nil
}

func readOptionalBytes(cctx *Context, path string) ([]byte, bool, error) {
	data, err := os.ReadFile(cctx.RootPath(path))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, false, nil
		}
		return nil, false, err
	}
	return data, true, nil
}

func parseModuleNames(data string, max int) []string {
	var out []string
	for _, line := range strings.Split(strings.TrimSpace(data), "\n") {
		if len(out) >= max {
			break
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		out = append(out, fields[0])
	}
	return out
}

func parseKernelConfig(data string, keys map[string]bool) map[string]string {
	out := map[string]string{}
	for _, line := range strings.Split(data, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "# ") && strings.HasSuffix(line, " is not set") {
			key := strings.TrimSuffix(strings.TrimPrefix(line, "# "), " is not set")
			if keys[key] {
				out[key] = "n"
			}
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok || !keys[key] {
			continue
		}
		out[key] = strings.Trim(value, `"`)
	}
	return out
}

func parseOSRelease(data string) map[string]string {
	out := map[string]string{}
	for _, line := range strings.Split(data, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		out[key] = strings.Trim(strings.TrimSpace(value), `"`)
	}
	return out
}

func parseDpkgStatus(data string, wanted map[string]bool) []map[string]string {
	var out []map[string]string
	current := map[string]string{}

	flush := func() {
		name := current["Package"]
		if name == "" || !wanted[name] {
			current = map[string]string{}
			return
		}
		status := current["Status"]
		if status != "" && !dpkgStatusIsInstalled(status) {
			current = map[string]string{}
			return
		}
		item := map[string]string{
			"name":    name,
			"version": current["Version"],
			"status":  status,
		}
		if arch := current["Architecture"]; arch != "" {
			item["architecture"] = arch
		}
		out = append(out, item)
		current = map[string]string{}
	}

	for _, line := range strings.Split(data, "\n") {
		if strings.TrimSpace(line) == "" {
			flush()
			continue
		}
		if strings.HasPrefix(line, " ") || strings.HasPrefix(line, "\t") {
			continue
		}
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		current[key] = strings.TrimSpace(value)
	}
	flush()

	sort.Slice(out, func(i, j int) bool {
		return out[i]["name"] < out[j]["name"]
	})
	return out
}

func dpkgStatusIsInstalled(status string) bool {
	fields := strings.Fields(status)
	return len(fields) == 3 && fields[1] == "ok" && fields[2] == "installed"
}
