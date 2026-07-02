package collectors

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/ekkoo-z/KubeTrail/internal/model"
)

func collectProcSysEscape(_ context.Context, cctx *Context) ([]model.Fact, []model.ErrorEntry) {
	var errs []model.ErrorEntry
	mounts := readMountsForProbe(cctx)
	value := map[string]any{
		"cgroup":             collectCgroupBreakoutSurfaces(cctx, mounts),
		"kernelHelperPaths":  collectKernelHelperPathSurfaces(cctx, mounts),
		"sensitiveExposures": collectSensitiveProcSysExposures(cctx, mounts),
		"securityProfiles":   collectLinuxSecurityProfiles(cctx),
		"userNamespace":      collectUserNamespaceMappings(cctx),
		"hostVisibility":     collectHostVisibilitySignals(cctx),
	}
	return []model.Fact{fact("proc_sys.breakout_surfaces", "process", "/proc,/sys,/sys/fs/cgroup", false, value)}, errs
}

func readMountsForProbe(cctx *Context) []map[string]any {
	data, err := os.ReadFile(cctx.RootPath("/proc/mounts"))
	if err != nil {
		return nil
	}
	return parseMounts(string(data))
}

func collectCgroupBreakoutSurfaces(cctx *Context, mounts []map[string]any) map[string]any {
	releaseAgents := []map[string]any{}
	root := cctx.RootPath("/sys/fs/cgroup")
	_ = filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil || entry == nil {
			return nil
		}
		if entry.IsDir() {
			return nil
		}
		if entry.Name() != "release_agent" {
			return nil
		}
		releaseAgents = append(releaseAgents, probeLogicalPath(cctx, logicalPath(cctx, path), mounts))
		return nil
	})
	sort.Slice(releaseAgents, func(i, j int) bool {
		return toString(releaseAgents[i]["path"]) < toString(releaseAgents[j]["path"])
	})

	writableMounts := cgroupWritability(mounts)
	return map[string]any{
		"releaseAgents":        releaseAgents,
		"releaseAgentPresent":  len(releaseAgents) > 0,
		"writableCgroupMounts": writableMounts,
	}
}

func collectKernelHelperPathSurfaces(cctx *Context, mounts []map[string]any) map[string]any {
	paths := []struct {
		id   string
		path string
	}{
		{"core_pattern", "/proc/sys/kernel/core_pattern"},
		{"modprobe", "/proc/sys/kernel/modprobe"},
		{"panic_on_oom", "/proc/sys/vm/panic_on_oom"},
		{"suid_dumpable", "/proc/sys/fs/suid_dumpable"},
		{"binfmt_misc_register", "/proc/sys/fs/binfmt_misc/register"},
		{"uevent_helper", "/sys/kernel/uevent_helper"},
		{"sysrq_trigger", "/proc/sysrq-trigger"},
	}
	out := map[string]any{}
	for _, item := range paths {
		out[item.id] = probeLogicalPath(cctx, item.path, mounts)
	}
	if data, ok, err := readOptionalText(cctx, "/proc/sys/kernel/modprobe"); err == nil && ok {
		out["modprobeBinary"] = strings.TrimSpace(data)
	}
	return out
}

func collectSensitiveProcSysExposures(cctx *Context, mounts []map[string]any) map[string]any {
	paths := []struct {
		id   string
		path string
	}{
		{"proc_config_gz", "/proc/config.gz"},
		{"proc_sched_debug", "/proc/sched_debug"},
		{"proc_mountinfo_any", "/proc/self/mountinfo"},
		{"proc_keys", "/proc/keys"},
		{"proc_timer_list", "/proc/timer_list"},
		{"proc_kmsg", "/proc/kmsg"},
		{"proc_kallsyms", "/proc/kallsyms"},
		{"proc_self_mem", "/proc/self/mem"},
		{"proc_kcore", "/proc/kcore"},
		{"proc_kmem", "/proc/kmem"},
		{"proc_mem", "/proc/mem"},
		{"sys_firmware", "/sys/firmware"},
		{"sys_kernel_debug", "/sys/kernel/debug"},
		{"sys_kernel_security", "/sys/kernel/security"},
		{"sys_kernel_vmcoreinfo", "/sys/kernel/vmcoreinfo"},
		{"efi_vars", "/sys/firmware/efi/vars"},
		{"efi_efivars", "/sys/firmware/efi/efivars"},
	}
	out := map[string]any{}
	for _, item := range paths {
		out[item.id] = probeLogicalPath(cctx, item.path, mounts)
	}
	return out
}

func collectLinuxSecurityProfiles(cctx *Context) map[string]any {
	out := map[string]any{
		"apparmor": map[string]any{},
		"selinux":  map[string]any{},
	}
	if data, ok, err := readOptionalText(cctx, "/proc/self/attr/current"); err == nil && ok {
		current := cleanOptionalText(data)
		if strings.Count(current, ":") >= 2 {
			out["selinuxContext"] = current
			selinux := out["selinux"].(map[string]any)
			selinux["context"] = current
		} else {
			out["apparmorProfile"] = current
			apparmor := out["apparmor"].(map[string]any)
			apparmor["profile"] = current
			apparmor["unconfined"] = strings.Contains(strings.ToLower(current), "unconfined")
		}
	}
	if data, ok, err := readOptionalText(cctx, "/sys/module/apparmor/parameters/enabled"); err == nil && ok {
		apparmor := out["apparmor"].(map[string]any)
		value := strings.TrimSpace(data)
		apparmor["enabledRaw"] = value
		apparmor["enabled"] = strings.EqualFold(value, "Y") || strings.EqualFold(value, "yes") || value == "1"
	}
	if fileExists(cctx.RootPath("/sys/kernel/security/apparmor/profiles")) {
		apparmor := out["apparmor"].(map[string]any)
		apparmor["profilesFilePresent"] = true
	}
	selinux := out["selinux"].(map[string]any)
	if _, err := os.Stat(cctx.RootPath("/sys/fs/selinux")); err == nil {
		selinux["present"] = true
	} else if errors.Is(err, os.ErrNotExist) {
		selinux["present"] = false
	}
	if data, ok, err := readOptionalText(cctx, "/sys/fs/selinux/enforce"); err == nil && ok {
		enforce := strings.TrimSpace(data)
		selinux["enforceRaw"] = enforce
		switch enforce {
		case "1":
			selinux["mode"] = "Enforcing"
		case "0":
			selinux["mode"] = "Permissive"
		default:
			selinux["mode"] = "unknown"
		}
	} else if present, _ := selinux["present"].(bool); !present {
		selinux["mode"] = "Disabled"
	}
	return out
}

func collectUserNamespaceMappings(cctx *Context) map[string]any {
	uidMapText, _, _ := readOptionalText(cctx, "/proc/self/uid_map")
	gidMapText, _, _ := readOptionalText(cctx, "/proc/self/gid_map")
	setgroups, _, _ := readOptionalText(cctx, "/proc/self/setgroups")
	uidMap := parseIDMap(uidMapText)
	gidMap := parseIDMap(gidMapText)
	initial := idMapInitialUserNamespace(uidMap)
	return map[string]any{
		"uidMapRaw":                 cleanOptionalText(uidMapText),
		"gidMapRaw":                 cleanOptionalText(gidMapText),
		"uidMap":                    uidMap,
		"gidMap":                    gidMap,
		"setgroups":                 strings.TrimSpace(setgroups),
		"initialUserNamespace":      initial,
		"remappedUserNamespace":     len(uidMap) > 0 && !initial,
		"containerRootMapsHostRoot": idMapRootMapsHostRoot(uidMap),
	}
}

func parseIDMap(data string) []map[string]any {
	var out []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 3 {
			continue
		}
		containerID, err1 := strconv.ParseUint(fields[0], 10, 64)
		hostID, err2 := strconv.ParseUint(fields[1], 10, 64)
		size, err3 := strconv.ParseUint(fields[2], 10, 64)
		if err1 != nil || err2 != nil || err3 != nil {
			continue
		}
		out = append(out, map[string]any{
			"containerID": containerID,
			"hostID":      hostID,
			"size":        size,
		})
	}
	return out
}

func idMapInitialUserNamespace(items []map[string]any) bool {
	if len(items) != 1 {
		return false
	}
	return uint64FromMap(items[0], "containerID") == 0 &&
		uint64FromMap(items[0], "hostID") == 0 &&
		uint64FromMap(items[0], "size") >= 4294967295
}

func idMapRootMapsHostRoot(items []map[string]any) bool {
	for _, item := range items {
		if uint64FromMap(item, "containerID") == 0 && uint64FromMap(item, "hostID") == 0 {
			return true
		}
	}
	return false
}

func uint64FromMap(item map[string]any, key string) uint64 {
	switch value := item[key].(type) {
	case uint64:
		return value
	case int:
		return uint64(value)
	default:
		return 0
	}
}

func collectHostVisibilitySignals(cctx *Context) map[string]any {
	processCount, processNames := visibleHostProcessSignals(cctx)
	charDevices := charDeviceCount(cctx.RootPath("/dev"))
	return map[string]any{
		"procPidCount":            processCount,
		"hostLikeProcesses":       processNames,
		"devCharDeviceCount":      charDevices,
		"procHeavilyPopulated":    processCount > 50,
		"devHeavilyPopulated":     charDevices > 50,
		"hostVisibilityHeuristic": processCount > 50 || len(processNames) > 0 || charDevices > 50,
	}
}

func visibleHostProcessSignals(cctx *Context) (int, []string) {
	entries, err := os.ReadDir(cctx.RootPath("/proc"))
	if err != nil {
		return 0, nil
	}
	interesting := map[string]bool{
		"systemd": true, "init": true, "kthreadd": true, "dockerd": true, "containerd": true,
		"kubelet": true, "sshd": true, "udevd": true, "NetworkManager": true, "dbus-daemon": true,
	}
	seen := map[string]bool{}
	count := 0
	for _, entry := range entries {
		if !isNumeric(entry.Name()) {
			continue
		}
		count++
		if count > 512 {
			continue
		}
		data, err := os.ReadFile(cctx.RootPath("/proc/" + entry.Name() + "/comm"))
		if err != nil {
			continue
		}
		name := strings.TrimSpace(string(data))
		if interesting[name] {
			seen[name] = true
		}
	}
	names := make([]string, 0, len(seen))
	for name := range seen {
		names = append(names, name)
	}
	sort.Strings(names)
	return count, names
}

func charDeviceCount(path string) int {
	entries, err := os.ReadDir(path)
	if err != nil {
		return 0
	}
	count := 0
	for _, entry := range entries {
		info, err := entry.Info()
		if err == nil && info.Mode()&os.ModeCharDevice != 0 {
			count++
		}
	}
	return count
}

func isNumeric(value string) bool {
	if value == "" {
		return false
	}
	for _, r := range value {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func probeLogicalPath(cctx *Context, path string, mounts []map[string]any) map[string]any {
	item := map[string]any{
		"path":    path,
		"present": false,
	}
	info, err := os.Stat(cctx.RootPath(path))
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			item["error"] = err.Error()
		}
		return item
	}
	item["present"] = true
	item["mode"] = info.Mode().String()
	item["isDir"] = info.IsDir()
	item["readableByCurrentUser"] = readableByCurrentUser(info)
	item["writableByCurrentUser"] = writableByCurrentUser(info)
	if uid, gid, ok := fileOwnerIDs(info); ok {
		item["uid"] = uid
		item["gid"] = gid
	}
	if mount := mostSpecificMount(path, mounts); mount != nil {
		item["mount"] = map[string]any{
			"path":    mount["path"],
			"fsType":  mount["fsType"],
			"options": mount["options"],
		}
		options, _ := mount["options"].([]string)
		mountRW := hasOption(options, "rw") && !hasOption(options, "ro")
		item["mountReadWrite"] = mountRW
		item["writableLikely"] = mountRW && writableByCurrentUser(info)
	} else {
		item["writableLikely"] = writableByCurrentUser(info)
	}
	return item
}

func mostSpecificMount(path string, mounts []map[string]any) map[string]any {
	var best map[string]any
	bestLen := -1
	for _, mount := range mounts {
		mountPath, _ := mount["path"].(string)
		if mountPath == "" {
			continue
		}
		if mountPath != "/" && path != mountPath && !strings.HasPrefix(path, strings.TrimRight(mountPath, "/")+"/") {
			continue
		}
		if mountPath == "/" || path == mountPath || strings.HasPrefix(path, strings.TrimRight(mountPath, "/")+"/") {
			if len(mountPath) > bestLen {
				best = mount
				bestLen = len(mountPath)
			}
		}
	}
	return best
}
