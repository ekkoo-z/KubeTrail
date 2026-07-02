package collectors

import (
	"context"
	"os"
	"reflect"
	"strings"

	"github.com/ekkoo-z/KubeTrail/internal/model"
)

func collectFilesystem(_ context.Context, cctx *Context) ([]model.Fact, []model.ErrorEntry) {
	var facts []model.Fact
	var errs []model.ErrorEntry

	devices, err := summarizeDevices(cctx.RootPath("/dev"), 512)
	if err != nil {
		errs = append(errs, errEntry("/dev", err))
	} else {
		facts = append(facts, fact("filesystem.devices", "filesystem", "/dev", false, devices))
	}

	facts = append(facts, fact("filesystem.container_hints", "filesystem", "/", false, map[string]any{
		"rootInodeIs2":     inodeIsRoot(cctx.RootPath("/")),
		"rootOverlay":      rootIsOverlay(cctx),
		"fstabEmpty":       fileEmpty(cctx.RootPath("/etc/fstab")),
		"bootEmpty":        dirEmpty(cctx.RootPath("/boot")),
		"containerEnvFile": fileExists(cctx.RootPath("/.dockerenv")),
	}))

	runtimeSockets := findExisting(cctx, []string{
		"/var/run/docker.sock",
		"/run/docker.sock",
		"/run/containerd/containerd.sock",
		"/var/run/containerd/containerd.sock",
		"/var/run/crio/crio.sock",
		"/run/crio/crio.sock",
		"/var/run/cri-dockerd.sock",
	})
	if len(runtimeSockets) > 0 {
		facts = append(facts, fact("filesystem.runtime_sockets", "runtime", "filesystem", false, runtimeSockets))
	}

	if hints := volumeHints(cctx); len(hints) > 0 {
		facts = append(facts, fact("filesystem.volume_hints", "filesystem", "/proc/mounts", false, hints))
	}
	if data, err := os.ReadFile(cctx.RootPath("/proc/self/mountinfo")); err == nil {
		items := writableBindMountsWithoutNosuid(parseMountInfo(string(data)))
		facts = append(facts, fact("filesystem.writable_bind_mounts_without_nosuid", "filesystem", "/proc/self/mountinfo", false, map[string]any{
			"items": items,
			"count": len(items),
		}))
	} else if !os.IsNotExist(err) {
		errs = append(errs, errEntry("/proc/self/mountinfo", err))
	}
	return facts, errs
}

func summarizeDevices(path string, max int) (map[string]any, error) {
	entries, err := os.ReadDir(path)
	if err != nil {
		return nil, err
	}
	items := make([]map[string]any, 0)
	summary := map[string]any{
		"totalEntries":            len(entries),
		"scannedEntries":          0,
		"truncated":               false,
		"directories":             0,
		"characterDevices":        0,
		"blockDevices":            0,
		"sockets":                 0,
		"symlinks":                0,
		"ttyDevices":              0,
		"omittedLowSignalEntries": 0,
		"interestingEntries":      0,
	}
	for i, entry := range entries {
		if i >= max {
			summary["truncated"] = true
			break
		}
		info, err := entry.Info()
		if err != nil {
			continue
		}
		summary["scannedEntries"] = intFromSummary(summary, "scannedEntries") + 1
		updateDeviceSummary(summary, entry.Name(), info)
		reason := deviceInterestReason(entry.Name(), info)
		if reason == "" {
			summary["omittedLowSignalEntries"] = intFromSummary(summary, "omittedLowSignalEntries") + 1
			continue
		}
		summary["interestingEntries"] = intFromSummary(summary, "interestingEntries") + 1
		items = append(items, map[string]any{
			"name":   entry.Name(),
			"mode":   info.Mode().String(),
			"isDir":  info.IsDir(),
			"reason": reason,
		})
	}
	return map[string]any{
		"summary": summary,
		"items":   items,
	}, nil
}

func updateDeviceSummary(summary map[string]any, name string, info os.FileInfo) {
	mode := info.Mode()
	if info.IsDir() {
		summary["directories"] = intFromSummary(summary, "directories") + 1
	}
	if mode&os.ModeCharDevice != 0 {
		summary["characterDevices"] = intFromSummary(summary, "characterDevices") + 1
	}
	if mode&os.ModeDevice != 0 && mode&os.ModeCharDevice == 0 {
		summary["blockDevices"] = intFromSummary(summary, "blockDevices") + 1
	}
	if mode&os.ModeSocket != 0 {
		summary["sockets"] = intFromSummary(summary, "sockets") + 1
	}
	if mode&os.ModeSymlink != 0 {
		summary["symlinks"] = intFromSummary(summary, "symlinks") + 1
	}
	if isTTYDeviceName(name) {
		summary["ttyDevices"] = intFromSummary(summary, "ttyDevices") + 1
	}
}

func deviceInterestReason(name string, info os.FileInfo) string {
	mode := info.Mode()
	if mode&os.ModeSocket != 0 {
		return "socket"
	}
	if mode&os.ModeDevice != 0 && mode&os.ModeCharDevice == 0 {
		return "block_device"
	}
	switch strings.ToLower(name) {
	case "btrfs-control", "crash", "fuse", "kcore", "kmem", "kmsg", "kvm", "loop-control",
		"mem", "nvram", "oldmem", "port", "ppp", "raw", "snapshot", "tun", "uhid", "uinput",
		"vhost-net", "vhost-vsock":
		return "sensitive_device"
	case "mapper", "net", "vfio", "virtio-ports":
		return "sensitive_device_directory"
	default:
		return ""
	}
}

func isTTYDeviceName(name string) bool {
	if name == "tty" {
		return true
	}
	if strings.HasPrefix(name, "ttyS") {
		return isDecimalString(name[4:])
	}
	if strings.HasPrefix(name, "tty") {
		return isDecimalString(name[3:])
	}
	return false
}

func isDecimalString(value string) bool {
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

func intFromSummary(summary map[string]any, key string) int {
	value, _ := summary[key].(int)
	return value
}

func inodeIsRoot(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	sys := reflect.ValueOf(info.Sys())
	if !sys.IsValid() {
		return false
	}
	if sys.Kind() == reflect.Pointer {
		sys = sys.Elem()
	}
	if !sys.IsValid() {
		return false
	}
	field := sys.FieldByName("Ino")
	if !field.IsValid() {
		return false
	}
	switch field.Kind() {
	case reflect.Uint64, reflect.Uint32, reflect.Uint, reflect.Uintptr:
		return field.Uint() == 2
	case reflect.Int64, reflect.Int32, reflect.Int:
		return field.Int() == 2
	default:
		return false
	}
}

func rootIsOverlay(cctx *Context) bool {
	data, err := os.ReadFile(cctx.RootPath("/proc/mounts"))
	if err != nil {
		return false
	}
	for _, mount := range parseMounts(string(data)) {
		if mount["path"] == "/" && mount["fsType"] == "overlay" {
			return true
		}
	}
	return false
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func fileEmpty(path string) bool {
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(data)) == ""
}

func dirEmpty(path string) bool {
	entries, err := os.ReadDir(path)
	if err != nil {
		return false
	}
	return len(entries) == 0
}

func findExisting(cctx *Context, paths []string) []map[string]any {
	out := make([]map[string]any, 0)
	for _, path := range paths {
		info, err := os.Stat(cctx.RootPath(path))
		if err != nil {
			continue
		}
		out = append(out, map[string]any{
			"path":  path,
			"mode":  info.Mode().String(),
			"isDir": info.IsDir(),
		})
	}
	return out
}

func volumeHints(cctx *Context) []map[string]any {
	data, err := os.ReadFile(cctx.RootPath("/proc/mounts"))
	if err != nil {
		return nil
	}
	var out []map[string]any
	for _, mount := range parseMounts(string(data)) {
		path, _ := mount["path"].(string)
		device, _ := mount["device"].(string)
		kind := volumeKind(path, device)
		if kind == "" {
			continue
		}
		out = append(out, map[string]any{
			"path":   path,
			"device": device,
			"fsType": mount["fsType"],
			"kind":   kind,
		})
	}
	return out
}

func volumeKind(path, device string) string {
	value := strings.ToLower(path + " " + device)
	switch {
	case strings.Contains(value, "kubernetes.io~secret"):
		return "secret"
	case strings.Contains(value, "kubernetes.io~configmap"):
		return "configmap"
	case strings.Contains(value, "kubernetes.io~projected"):
		return "projected"
	case strings.Contains(value, "kubernetes.io~empty-dir"):
		return "emptyDir"
	case strings.Contains(value, "kubernetes.io~host-path"):
		return "hostPath"
	case strings.Contains(value, "serviceaccount"):
		return "serviceAccount"
	case strings.Contains(value, "kubernetes.io~csi") || strings.Contains(value, "/plugins/kubernetes.io/csi/") || strings.Contains(value, "kubernetes.io/csi"):
		return "csi"
	case strings.Contains(value, "nfs"):
		return "nfs"
	default:
		return ""
	}
}

func writableBindMountsWithoutNosuid(mounts []map[string]any) []map[string]any {
	var out []map[string]any
	for _, mount := range mounts {
		options, _ := mount["options"].([]string)
		superOptions, _ := mount["superOptions"].([]string)
		if !hasOption(options, "rw") || hasAnyOption(options, "nosuid") || hasAnyOption(superOptions, "nosuid") {
			continue
		}
		fsType, _ := mount["fsType"].(string)
		if isPseudoMountFSType(fsType) {
			continue
		}
		confidence, reason := bindMountConfidence(mount)
		if confidence == "" {
			continue
		}
		item := map[string]any{
			"path":         mount["path"],
			"root":         mount["root"],
			"source":       mount["source"],
			"fsType":       fsType,
			"options":      options,
			"superOptions": superOptions,
			"confidence":   confidence,
			"reason":       reason,
		}
		if optional, ok := mount["optional"].([]string); ok {
			item["optional"] = optional
		}
		out = append(out, item)
	}
	return out
}

func bindMountConfidence(mount map[string]any) (string, string) {
	options, _ := mount["options"].([]string)
	optional, _ := mount["optional"].([]string)
	root, _ := mount["root"].(string)
	path, _ := mount["path"].(string)
	source, _ := mount["source"].(string)
	joined := strings.ToLower(strings.Join(append(append([]string{}, options...), optional...), ","))
	lowerEvidence := strings.ToLower(root + " " + path + " " + source)
	switch {
	case strings.Contains(joined, "bind"):
		return "high", "mountinfo contains bind marker"
	case strings.Contains(lowerEvidence, "kubernetes.io~host-path"):
		return "high", "Kubernetes hostPath mount source/root"
	case strings.Contains(lowerEvidence, "/var/lib/kubelet/pods/") && strings.Contains(lowerEvidence, "host"):
		return "high", "kubelet pod host-backed mount path"
	case root != "/" && strings.HasPrefix(root, "/"):
		return "medium", "mount root is a subpath; bind-like but not explicitly marked"
	default:
		return "", ""
	}
}

func isPseudoMountFSType(fsType string) bool {
	switch fsType {
	case "proc", "sysfs", "cgroup", "cgroup2", "devpts", "devtmpfs", "mqueue", "securityfs", "debugfs", "tracefs", "configfs", "pstore", "autofs", "binfmt_misc", "rpc_pipefs":
		return true
	default:
		return false
	}
}
