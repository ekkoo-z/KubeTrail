package collectors

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/ekkoo-z/KubeTrail/internal/model"
)

const processCmdlinePreviewBytes = 512

func collectProc(_ context.Context, cctx *Context) ([]model.Fact, []model.ErrorEntry) {
	var facts []model.Fact
	var errs []model.ErrorEntry

	if status, err := readProcStatus(cctx.RootPath("/proc/self/status")); err == nil {
		facts = append(facts, fact("proc.status_security", "process", "/proc/self/status", false, map[string]any{
			"capabilities": map[string]string{
				"effective":   status["CapEff"],
				"permitted":   status["CapPrm"],
				"inheritable": status["CapInh"],
				"bounding":    status["CapBnd"],
				"ambient":     status["CapAmb"],
			},
			"noNewPrivs": status["NoNewPrivs"],
			"seccomp":    status["Seccomp"],
			"uid":        status["Uid"],
			"gid":        status["Gid"],
		}))
	} else {
		errs = append(errs, errEntry("/proc/self/status", err))
	}

	if data, err := os.ReadFile(cctx.RootPath("/proc/self/cgroup")); err == nil {
		facts = append(facts, fact("proc.cgroups", "process", "/proc/self/cgroup", false, parseCgroups(string(data))))
	} else {
		errs = append(errs, errEntry("/proc/self/cgroup", err))
	}

	const cgroupDevicesPath = "/sys/fs/cgroup/devices/devices.list"
	if data, err := os.ReadFile(cctx.RootPath(cgroupDevicesPath)); err == nil {
		facts = append(facts, fact("proc.cgroup_devices", "process", cgroupDevicesPath, false, parseCgroupDevices(string(data))))
	} else {
		errs = append(errs, errEntry(cgroupDevicesPath, err))
	}

	if data, err := os.ReadFile(cctx.RootPath("/proc/mounts")); err == nil {
		mounts := parseMounts(string(data))
		facts = append(facts, fact("proc.mounts", "filesystem", "/proc/mounts", false, mounts))
		facts = append(facts, fact("proc.cgroup_writable", "process", "/proc/mounts", false, cgroupWritability(mounts)))
	} else {
		errs = append(errs, errEntry("/proc/mounts", err))
	}

	if namespaces, err := readNamespaces(cctx.RootPath("/proc/self/ns")); err == nil {
		facts = append(facts, fact("proc.namespaces_self", "process", "/proc/self/ns", false, namespaces))
	} else {
		errs = append(errs, errEntry("/proc/self/ns", err))
	}

	if namespaces, err := readNamespaces(cctx.RootPath("/proc/1/ns")); err == nil {
		facts = append(facts, fact("proc.namespaces_pid1", "process", "/proc/1/ns", false, namespaces))
	} else {
		errs = append(errs, errEntry("/proc/1/ns", err))
	}

	processes, processErrs := readProcesses(cctx.RootPath("/proc"), 256)
	facts = append(facts, fact("proc.processes", "process", "/proc", false, processes))
	errs = append(errs, processErrs...)

	return facts, errs
}

func readProcStatus(path string) (map[string]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	out := map[string]string{}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		key, value, ok := strings.Cut(scanner.Text(), ":")
		if ok {
			out[key] = strings.TrimSpace(value)
		}
	}
	return out, scanner.Err()
}

func parseCgroups(data string) []map[string]string {
	var out []map[string]string
	for _, line := range strings.Split(strings.TrimSpace(data), "\n") {
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, ":", 3)
		if len(parts) != 3 {
			continue
		}
		out = append(out, map[string]string{
			"hierarchy":  parts[0],
			"controller": parts[1],
			"path":       parts[2],
			"version":    cgroupVersion(parts[0], parts[1]),
		})
	}
	return out
}

func cgroupVersion(hierarchy, controller string) string {
	if hierarchy == "0" && controller == "" {
		return "v2"
	}
	return "v1"
}

func parseCgroupDevices(data string) map[string]any {
	var rules []map[string]string
	blockWriteAllowed := false
	for _, line := range strings.Split(strings.TrimSpace(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 3 {
			continue
		}
		devType := fields[0]
		majorMinor := strings.SplitN(fields[1], ":", 2)
		if len(majorMinor) != 2 {
			continue
		}
		access := fields[2]
		rules = append(rules, map[string]string{
			"type":   devType,
			"major":  majorMinor[0],
			"minor":  majorMinor[1],
			"access": access,
		})
		if (devType == "a" || devType == "b") && strings.Contains(access, "w") {
			blockWriteAllowed = true
		}
	}
	return map[string]any{
		"rules":             rules,
		"blockWriteAllowed": blockWriteAllowed,
	}
}

func cgroupWritability(mounts []map[string]any) map[string]any {
	var writableMounts []map[string]string
	for _, m := range mounts {
		fsType, _ := m["fsType"].(string)
		if fsType != "cgroup" && fsType != "cgroup2" {
			continue
		}
		path, _ := m["path"].(string)
		opts, _ := m["options"].([]string)
		rw := false
		for _, opt := range opts {
			if opt == "rw" {
				rw = true
				break
			}
		}
		if rw {
			writableMounts = append(writableMounts, map[string]string{
				"path":   path,
				"fsType": fsType,
			})
		}
	}
	return map[string]any{
		"writable":       len(writableMounts) > 0,
		"writableMounts": writableMounts,
	}
}

func parseMounts(data string) []map[string]any {
	var out []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		out = append(out, map[string]any{
			"device":  unescapeMountField(fields[0]),
			"path":    unescapeMountField(fields[1]),
			"fsType":  fields[2],
			"options": strings.Split(fields[3], ","),
		})
	}
	return out
}

func parseMountInfo(data string) []map[string]any {
	var out []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 10 {
			continue
		}
		sep := -1
		for i, field := range fields {
			if field == "-" {
				sep = i
				break
			}
		}
		if sep < 6 || sep+3 > len(fields) {
			continue
		}
		out = append(out, map[string]any{
			"id":           fields[0],
			"parent":       fields[1],
			"majorMinor":   fields[2],
			"root":         unescapeMountField(fields[3]),
			"path":         unescapeMountField(fields[4]),
			"options":      strings.Split(fields[5], ","),
			"optional":     fields[6:sep],
			"fsType":       fields[sep+1],
			"source":       unescapeMountField(fields[sep+2]),
			"superOptions": strings.Split(fields[sep+3], ","),
		})
	}
	return out
}

func unescapeMountField(value string) string {
	replacer := strings.NewReplacer(`\040`, " ", `\011`, "\t", `\012`, "\n", `\134`, `\`)
	return replacer.Replace(value)
}

func readNamespaces(path string) (map[string]string, error) {
	entries, err := os.ReadDir(path)
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	for _, entry := range entries {
		target, err := os.Readlink(filepath.Join(path, entry.Name()))
		if err != nil {
			target = err.Error()
		}
		out[entry.Name()] = target
	}
	return out, nil
}

func readProcesses(procRoot string, max int) ([]map[string]any, []model.ErrorEntry) {
	entries, err := os.ReadDir(procRoot)
	if err != nil {
		return nil, []model.ErrorEntry{errEntry("/proc", err)}
	}

	var out []map[string]any
	var errs []model.ErrorEntry
	for _, entry := range entries {
		if len(out) >= max {
			break
		}
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid <= 0 {
			continue
		}
		item, err := readProcess(procRoot, pid)
		if err != nil {
			errs = append(errs, errEntry(fmt.Sprintf("/proc/%d", pid), err))
			continue
		}
		out = append(out, item)
	}
	return out, errs
}

func readProcess(procRoot string, pid int) (map[string]any, error) {
	status, err := readProcStatus(filepath.Join(procRoot, strconv.Itoa(pid), "status"))
	if err != nil {
		return nil, err
	}
	cmdlineData, _ := os.ReadFile(filepath.Join(procRoot, strconv.Itoa(pid), "cmdline"))
	cmdline := strings.Trim(strings.ReplaceAll(string(cmdlineData), "\x00", " "), " ")
	ppid, _ := strconv.Atoi(status["PPid"])
	item := map[string]any{
		"pid":   pid,
		"ppid":  ppid,
		"name":  status["Name"],
		"state": status["State"],
	}
	for key, value := range processCmdlineFields(cmdline) {
		item[key] = value
	}
	return item, nil
}

func processCmdlineFields(cmdline string) map[string]any {
	fields := map[string]any{
		"cmdline":       cmdline,
		"cmdlineLength": len(cmdline),
		"argCount":      len(strings.Fields(cmdline)),
	}
	if cmdline == "" {
		return fields
	}
	if len(cmdline) > processCmdlinePreviewBytes {
		fields["cmdline"] = cmdline[:processCmdlinePreviewBytes] + " ..."
		fields["cmdlineTruncated"] = true
		fields["cmdlineOmittedBytes"] = len(cmdline) - processCmdlinePreviewBytes
		fields["cmdlineSha256"] = sha256HexString(cmdline)
	}
	if matches := secretLikeCmdlineArgs(cmdline, 16); len(matches) > 0 {
		fields["secretLikeArgs"] = matches
		fields["secretLikeArgCount"] = len(matches)
	}
	if indicators := cmdlineIndicators(cmdline); len(indicators) > 0 {
		fields["indicators"] = indicators
	}
	return fields
}

func secretLikeCmdlineArgs(cmdline string, max int) []string {
	seen := map[string]bool{}
	var out []string
	for _, arg := range strings.Fields(cmdline) {
		key := cmdlineArgKey(arg)
		if key == "" || !isCmdlineSecretLike(key) || seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, key)
		if len(out) >= max {
			break
		}
	}
	return out
}

func cmdlineArgKey(arg string) string {
	value := strings.Trim(arg, `"'`)
	value = strings.TrimPrefix(value, "-D")
	value = strings.TrimLeft(value, "-")
	if key, _, ok := strings.Cut(value, "="); ok {
		value = key
	}
	value = strings.TrimSpace(value)
	if len(value) > 96 {
		value = value[:96]
	}
	return value
}

func isCmdlineSecretLike(value string) bool {
	upper := strings.ToUpper(value)
	normalized := strings.NewReplacer(".", "_", "-", "_", "/", "_").Replace(upper)
	if isSecretLike(normalized) {
		return true
	}
	for _, marker := range []string{"ACCESSID", "ACCESSKEY", "AKID", "AKSECRET", "SECRETKEY", "PRIVATEKEY", "CLIENTSECRET"} {
		if strings.Contains(normalized, marker) {
			return true
		}
	}
	return false
}

func cmdlineIndicators(cmdline string) []string {
	lower := strings.ToLower(cmdline)
	var out []string
	add := func(name string) {
		for _, existing := range out {
			if existing == name {
				return
			}
		}
		out = append(out, name)
	}
	if strings.Contains(lower, "java") || strings.Contains(lower, "-classpath") || strings.Contains(lower, "-cp ") {
		add("java")
	}
	if strings.Contains(lower, "classpath") {
		add("classpath")
	}
	if strings.Contains(lower, "spring") {
		add("spring")
	}
	if strings.Contains(lower, "password") || strings.Contains(lower, "passwd") || strings.Contains(lower, "secret") || strings.Contains(lower, "token") || strings.Contains(lower, "credential") {
		add("secret_keyword")
	}
	return out
}
