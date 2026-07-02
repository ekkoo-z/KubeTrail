package collectors

import (
	"context"
	"net"
	"os"
	"sort"
	"strings"

	"github.com/ekkoo-z/KubeTrail/internal/model"
)

func collectNodeLocal(_ context.Context, cctx *Context) ([]model.Fact, []model.ErrorEntry) {
	var facts []model.Fact
	var errs []model.ErrorEntry

	for _, item := range []struct {
		id       string
		category string
		path     string
	}{
		{"node.cpuinfo", "node", "/proc/cpuinfo"},
		{"node.meminfo", "node", "/proc/meminfo"},
		{"node.kernel", "node", "/proc/version"},
		{"network.routes", "network", "/proc/net/route"},
		{"network.resolv_conf", "network", "/etc/resolv.conf"},
		{"network.hosts", "network", "/etc/hosts"},
	} {
		data, err := os.ReadFile(cctx.RootPath(item.path))
		if err != nil {
			errs = append(errs, errEntry(item.path, err))
			continue
		}
		facts = append(facts, fact(item.id, item.category, item.path, false, summarizeTextFile(item.path, string(data))))
	}

	ifaces, err := net.Interfaces()
	if err != nil {
		errs = append(errs, errEntry("net.Interfaces", err))
	} else {
		facts = append(facts, fact("network.interfaces", "network", "net.Interfaces", false, describeInterfaces(ifaces)))
	}
	return facts, errs
}

func summarizeTextFile(path, data string) any {
	switch path {
	case "/proc/cpuinfo":
		return summarizeCPUInfo(data)
	case "/proc/meminfo":
		return parseKeyValueLines(data)
	case "/proc/version":
		return map[string]any{
			"version": strings.TrimSpace(data),
		}
	default:
		return data
	}
}

func summarizeCPUInfo(data string) map[string]any {
	values := parseCPUInfo(data)
	flags := strings.Fields(values["flags"])
	if len(flags) == 0 {
		flags = strings.Fields(values["Features"])
	}
	return map[string]any{
		"processorCount":  cpuProcessorCount(data),
		"modelNames":      uniqueNonEmpty(values["model name"], values["Processor"], values["cpu"]),
		"vendorIDs":       uniqueNonEmpty(values["vendor_id"], values["CPU implementer"]),
		"architecture":    values["Architecture"],
		"flagsOfInterest": cpuFlagsOfInterest(flags),
		"rawBytes":        len(data),
		"rawSha256":       sha256HexString(data),
	}
}

func parseCPUInfo(data string) map[string]string {
	out := map[string]string{}
	for _, line := range strings.Split(data, "\n") {
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if key == "" || value == "" {
			continue
		}
		if out[key] == "" {
			out[key] = value
		}
	}
	return out
}

func cpuProcessorCount(data string) int {
	count := 0
	for _, line := range strings.Split(data, "\n") {
		key, _, ok := strings.Cut(line, ":")
		if ok && strings.TrimSpace(key) == "processor" {
			count++
		}
	}
	if count > 0 {
		return count
	}
	trimmed := strings.TrimSpace(data)
	if trimmed == "" {
		return 0
	}
	return strings.Count(trimmed, "\n\n") + 1
}

func cpuFlagsOfInterest(flags []string) []string {
	interesting := map[string]bool{
		"hypervisor": true,
		"vmx":        true,
		"svm":        true,
		"ept":        true,
		"smep":       true,
		"smap":       true,
		"fsgsbase":   true,
		"nx":         true,
		"pae":        true,
		"pku":        true,
		"ibrs":       true,
		"ibpb":       true,
		"stibp":      true,
	}
	seen := map[string]bool{}
	var out []string
	for _, flag := range flags {
		flag = strings.TrimSpace(flag)
		if flag == "" || !interesting[flag] || seen[flag] {
			continue
		}
		seen[flag] = true
		out = append(out, flag)
	}
	sort.Strings(out)
	return out
}

func uniqueNonEmpty(values ...string) []string {
	seen := map[string]bool{}
	var out []string
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	return out
}

func parseKeyValueLines(data string) map[string]string {
	out := map[string]string{}
	for _, line := range strings.Split(data, "\n") {
		key, value, ok := strings.Cut(line, ":")
		if ok {
			out[strings.TrimSpace(key)] = strings.TrimSpace(value)
		}
	}
	return out
}

func describeInterfaces(ifaces []net.Interface) []map[string]any {
	var out []map[string]any
	for _, iface := range ifaces {
		addrs, _ := iface.Addrs()
		addrValues := make([]string, 0, len(addrs))
		for _, addr := range addrs {
			addrValues = append(addrValues, addr.String())
		}
		out = append(out, map[string]any{
			"name":         iface.Name,
			"index":        iface.Index,
			"mtu":          iface.MTU,
			"flags":        iface.Flags.String(),
			"hardwareAddr": iface.HardwareAddr.String(),
			"addrs":        addrValues,
		})
	}
	return out
}
