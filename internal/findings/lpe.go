package findings

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/ekkoo-z/KubeTrail/internal/model"
)

func EvaluateLPE(doc model.Document) []Finding {
	facts := indexFacts(doc.Facts)
	if lpeSkipped(facts) || identityIsRoot(facts) {
		return nil
	}

	var findings []Finding
	findings = append(findings, evaluateLPEUserland(facts)...)
	findings = append(findings, evaluateLPEKernel(facts)...)
	if len(findings) == 0 {
		if summary := lpeNoHitsSummary(facts); summary != nil {
			findings = append(findings, *summary)
		}
	}
	return findings
}

// lpeNoHitsSummary distinguishes a genuine "no exploitable LPE" result from a
// silent "collection failed / nothing to evaluate" one. When core LPE inputs
// were collected but no rule matched, we emit an info-level summary so an empty
// LPE section reads as a positive finding rather than a possible data gap.
func lpeNoHitsSummary(facts map[string]model.Fact) *Finding {
	kernel := factMap(facts, "lpe.kernel")
	release, _ := kernel["release"].(string)
	packages := factMap(facts, "lpe.packages")
	hasPackages := packages != nil && hasLpePackageItems(packages["packages"])
	hasSUIDTools := facts["lpe.suid_tools"].ID != ""
	hasKernel := release != ""
	hasModules := facts["lpe.modules"].ID != ""
	hasSysctls := facts["lpe.sysctls"].ID != ""

	// Nothing collected at all → not a "no exploit" verdict, just a data gap.
	if !hasKernel && !hasPackages && !hasSUIDTools {
		return nil
	}

	var parts []string
	if hasKernel {
		parts = append(parts, fmt.Sprintf("kernel=%s", release))
	}
	if hasPackages {
		parts = append(parts, "packages scanned")
	}
	if hasSUIDTools {
		parts = append(parts, "suid_tools scanned")
	}
	if _, ok := facts["lpe.kernel_config"]; ok {
		parts = append(parts, "kernel_config scanned")
	}
	if hasModules {
		parts = append(parts, "modules scanned")
	}
	if hasSysctls {
		parts = append(parts, "sysctls scanned")
	}
	return &Finding{
		Severity:    "info",
		Category:    "lpe",
		Confidence:  "signal",
		Title:       "No LPE candidates matched",
		Description: "Kernel release, setuid tools, and package versions were collected but fell outside known vulnerable CVE ranges / prerequisites: " + strings.Join(parts, ", "),
		Evidence:    "lpe.status,lpe.kernel,lpe.packages,lpe.suid_tools",
	}
}

func hasLpePackageItems(raw any) bool {
	switch v := raw.(type) {
	case []any:
		return len(v) > 0
	case []map[string]any:
		return len(v) > 0
	case []map[string]string:
		return len(v) > 0
	default:
		return false
	}
}

func evaluateLPEUserland(facts map[string]model.Fact) []Finding {
	var findings []Finding

	if version, ok := lpePackageVersion(facts, "sudo"); ok {
		if vulnerable, reason := lpeSudo3156PackagePotentiallyVulnerable(facts, version); vulnerable {
			severity, confidence, prereq := lpeSUIDFindingRisk(facts, "sudo", "sudoedit")
			findings = append(findings, Finding{
				Severity:    severity,
				Category:    "lpe",
				Confidence:  confidence,
				Title:       "Potential CVE-2021-3156 sudo Baron Samedit",
				Description: fmt.Sprintf("sudo package version %s %s; %s", version, reason, prereq),
				Evidence:    "lpe.packages",
			})
		}
		if compareNumericVersion(version, "1.9.14") >= 0 && compareNumericVersion(version, "1.9.17") <= 0 {
			severity, confidence, prereq := lpeSUIDFindingRisk(facts, "sudo", "sudoedit")
			findings = append(findings, Finding{
				Severity:    severity,
				Category:    "lpe",
				Confidence:  confidence,
				Title:       "Potential CVE-2025-32463 sudo chroot LPE",
				Description: fmt.Sprintf("sudo package version %s falls in the 1.9.14-1.9.17 upstream range; vendor backports may change affected status; %s", version, prereq),
				Evidence:    "lpe.packages",
			})
		}
	}

	pkexecSUID := lpeToolSetuid(facts, "pkexec")
	pkexecUsable := lpeToolSetuidUsable(facts, "pkexec") && lpeSUIDTransitionsLikely(facts)
	for _, pkg := range []string{"policykit-1", "polkit", "polkitd"} {
		version, ok := lpePackageVersion(facts, pkg)
		if !ok {
			continue
		}
		vulnerable, reason := lpePwnKitPackagePotentiallyVulnerable(facts, version)
		if pkexecSUID && vulnerable {
			severity := "medium"
			confidence := "signal"
			prereq := "setuid pkexec is present, but current SUID transition usability was not fully confirmed"
			if pkexecUsable {
				severity = "high"
				confidence = "probable"
				prereq = "setuid pkexec appears usable in the current mount/no_new_privs context"
			}
			findings = append(findings, Finding{
				Severity:    severity,
				Category:    "lpe",
				Confidence:  confidence,
				Title:       "Potential CVE-2021-4034 PwnKit pkexec",
				Description: fmt.Sprintf("%s package version %s with setuid pkexec present; %s; %s", pkg, version, reason, prereq),
				Evidence:    "lpe.packages,lpe.suid_tools",
			})
			break
		}
	}
	if pkexecUsable && !lpeAnyPackagePresent(facts, "policykit-1", "polkit", "polkitd") {
		findings = append(findings, Finding{
			Severity:    "medium",
			Category:    "lpe",
			Confidence:  "signal",
			Title:       "PwnKit exposure signal: setuid pkexec present",
			Description: "pkexec is setuid, but package version was unavailable; collect host package advisory state to confirm CVE-2021-4034 exposure",
			Evidence:    "lpe.suid_tools",
		})
	}

	if version, ok := lpePackageVersion(facts, "screen"); ok && compareNumericVersion(version, "4.5.0") == 0 && lpeToolSetuid(facts, "screen") {
		severity, confidence, prereq := lpeSUIDFindingRisk(facts, "screen")
		findings = append(findings, Finding{
			Severity:    severity,
			Category:    "lpe",
			Confidence:  confidence,
			Title:       "Potential CVE-2017-5618 setuid screen LPE",
			Description: fmt.Sprintf("screen 4.5.0 is installed and the screen binary is setuid; %s", prereq),
			Evidence:    "lpe.packages,lpe.suid_tools",
		})
	}

	if version, ok := lpePackageVersion(facts, "packagekit"); ok {
		if vulnerable, reason := lpePackageKitPotentiallyVulnerable(facts, version); vulnerable {
			findings = append(findings, Finding{
				Severity:    "medium",
				Category:    "lpe",
				Confidence:  "signal",
				Title:       "Potential CVE-2026-41651 PackageKit TOCTOU LPE",
				Description: fmt.Sprintf("PackageKit version %s %s; D-Bus activation/service reachability was not confirmed by this local fact set", version, reason),
				Evidence:    "lpe.packages",
			})
		}
	}

	return findings
}

func evaluateLPEKernel(facts map[string]model.Fact) []Finding {
	kernel := factMap(facts, "lpe.kernel")
	if kernel == nil {
		return nil
	}
	release, _ := kernel["release"].(string)
	if release == "" {
		return nil
	}
	version, ok := parseKernelVersion(release)
	if !ok {
		return nil
	}

	usernsEnabled, usernsKnown := lpeUsernsState(facts)
	hasCAPSysAdmin := lpeCapEffectiveHas(facts, 21)
	bpfEnabled, bpfKnown := lpeKernelConfigEnabled(facts, "CONFIG_BPF_SYSCALL")
	unprivBPFEnabled := lpeSysctlEquals(facts, "kernel.unprivileged_bpf_disabled", "0")
	nfTables := lpeModulePresent(facts, "nf_tables")
	overlay := lpeModulePresent(facts, "overlay") || lpeFilesystemBool(facts, "hasOverlay")
	fuse := lpeModulePresent(facts, "fuse") || lpeFilesystemBool(facts, "hasFuse")
	ubuntu := lpeKernelLooksLikeUbuntu(kernel)

	var findings []Finding
	if kernelInDirtyPipeRange(version) {
		findings = append(findings, Finding{
			Severity:    "medium",
			Category:    "lpe",
			Confidence:  "signal",
			Title:       "Potential CVE-2022-0847 Dirty Pipe kernel range",
			Description: fmt.Sprintf("kernel release %s falls in a Dirty Pipe pre-fix branch; fixed upstream stable points include 5.10.102, 5.15.25, and 5.16.11; vendor backports may change affected status", release),
			Evidence:    "lpe.kernel",
		})
	}

	if bpfKnown && bpfEnabled && unprivBPFEnabled && kernelBetween(version, kv(4, 4, 0), kv(4, 14, 8)) {
		findings = append(findings, Finding{
			Severity:    "medium",
			Category:    "lpe",
			Confidence:  "signal",
			Title:       "Potential CVE-2017-16995 eBPF verifier LPE",
			Description: "kernel range, CONFIG_BPF_SYSCALL, and enabled unprivileged BPF match public exploit prerequisites; vendor backports still need confirmation",
			Evidence:    "lpe.kernel,lpe.kernel_config,lpe.sysctls",
		})
	}

	if bpfKnown && bpfEnabled && unprivBPFEnabled && kernelBetween(version, kv(5, 7, 0), kv(5, 11, 999)) {
		findings = append(findings, Finding{
			Severity:    "medium",
			Category:    "lpe",
			Confidence:  "signal",
			Title:       "Potential CVE-2021-3490 eBPF ALU32 LPE",
			Description: "kernel range, CONFIG_BPF_SYSCALL, and enabled unprivileged BPF match public exploit prerequisites; vendor backports still need confirmation",
			Evidence:    "lpe.kernel,lpe.kernel_config,lpe.sysctls",
		})
	}

	if kernelInNfTables1086ExploitRange(version) {
		switch {
		case nfTables && usernsEnabled:
			severity, confidence, note := lpeKernelPrereqRisk(release)
			if lpeNfTablesInitOnAllocCaveat(version, facts) {
				severity = "medium"
				confidence = "signal"
				note = "CONFIG_INIT_ON_ALLOC_DEFAULT_ON is enabled on a 6.4+ kernel, which public CVE-2024-1086 PoCs identify as a major exploitability caveat"
			}
			findings = append(findings, Finding{
				Severity:    severity,
				Category:    "lpe",
				Confidence:  confidence,
				Title:       "Potential CVE-2024-1086 nf_tables LPE",
				Description: "kernel range, nf_tables presence, and unprivileged user namespaces match public exploit prerequisites; " + note,
				Evidence:    "lpe.kernel,lpe.modules,lpe.sysctls",
			})
		case nfTables && !usernsKnown:
			findings = append(findings, Finding{
				Severity:    "medium",
				Category:    "lpe",
				Confidence:  "signal",
				Title:       "CVE-2024-1086 kernel range with nf_tables present",
				Description: "user namespace state was unavailable, so exploitability remains a medium-confidence heuristic",
				Evidence:    "lpe.kernel,lpe.modules",
			})
		}
	}

	if kernelInCopyFailRange(version) && lpeKernelConfigAllEnabled(facts, "CONFIG_CRYPTO_USER_API_AEAD", "CONFIG_CRYPTO_AUTHENC") {
		findings = append(findings, Finding{
			Severity:    "high",
			Category:    "lpe",
			Confidence:  "probable",
			Title:       "Potential CVE-2026-31431 Copy Fail AF_ALG LPE",
			Description: "kernel range and AF_ALG AEAD/authenc kernel config match the public Copy Fail exposure prerequisites",
			Evidence:    "lpe.kernel,lpe.kernel_config",
		})
	}

	dirtyFragPrereq := usernsEnabled || hasCAPSysAdmin
	if dirtyFragPrereq && kernelInDirtyFragESPRange(version) && lpeDirtyFragESPReachable(facts) {
		findings = append(findings, Finding{
			Severity:    "high",
			Category:    "lpe",
			Confidence:  "probable",
			Title:       "Potential CVE-2026-43284 Dirty Frag xfrm-ESP LPE",
			Description: "kernel range, xfrm/ESP reachability, and namespace/capability prerequisites match public Dirty Frag signals",
			Evidence:    "lpe.kernel,lpe.kernel_config,lpe.modules,lpe.sysctls,lpe.process_security",
		})
	}

	if dirtyFragPrereq && kernelInDirtyFragRxRPCRange(version) && lpeDirtyFragRxRPCReachable(facts) {
		findings = append(findings, Finding{
			Severity:    "high",
			Category:    "lpe",
			Confidence:  "probable",
			Title:       "Potential CVE-2026-43500 Dirty Frag RxRPC LPE",
			Description: "kernel range, RxRPC reachability, and namespace/capability prerequisites match public Dirty Frag signals",
			Evidence:    "lpe.kernel,lpe.kernel_config,lpe.modules,lpe.sysctls,lpe.process_security",
		})
	}

	if kernelBetween(version, kv(5, 11, 0), kv(6, 2, 999)) {
		switch {
		case overlay && fuse && usernsEnabled:
			severity, confidence, note := lpeKernelPrereqRisk(release)
			findings = append(findings, Finding{
				Severity:    severity,
				Category:    "lpe",
				Confidence:  confidence,
				Title:       "Potential CVE-2023-0386 OverlayFS LPE",
				Description: "kernel range plus OverlayFS/FUSE/userns signals match public exploit prerequisites; " + note,
				Evidence:    "lpe.kernel,lpe.modules,lpe.filesystems,lpe.sysctls",
			})
		case overlay && usernsKnown && usernsEnabled:
			findings = append(findings, Finding{
				Severity:    "medium",
				Category:    "lpe",
				Confidence:  "signal",
				Title:       "CVE-2023-0386 OverlayFS kernel range",
				Description: "OverlayFS and user namespaces are present; FUSE signal was not observed",
				Evidence:    "lpe.kernel,lpe.modules,lpe.sysctls",
			})
		}
	}

	if kernelBetween(version, kv(5, 4, 0), kv(5, 16, 2)) && (usernsEnabled || hasCAPSysAdmin) {
		findings = append(findings, Finding{
			Severity:    "medium",
			Category:    "lpe",
			Confidence:  "signal",
			Title:       "Potential CVE-2022-0185 fs_context LPE range",
			Description: "kernel range and namespace/capability prerequisites match common public exploit requirements",
			Evidence:    "lpe.kernel,lpe.sysctls,lpe.process_security",
		})
	}

	if ubuntu && kernelBetween(version, kv(3, 13, 0), kv(5, 13, 999)) && overlay && (usernsEnabled || hasCAPSysAdmin) {
		findings = append(findings, Finding{
			Severity:    "medium",
			Category:    "lpe",
			Confidence:  "signal",
			Title:       "Potential CVE-2021-3493 Ubuntu OverlayFS LPE",
			Description: "Ubuntu kernel release, OverlayFS signal, and namespace/capability prerequisite match public suggester heuristics; Ubuntu kernel package fixes still need confirmation",
			Evidence:    "lpe.kernel,lpe.modules,lpe.filesystems,lpe.sysctls,lpe.process_security",
		})
	}

	if compareKernelVersion(version, kv(4, 8, 3)) < 0 {
		findings = append(findings, Finding{
			Severity:    "medium",
			Category:    "lpe",
			Confidence:  "signal",
			Title:       "Legacy Dirty COW kernel range",
			Description: fmt.Sprintf("kernel release %s is older than the common CVE-2016-5195 fixed range", release),
			Evidence:    "lpe.kernel",
		})
	}

	return findings
}

func lpeSkipped(facts map[string]model.Fact) bool {
	status := factMap(facts, "lpe.status")
	if status == nil {
		return false
	}
	skipped, _ := status["skipped"].(bool)
	return skipped
}

func identityIsRoot(facts map[string]model.Fact) bool {
	identity := factMap(facts, "identity.current_user")
	if identity == nil {
		return false
	}
	euid, ok := int64FromAny(identity["euid"])
	return ok && euid == 0
}

func lpePackageVersion(facts map[string]model.Fact, name string) (string, bool) {
	packages := factMap(facts, "lpe.packages")
	if packages == nil {
		return "", false
	}
	rawItems, ok := packages["packages"].([]any)
	if !ok {
		return packageVersionFromTypedSlice(packages["packages"], name)
	}
	for _, raw := range rawItems {
		item, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		itemName, _ := item["name"].(string)
		version, _ := item["version"].(string)
		if itemName == name && version != "" {
			return version, true
		}
	}
	return "", false
}

func packageVersionFromTypedSlice(raw any, name string) (string, bool) {
	items, ok := raw.([]map[string]string)
	if !ok {
		return "", false
	}
	for _, item := range items {
		if item["name"] == name && item["version"] != "" {
			return item["version"], true
		}
	}
	return "", false
}

func lpeAnyPackagePresent(facts map[string]model.Fact, names ...string) bool {
	for _, name := range names {
		if _, ok := lpePackageVersion(facts, name); ok {
			return true
		}
	}
	return false
}

func lpePackageKitPotentiallyVulnerable(facts map[string]model.Fact, version string) (bool, string) {
	if strings.EqualFold(lpeOSReleaseField(facts, "ID"), "ubuntu") {
		release := lpeOSReleaseField(facts, "VERSION_ID")
		if fixed, ok := ubuntuPackageKitFixedVersion(release); ok {
			if compareNumericVersion(version, fixed) < 0 {
				return true, fmt.Sprintf("is below Ubuntu %s fixed package version %s", release, fixed)
			}
			return false, ""
		}
	}

	if compareNumericVersion(version, "1.0.2") >= 0 && compareNumericVersion(version, "1.3.5") < 0 {
		return true, "is in the upstream affected range >=1.0.2 <1.3.5; verify distro advisory/backport status before exploitation"
	}
	return false, ""
}

func lpePwnKitPackagePotentiallyVulnerable(facts map[string]model.Fact, version string) (bool, string) {
	if strings.EqualFold(lpeOSReleaseField(facts, "ID"), "ubuntu") {
		release := lpeOSReleaseField(facts, "VERSION_ID")
		if fixed, ok := ubuntuPwnKitFixedVersion(release); ok {
			if compareNumericVersion(version, fixed) < 0 {
				return true, fmt.Sprintf("version is below Ubuntu %s fixed package version %s", release, fixed)
			}
			return false, ""
		}
	}

	if compareNumericVersion(version, "0.105-31") <= 0 {
		return true, "version falls in the generic upstream pre-0.105-31 heuristic range; verify distro advisory status before exploitation"
	}
	return false, ""
}

func lpeSudo3156PackagePotentiallyVulnerable(facts map[string]model.Fact, version string) (bool, string) {
	if strings.EqualFold(lpeOSReleaseField(facts, "ID"), "ubuntu") {
		release := lpeOSReleaseField(facts, "VERSION_ID")
		if fixed, ok := ubuntuSudo3156FixedVersion(release); ok {
			if compareNumericVersion(version, fixed) < 0 {
				return true, fmt.Sprintf("is below Ubuntu %s fixed package version %s; verify vendor backports before exploitation", release, fixed)
			}
			return false, ""
		}
	}

	if compareNumericVersion(version, "1.9.5p2") < 0 {
		return true, "is below upstream 1.9.5p2; verify vendor backports before exploitation"
	}
	return false, ""
}

func ubuntuSudo3156FixedVersion(versionID string) (string, bool) {
	switch strings.Trim(versionID, `"`) {
	case "14.04":
		return "1.8.9p5-1ubuntu1.5", true
	case "16.04":
		return "1.8.16-0ubuntu1.10", true
	case "18.04":
		return "1.8.21p2-3ubuntu1.4", true
	case "20.04":
		return "1.8.31-1ubuntu1.2", true
	case "20.10":
		return "1.9.1-1ubuntu1.1", true
	default:
		return "", false
	}
}

func ubuntuPackageKitFixedVersion(versionID string) (string, bool) {
	switch strings.Trim(versionID, `"`) {
	case "16.04":
		return "0.8.17-4ubuntu6~gcc5.4ubuntu1.5+esm1", true
	case "18.04":
		return "1.1.9-1ubuntu2.18.04.6+esm1", true
	case "20.04":
		return "1.1.13-2ubuntu1.1+esm1", true
	case "22.04":
		return "1.2.5-2ubuntu3.1", true
	case "24.04":
		return "1.2.8-2ubuntu1.5", true
	case "25.10":
		return "1.3.1-1ubuntu1.1", true
	case "26.04":
		return "1.3.4-3ubuntu1", true
	default:
		return "", false
	}
}

func ubuntuPwnKitFixedVersion(versionID string) (string, bool) {
	switch strings.Trim(versionID, `"`) {
	case "14.04":
		return "0.105-4ubuntu3.14.04.6", true
	case "16.04":
		return "0.105-14.1ubuntu0.5", true
	case "18.04":
		return "0.105-20ubuntu0.18.04.6", true
	case "20.04":
		return "0.105-26ubuntu1.2", true
	case "21.10":
		return "0.105-31ubuntu0.1", true
	case "22.04":
		return "0.105-31ubuntu1", true
	default:
		return "", false
	}
}

func lpeOSReleaseField(facts map[string]model.Fact, key string) string {
	kernel := factMap(facts, "lpe.kernel")
	if kernel == nil {
		return ""
	}
	switch osRelease := kernel["osRelease"].(type) {
	case map[string]any:
		value, _ := osRelease[key].(string)
		return value
	case map[string]string:
		return osRelease[key]
	default:
		return ""
	}
}

func lpeToolSetuid(facts map[string]model.Fact, name string) bool {
	f, ok := facts["lpe.suid_tools"]
	if !ok {
		return false
	}
	if items, ok := f.Value.([]map[string]any); ok {
		for _, item := range items {
			if item["name"] == name {
				setuid, _ := item["setuid"].(bool)
				if setuid {
					return true
				}
			}
		}
		return false
	}
	items, ok := f.Value.([]any)
	if !ok {
		return false
	}
	for _, raw := range items {
		item, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		itemName, _ := item["name"].(string)
		setuid, _ := item["setuid"].(bool)
		if itemName == name && setuid {
			return true
		}
	}
	return false
}

func lpeSUIDFindingRisk(facts map[string]model.Fact, toolNames ...string) (string, string, string) {
	if lpeAnyToolSetuidUsable(facts, toolNames...) && lpeSUIDTransitionsLikely(facts) {
		return "high", "probable", "setuid helper appears usable in the current mount/no_new_privs context"
	}
	if lpeNoNewPrivsEnabled(facts) {
		return "medium", "signal", "NoNewPrivs=1 may block privilege-gaining exec transitions in the current container"
	}
	for _, name := range toolNames {
		if lpeToolSetuid(facts, name) && !lpeToolSetuidUsable(facts, name) {
			return "medium", "signal", "setuid helper is present, but its mount appears nosuid or otherwise not usable"
		}
	}
	return "medium", "signal", "setuid helper usability was not confirmed"
}

func lpeAnyToolSetuidUsable(facts map[string]model.Fact, names ...string) bool {
	for _, name := range names {
		if lpeToolSetuidUsable(facts, name) {
			return true
		}
	}
	return false
}

func lpeToolSetuidUsable(facts map[string]model.Fact, name string) bool {
	f, ok := facts["lpe.suid_tools"]
	if !ok {
		return false
	}
	for _, item := range sliceMapsFromAny(f.Value) {
		itemName, _ := item["name"].(string)
		setuid, _ := item["setuid"].(bool)
		isDir, _ := item["isDir"].(bool)
		nosuid, _ := item["nosuid"].(bool)
		if itemName == name && setuid && !isDir && !nosuid {
			return true
		}
	}
	return false
}

func lpeSUIDTransitionsLikely(facts map[string]model.Fact) bool {
	return !lpeNoNewPrivsEnabled(facts)
}

func lpeNoNewPrivsEnabled(facts map[string]model.Fact) bool {
	security := factMap(facts, "lpe.process_security")
	if security == nil {
		return false
	}
	value, ok := stringFromAny(security["noNewPrivs"])
	return ok && strings.TrimSpace(value) == "1"
}

func lpeUsernsState(facts map[string]model.Fact) (bool, bool) {
	sysctls := factMap(facts, "lpe.sysctls")
	if sysctls == nil {
		return false, false
	}
	if value, ok := stringFromAny(sysctls["kernel.unprivileged_userns_clone"]); ok {
		return strings.TrimSpace(value) == "1", true
	}
	if value, ok := stringFromAny(sysctls["user.max_user_namespaces"]); ok {
		n, err := strconv.ParseInt(strings.TrimSpace(value), 10, 64)
		if err == nil {
			return n > 0, true
		}
	}
	return false, false
}

func lpeModulePresent(facts map[string]model.Fact, name string) bool {
	modules := factMap(facts, "lpe.modules")
	if modules == nil {
		return false
	}
	return stringSliceContains(modules["present"], name) || stringSliceContains(modules["loadedNames"], name)
}

func lpeKernelConfigAllEnabled(facts map[string]model.Fact, keys ...string) bool {
	for _, key := range keys {
		enabled, known := lpeKernelConfigEnabled(facts, key)
		if !known || !enabled {
			return false
		}
	}
	return true
}

func lpeKernelConfigEnabled(facts map[string]model.Fact, key string) (bool, bool) {
	value, ok := lpeKernelConfigValue(facts, key)
	if !ok {
		return false, false
	}
	return value == "y" || value == "m", true
}

func lpeKernelConfigValue(facts map[string]model.Fact, key string) (string, bool) {
	config := factMap(facts, "lpe.kernel_config")
	if config == nil {
		return "", false
	}
	switch values := config["values"].(type) {
	case map[string]string:
		value, ok := values[key]
		return value, ok
	case map[string]any:
		value, ok := stringFromAny(values[key])
		return value, ok
	default:
		return "", false
	}
}

func lpeSysctlEquals(facts map[string]model.Fact, key, expected string) bool {
	sysctls := factMap(facts, "lpe.sysctls")
	if sysctls == nil {
		return false
	}
	value, ok := stringFromAny(sysctls[key])
	return ok && strings.TrimSpace(value) == expected
}

func lpeFilesystemBool(facts map[string]model.Fact, key string) bool {
	filesystems := factMap(facts, "lpe.filesystems")
	if filesystems == nil {
		return false
	}
	value, _ := filesystems[key].(bool)
	return value
}

func lpeCapEffectiveHas(facts map[string]model.Fact, bit uint) bool {
	security := factMap(facts, "lpe.process_security")
	if security == nil {
		return false
	}
	caps, ok := security["capabilities"].(map[string]any)
	if !ok {
		if typed, ok := security["capabilities"].(map[string]string); ok {
			eff, err := strconv.ParseUint(typed["effective"], 16, 64)
			return err == nil && eff&(1<<bit) != 0
		}
		return false
	}
	effective, _ := caps["effective"].(string)
	eff, err := strconv.ParseUint(effective, 16, 64)
	return err == nil && eff&(1<<bit) != 0
}

func lpeDirtyFragESPReachable(facts map[string]model.Fact) bool {
	if lpeModulePresent(facts, "esp4") || lpeModulePresent(facts, "esp6") {
		return true
	}
	xfrmEnabled, xfrmKnown := lpeKernelConfigEnabled(facts, "CONFIG_XFRM")
	esp4Enabled, esp4Known := lpeKernelConfigEnabled(facts, "CONFIG_INET_ESP")
	esp6Enabled, esp6Known := lpeKernelConfigEnabled(facts, "CONFIG_INET6_ESP")
	return xfrmKnown && xfrmEnabled && ((esp4Known && esp4Enabled) || (esp6Known && esp6Enabled))
}

func lpeDirtyFragRxRPCReachable(facts map[string]model.Fact) bool {
	if lpeModulePresent(facts, "rxrpc") {
		return true
	}
	enabled, known := lpeKernelConfigEnabled(facts, "CONFIG_RXRPC")
	return known && enabled
}

func lpeKernelLooksLikeUbuntu(kernel map[string]any) bool {
	version, _ := kernel["version"].(string)
	release, _ := kernel["release"].(string)
	if strings.Contains(strings.ToLower(version+" "+release), "ubuntu") {
		return true
	}
	osRelease, ok := kernel["osRelease"].(map[string]any)
	if ok {
		id, _ := osRelease["ID"].(string)
		return strings.EqualFold(id, "ubuntu")
	}
	if typed, ok := kernel["osRelease"].(map[string]string); ok {
		return strings.EqualFold(typed["ID"], "ubuntu")
	}
	return false
}

func lpeKernelPrereqRisk(release string) (string, string, string) {
	if lpeKernelReleaseLooksVendorPatched(release) {
		return "medium", "signal", "kernel release looks distro/vendor patched, so fixed-package advisory state should be checked before treating this as exploitable"
	}
	return "high", "probable", "kernel release does not look like a distro-patched ABI string, but advisory status should still be verified"
}

func lpeKernelReleaseLooksVendorPatched(release string) bool {
	_, suffix, ok := strings.Cut(release, "-")
	if !ok {
		return false
	}
	suffix = strings.ToLower(suffix)
	for _, marker := range []string{
		"generic", "amd64", "ubuntu", "deb", "el", "uek", "amzn", "aws", "azure", "gcp", "cloud", "rt", "raspi",
	} {
		if strings.Contains(suffix, marker) {
			return true
		}
	}
	return false
}

func lpeNfTablesInitOnAllocCaveat(version kernelVersion, facts map[string]model.Fact) bool {
	enabled, known := lpeKernelConfigEnabled(facts, "CONFIG_INIT_ON_ALLOC_DEFAULT_ON")
	return known && enabled && compareKernelVersion(version, kv(6, 4, 0)) >= 0
}

func kernelInDirtyPipeRange(v kernelVersion) bool {
	return kernelInRanges(v, [][2]kernelVersion{
		{kv(5, 8, 0), kv(5, 9, 999)},
		{kv(5, 10, 0), kv(5, 10, 101)},
		{kv(5, 11, 0), kv(5, 14, 999)},
		{kv(5, 15, 0), kv(5, 15, 24)},
		{kv(5, 16, 0), kv(5, 16, 10)},
	})
}

func kernelInNfTables1086ExploitRange(v kernelVersion) bool {
	if !kernelBetween(v, kv(5, 14, 0), kv(6, 6, 999)) {
		return false
	}
	switch {
	case v.major == 5 && v.minor == 15 && v.patch >= 149:
		return false
	case v.major == 6 && v.minor == 1 && v.patch >= 76:
		return false
	case v.major == 6 && v.minor == 6 && v.patch >= 15:
		return false
	default:
		return true
	}
}

func kernelInCopyFailRange(v kernelVersion) bool {
	return kernelInRanges(v, [][2]kernelVersion{
		{kv(4, 14, 0), kv(5, 10, 253)},
		{kv(5, 11, 0), kv(5, 15, 203)},
		{kv(5, 16, 0), kv(6, 1, 169)},
		{kv(6, 2, 0), kv(6, 6, 136)},
		{kv(6, 7, 0), kv(6, 12, 84)},
		{kv(6, 13, 0), kv(6, 18, 21)},
		{kv(6, 19, 0), kv(6, 19, 11)},
	})
}

func kernelInDirtyFragESPRange(v kernelVersion) bool {
	return kernelInRanges(v, [][2]kernelVersion{
		{kv(4, 11, 0), kv(5, 10, 254)},
		{kv(5, 12, 0), kv(5, 15, 204)},
		{kv(5, 16, 0), kv(6, 1, 170)},
		{kv(6, 2, 0), kv(6, 6, 137)},
		{kv(6, 7, 0), kv(6, 12, 86)},
		{kv(6, 13, 0), kv(6, 18, 27)},
		{kv(7, 0, 0), kv(7, 0, 4)},
	})
}

func kernelInDirtyFragRxRPCRange(v kernelVersion) bool {
	return kernelInRanges(v, [][2]kernelVersion{
		{kv(5, 4, 0), kv(6, 18, 28)},
		{kv(6, 19, 0), kv(7, 0, 5)},
	})
}

func kernelInRanges(v kernelVersion, ranges [][2]kernelVersion) bool {
	for _, r := range ranges {
		if kernelBetween(v, r[0], r[1]) {
			return true
		}
	}
	return false
}

type kernelVersion struct {
	major int
	minor int
	patch int
}

func kv(major, minor, patch int) kernelVersion {
	return kernelVersion{major: major, minor: minor, patch: patch}
}

func parseKernelVersion(release string) (kernelVersion, bool) {
	head := strings.SplitN(release, "-", 2)[0]
	parts := strings.Split(head, ".")
	if len(parts) < 2 {
		return kernelVersion{}, false
	}
	major, err := strconv.Atoi(parts[0])
	if err != nil {
		return kernelVersion{}, false
	}
	minor, err := strconv.Atoi(parts[1])
	if err != nil {
		return kernelVersion{}, false
	}
	patch := 0
	if len(parts) >= 3 {
		value, err := strconv.Atoi(parts[2])
		if err == nil {
			patch = value
		}
	}
	return kernelVersion{major: major, minor: minor, patch: patch}, true
}

func kernelBetween(v, min, max kernelVersion) bool {
	return compareKernelVersion(v, min) >= 0 && compareKernelVersion(v, max) <= 0
}

func compareKernelVersion(a, b kernelVersion) int {
	if a.major != b.major {
		return compareInt(a.major, b.major)
	}
	if a.minor != b.minor {
		return compareInt(a.minor, b.minor)
	}
	return compareInt(a.patch, b.patch)
}

func compareNumericVersion(a, b string) int {
	ap := numericVersionParts(a)
	bp := numericVersionParts(b)
	n := len(ap)
	if len(bp) > n {
		n = len(bp)
	}
	for i := 0; i < n; i++ {
		av := 0
		bv := 0
		if i < len(ap) {
			av = ap[i]
		}
		if i < len(bp) {
			bv = bp[i]
		}
		if av != bv {
			return compareInt(av, bv)
		}
	}
	return 0
}

func numericVersionParts(value string) []int {
	if _, rest, ok := strings.Cut(value, ":"); ok {
		value = rest
	}
	var parts []int
	current := ""
	for _, r := range value {
		if r >= '0' && r <= '9' {
			current += string(r)
			continue
		}
		if current != "" {
			part, _ := strconv.Atoi(current)
			parts = append(parts, part)
			current = ""
		}
	}
	if current != "" {
		part, _ := strconv.Atoi(current)
		parts = append(parts, part)
	}
	return parts
}

func stringFromAny(value any) (string, bool) {
	switch v := value.(type) {
	case string:
		return v, true
	case fmt.Stringer:
		return v.String(), true
	default:
		return "", false
	}
}

func int64FromAny(value any) (int64, bool) {
	switch v := value.(type) {
	case int:
		return int64(v), true
	case int64:
		return v, true
	case int32:
		return int64(v), true
	case float64:
		return int64(v), true
	case string:
		n, err := strconv.ParseInt(v, 10, 64)
		return n, err == nil
	default:
		return 0, false
	}
}

func stringSliceContains(raw any, target string) bool {
	switch values := raw.(type) {
	case []string:
		for _, value := range values {
			if value == target {
				return true
			}
		}
	case []any:
		for _, rawValue := range values {
			value, _ := rawValue.(string)
			if value == target {
				return true
			}
		}
	}
	return false
}

func compareInt(a, b int) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	default:
		return 0
	}
}
