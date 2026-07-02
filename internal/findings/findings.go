package findings

import (
	"fmt"
	"path"
	"strconv"
	"strings"

	"github.com/ekkoo-z/KubeTrail/internal/model"
)

type Finding = model.Finding

func Evaluate(doc model.Document, scans []string) []Finding {
	runLPE := len(scans) == 0 || hasStr(scans, "lpe")
	runEscape := len(scans) == 0 || hasStr(scans, "escape")
	runRBAC := len(scans) == 0 || hasStr(scans, "rbac")

	var results []Finding
	if runLPE {
		results = append(results, EvaluateLPE(doc)...)
	}
	if runEscape {
		results = append(results, EvaluateEscape(doc)...)
	}
	if runRBAC {
		results = append(results, EvaluateRBAC(doc)...)
	}
	SortBySeverity(results)
	return results
}

func EvaluateEscape(doc model.Document) []Finding {
	var findings []Finding
	facts := indexFacts(doc.Facts)

	if f, ok := facts["proc.status_security"]; ok {
		findings = append(findings, evaluateCaps(f)...)
		findings = append(findings, evaluateSeccomp(f)...)
		findings = append(findings, evaluateNoNewPrivs(f)...)
	}

	selfNS := factMap(facts, "proc.namespaces_self")
	pid1NS := factMap(facts, "proc.namespaces_pid1")
	if selfNS != nil && pid1NS != nil {
		findings = append(findings, evaluateNamespaceSharing(selfNS, pid1NS)...)
	}

	if f, ok := facts["proc.cgroup_writable"]; ok {
		findings = append(findings, evaluateCgroupWritable(f)...)
	}

	if f, ok := facts["proc.cgroup_devices"]; ok {
		findings = append(findings, evaluateCgroupDevices(f)...)
	}

	if f, ok := facts["proc_sys.breakout_surfaces"]; ok {
		findings = append(findings, evaluateProcSysBreakoutSurfaces(f)...)
	}

	if f, ok := facts["filesystem.runtime_sockets"]; ok {
		findings = append(findings, evaluateRuntimeSockets(f)...)
	}
	if f, ok := facts["runtime.sockets"]; ok {
		findings = append(findings, evaluateRuntimeSockets(f)...)
	}
	if f, ok := facts["runtime.versions"]; ok {
		findings = append(findings, evaluateRuntimeVersions(f)...)
	}

	if f, ok := facts["filesystem.volume_hints"]; ok {
		findings = append(findings, evaluateVolumeHints(f)...)
	}
	if f, ok := facts["filesystem.writable_bind_mounts_without_nosuid"]; ok {
		findings = append(findings, evaluateWritableBindMountsWithoutNosuid(f)...)
	}

	if f, ok := facts["k8s_profile.current_pod_structured"]; ok {
		findings = append(findings, evaluatePodSpec(f, "k8s_profile.current_pod_structured")...)
	} else if f, ok := facts["k8s_context.current_pod"]; ok {
		findings = append(findings, evaluatePodSpec(f, "k8s_context.current_pod")...)
	}

	return findings
}

func EvaluateRBAC(doc model.Document) []Finding {
	var findings []Finding
	facts := indexFacts(doc.Facts)

	if f, ok := facts["k8s_permissions.expanded_wildcards"]; ok {
		findings = append(findings, evaluateExpandedWildcards(f)...)
	}

	if f, ok := facts["k8s_permissions.high_value_access"]; ok {
		findings = append(findings, evaluateHighValueAccess(f)...)
	}

	return findings
}

func evaluateCaps(f model.Fact) []Finding {
	var findings []Finding
	val, ok := f.Value.(map[string]any)
	if !ok {
		return nil
	}
	caps, ok := val["capabilities"].(map[string]any)
	if !ok {
		return nil
	}
	effStr, _ := caps["effective"].(string)
	if effStr == "" {
		return nil
	}

	eff, err := strconv.ParseUint(effStr, 16, 64)
	if err != nil {
		return nil
	}

	type capCheck struct {
		bit      uint
		name     string
		severity string
	}
	checks := []capCheck{
		{21, "CAP_SYS_ADMIN", "critical"},
		{19, "CAP_SYS_PTRACE", "high"},
		{12, "CAP_NET_ADMIN", "medium"},
		{2, "CAP_DAC_READ_SEARCH", "medium"},
		{23, "CAP_SYS_RAWIO", "high"},
		{16, "CAP_SYS_MODULE", "critical"},
	}
	for _, c := range checks {
		if eff&(1<<c.bit) != 0 {
			findings = append(findings, Finding{
				Severity:    c.severity,
				Category:    "escape",
				Title:       fmt.Sprintf("%s in effective capabilities", c.name),
				Description: fmt.Sprintf("Capability bit %d set in CapEff=%s", c.bit, effStr),
				Evidence:    "proc.status_security",
			})
		}
	}
	return findings
}

func evaluateSeccomp(f model.Fact) []Finding {
	val, ok := f.Value.(map[string]any)
	if !ok {
		return nil
	}
	seccomp, _ := val["seccomp"].(string)
	if seccomp == "0" {
		return []Finding{{
			Severity:    "high",
			Category:    "escape",
			Title:       "Seccomp disabled",
			Description: "No seccomp profile active (Seccomp=0)",
			Evidence:    "proc.status_security",
		}}
	}
	return nil
}

func evaluateNoNewPrivs(f model.Fact) []Finding {
	val, ok := f.Value.(map[string]any)
	if !ok {
		return nil
	}
	noNewPrivs, _ := val["noNewPrivs"].(string)
	if noNewPrivs == "0" {
		return []Finding{{
			Severity:    "medium",
			Category:    "escape",
			Title:       "NoNewPrivs disabled",
			Description: "NoNewPrivs=0 allows privilege-gaining exec transitions if another vector is present",
			Evidence:    "proc.status_security",
		}}
	}
	return nil
}

func evaluateNamespaceSharing(selfNS, pid1NS map[string]any) []Finding {
	var findings []Finding
	type nsCheck struct {
		name     string
		title    string
		severity string
	}
	checks := []nsCheck{
		{"pid", "Host PID namespace shared", "high"},
		{"net", "Host network namespace shared", "high"},
		{"mnt", "Host mount namespace shared", "critical"},
	}
	for _, c := range checks {
		selfVal, _ := selfNS[c.name].(string)
		pid1Val, _ := pid1NS[c.name].(string)
		if selfVal != "" && selfVal == pid1Val {
			findings = append(findings, Finding{
				Severity:    c.severity,
				Category:    "escape",
				Title:       c.title,
				Description: fmt.Sprintf("Process ns/%s matches PID 1: %s", c.name, selfVal),
				Evidence:    "proc.namespaces_self",
			})
		}
	}
	return findings
}

func evaluateCgroupWritable(f model.Fact) []Finding {
	val, ok := f.Value.(map[string]any)
	if !ok {
		return nil
	}
	writable, _ := val["writable"].(bool)
	if writable {
		return []Finding{{
			Severity:    "high",
			Category:    "escape",
			Title:       "Writable cgroup mount (release_agent escape)",
			Description: "Cgroup filesystem mounted read-write inside container",
			Evidence:    "proc.cgroup_writable",
		}}
	}
	return nil
}

func evaluateCgroupDevices(f model.Fact) []Finding {
	val, ok := f.Value.(map[string]any)
	if !ok {
		return nil
	}
	blockWrite, _ := val["blockWriteAllowed"].(bool)
	if blockWrite {
		return []Finding{{
			Severity:    "high",
			Category:    "escape",
			Title:       "Block device write access allowed",
			Description: "Cgroup devices.list permits write to block devices (host disk access)",
			Evidence:    "proc.cgroup_devices",
		}}
	}
	return nil
}

func evaluateRuntimeSockets(f model.Fact) []Finding {
	items := sliceMapsFromAny(f.Value)
	if len(items) == 0 {
		return nil
	}
	var criticalPaths []string
	var visiblePaths []string
	for _, item := range items {
		path, _ := item["path"].(string)
		if path == "" {
			continue
		}
		visiblePaths = append(visiblePaths, path)
		writable, hasWritable := item["writableByCurrentUser"].(bool)
		_, hasDockerInfo := item["dockerInfo"].(map[string]any)
		if writable || hasDockerInfo || !hasWritable {
			criticalPaths = append(criticalPaths, path)
		}
	}
	if len(visiblePaths) == 0 {
		return nil
	}
	if len(criticalPaths) == 0 {
		return []Finding{{
			Severity:    "high",
			Category:    "escape",
			Title:       fmt.Sprintf("Runtime socket visible: %s", strings.Join(visiblePaths, ", ")),
			Description: "Container runtime socket exists but current-user write/API access was not confirmed",
			Evidence:    f.ID,
		}}
	}
	return []Finding{{
		Severity:    "critical",
		Category:    "escape",
		Title:       fmt.Sprintf("Runtime socket accessible: %s", strings.Join(criticalPaths, ", ")),
		Description: "Runtime socket is writable, Docker API-responsive, or comes from a legacy socket fact without permission metadata",
		Evidence:    f.ID,
	}}
}

func evaluateRuntimeVersions(f model.Fact) []Finding {
	var findings []Finding
	for _, item := range sliceMapsFromAny(f.Value) {
		name := strings.ToLower(toFindingString(item["name"]))
		version := toFindingString(item["version"])
		source := toFindingString(item["source"])
		if name == "" || version == "" {
			continue
		}
		add := func(severity, cve, detail string) {
			findings = append(findings, Finding{
				Severity:    severity,
				Category:    "escape",
				Title:       fmt.Sprintf("%s %s version range: %s", strings.Title(name), cve, version),
				Description: fmt.Sprintf("%s source=%s; version-only evidence, vendor backports still need confirmation", detail, source),
				Evidence:    "runtime.versions",
			})
		}
		switch name {
		case "docker":
			if source != "docker_api" {
				continue
			}
			if compareNumericVersion(version, "18.09.3") < 0 {
				add("high", "CVE-2019-5736", "Docker daemon ServerVersion is below the PEASS 18.09.3 threshold")
			}
			if compareNumericVersion(version, "18.09.5") < 0 {
				add("medium", "CVE-2019-13139", "Docker daemon ServerVersion is below the PEASS 18.09.5 threshold")
			}
			if compareNumericVersion(version, "20.10.9") < 0 {
				add("medium", "CVE-2021-41091", "Docker daemon ServerVersion is below the PEASS 20.10.9 threshold")
			}
		case "runc":
			if runcAffectedCVE20195736(version) {
				add("high", "CVE-2019-5736", "runc version appears older than the fixed rc6/1.0.0 lineage")
			}
		case "containerd":
			if containerdAffectedCVE202015257(version) {
				add("high", "CVE-2020-15257", "containerd version is in a public vulnerable range before 1.3.9 or before 1.4.3")
			}
		case "alpine":
			if compareNumericVersion(version, "3.3.0") >= 0 && compareNumericVersion(version, "3.6.0") <= 0 {
				add("medium", "CVE-2019-5021", "Alpine release falls in the PEASS default-root-password heuristic range")
			}
		}
	}
	return findings
}

func evaluateVolumeHints(f model.Fact) []Finding {
	var hostPaths []string
	for _, m := range sliceMapsFromAny(f.Value) {
		kind, _ := m["kind"].(string)
		path, _ := m["path"].(string)
		if kind == "hostPath" && path != "" {
			hostPaths = append(hostPaths, path)
		}
	}
	if len(hostPaths) == 0 {
		return nil
	}
	var findings []Finding
	for _, p := range hostPaths {
		findings = append(findings, Finding{
			Severity:    "high",
			Category:    "escape",
			Title:       fmt.Sprintf("hostPath volume mounted: %s", p),
			Description: "Host filesystem path mounted into container",
			Evidence:    "filesystem.volume_hints",
		})
	}
	return findings
}

func evaluatePodSpec(f model.Fact, evidence string) []Finding {
	val, ok := f.Value.(map[string]any)
	if !ok {
		return nil
	}
	spec, _ := val["spec"].(map[string]any)
	if spec == nil {
		return nil
	}

	var findings []Finding

	if hostPID, _ := spec["hostPID"].(bool); hostPID {
		findings = append(findings, Finding{
			Severity: "critical", Category: "escape",
			Title: "Pod spec: hostPID=true", Description: "Pod shares host PID namespace",
			Evidence: evidence,
		})
	}
	if hostNet, _ := spec["hostNetwork"].(bool); hostNet {
		findings = append(findings, Finding{
			Severity: "high", Category: "escape",
			Title: "Pod spec: hostNetwork=true", Description: "Pod shares host network namespace",
			Evidence: evidence,
		})
	}
	if hostIPC, _ := spec["hostIPC"].(bool); hostIPC {
		findings = append(findings, Finding{
			Severity: "high", Category: "escape",
			Title: "Pod spec: hostIPC=true", Description: "Pod shares host IPC namespace",
			Evidence: evidence,
		})
	}

	containers := sliceMapsFromAny(spec["containers"])
	for _, c := range containers {
		cm := c
		sc := mapFromAny(cm["securityContext"])
		if sc == nil {
			continue
		}
		if priv, _ := sc["privileged"].(bool); priv {
			name, _ := cm["name"].(string)
			findings = append(findings, Finding{
				Severity: "critical", Category: "escape",
				Title:       fmt.Sprintf("Privileged container: %s", name),
				Description: "Container runs in privileged mode with full host access",
				Evidence:    evidence,
			})
		}
		if ape, _ := sc["allowPrivilegeEscalation"].(bool); ape {
			name, _ := cm["name"].(string)
			findings = append(findings, Finding{
				Severity: "medium", Category: "escape",
				Title:       fmt.Sprintf("allowPrivilegeEscalation=true: %s", name),
				Description: "Container explicitly allows privilege escalation across exec transitions",
				Evidence:    evidence,
			})
		}
		if seccomp := mapFromAny(sc["seccompProfile"]); strings.EqualFold(toFindingString(seccomp["type"]), "Unconfined") {
			name, _ := cm["name"].(string)
			findings = append(findings, Finding{
				Severity: "high", Category: "escape",
				Title:       fmt.Sprintf("Unconfined seccomp profile: %s", name),
				Description: "Container securityContext sets seccompProfile.type=Unconfined",
				Evidence:    evidence,
			})
		}
		caps := mapFromAny(sc["capabilities"])
		for _, capName := range stringSliceFromAny(caps["add"]) {
			if dangerousPodCapability(capName) {
				name, _ := cm["name"].(string)
				findings = append(findings, Finding{
					Severity: "high", Category: "escape",
					Title:       fmt.Sprintf("Pod spec adds dangerous capability %s: %s", capName, name),
					Description: "Container securityContext.capabilities.add contains a capability commonly used in container breakouts",
					Evidence:    evidence,
				})
			}
		}
	}

	if podSC := mapFromAny(spec["securityContext"]); podSC != nil {
		if seccomp := mapFromAny(podSC["seccompProfile"]); strings.EqualFold(toFindingString(seccomp["type"]), "Unconfined") {
			findings = append(findings, Finding{
				Severity: "high", Category: "escape",
				Title: "Pod seccomp profile is Unconfined", Description: "Pod-level securityContext disables seccomp filtering",
				Evidence: evidence,
			})
		}
	}

	for _, volume := range sliceMapsFromAny(spec["volumes"]) {
		hostPath := mapFromAny(volume["hostPath"])
		path := toFindingString(hostPath["path"])
		if path == "" {
			continue
		}
		severity := "high"
		if dangerousHostPath(path) {
			severity = "critical"
		}
		findings = append(findings, Finding{
			Severity:    severity,
			Category:    "escape",
			Title:       fmt.Sprintf("Pod spec hostPath: %s", path),
			Description: "Current Pod spec mounts a hostPath volume; severity is based on the mounted host path",
			Evidence:    evidence,
		})
	}

	return findings
}

func evaluateWritableBindMountsWithoutNosuid(f model.Fact) []Finding {
	value := mapFromAny(f.Value)
	if value == nil {
		return nil
	}
	var findings []Finding
	for _, item := range sliceMapsFromAny(value["items"]) {
		path := toFindingString(item["path"])
		confidence := toFindingString(item["confidence"])
		if path == "" {
			continue
		}
		severity := "medium"
		if confidence == "high" {
			severity = "high"
		}
		findings = append(findings, Finding{
			Severity:    severity,
			Category:    "escape",
			Title:       fmt.Sprintf("Writable bind mount without nosuid: %s", path),
			Description: fmt.Sprintf("Mount is rw and lacks nosuid; confidence=%s reason=%s", confidence, toFindingString(item["reason"])),
			Evidence:    "filesystem.writable_bind_mounts_without_nosuid",
		})
	}
	return findings
}

func evaluateProcSysBreakoutSurfaces(f model.Fact) []Finding {
	value := mapFromAny(f.Value)
	if value == nil {
		return nil
	}
	var findings []Finding
	findings = append(findings, evaluateCgroupReleaseAgents(mapFromAny(value["cgroup"]))...)
	findings = append(findings, evaluateKernelHelperPaths(mapFromAny(value["kernelHelperPaths"]))...)
	findings = append(findings, evaluateSensitiveExposures(mapFromAny(value["sensitiveExposures"]))...)
	findings = append(findings, evaluateSecurityProfiles(mapFromAny(value["securityProfiles"]))...)
	findings = append(findings, evaluateUserNamespaceMapping(mapFromAny(value["userNamespace"]))...)
	findings = append(findings, evaluateHostVisibility(mapFromAny(value["hostVisibility"]))...)
	return findings
}

func evaluateExpandedWildcards(f model.Fact) []Finding {
	val, ok := f.Value.(map[string]any)
	if !ok {
		return nil
	}
	isAdmin, _ := val["clusterAdmin"].(bool)
	if isAdmin {
		return []Finding{{
			Severity:    "critical",
			Category:    "rbac",
			Title:       "Cluster-admin equivalent permissions",
			Description: "Identity has verbs=* resources=* apiGroups=* — full cluster control",
			Evidence:    "k8s_permissions.expanded_wildcards",
		}}
	}
	return nil
}

func evaluateHighValueAccess(f model.Fact) []Finding {
	type accessRule struct {
		ids      []string
		title    string
		severity string
	}
	rules := []accessRule{
		{[]string{"pods_exec", "pods_attach"}, "pods/exec allowed — lateral movement to any pod", "critical"},
		{[]string{"nodes_proxy_get", "nodes_proxy_create"}, "nodes/proxy allowed — kubelet API access on any node", "critical"},
		{[]string{"roles_escalate", "clusterroles_escalate"}, "RBAC escalate — can grant self higher privileges", "critical"},
		{[]string{"serviceaccounts_impersonate", "users_impersonate", "groups_impersonate"}, "Impersonation allowed — act as any identity", "critical"},
		{[]string{"kube_system_secrets_get", "kube_system_secrets_list"}, "kube-system secrets readable — control-plane credentials", "critical"},
		{[]string{"secrets_get", "secrets_list"}, "Secrets readable in namespace", "high"},
		{[]string{"serviceaccounts_token_create"}, "SA token creation — mint arbitrary service account JWTs", "high"},
		{[]string{"rolebindings_create", "clusterrolebindings_create"}, "RoleBinding create — grant roles to any identity", "high"},
		{[]string{"mutatingwebhook_create", "mutatingwebhook_update", "mutatingwebhook_patch"}, "MutatingWebhook control — intercept all API requests", "high"},
		{[]string{"pods_create"}, "Pod creation allowed — can spawn attacker workloads", "medium"},
		{[]string{"daemonsets_create"}, "DaemonSet creation — deploy to all nodes", "medium"},
	}

	allowed := map[string]bool{}
	for _, m := range sliceMapsFromAny(f.Value) {
		id, _ := m["id"].(string)
		isAllowed, _ := m["allowed"].(bool)
		if isAllowed {
			allowed[id] = true
		}
	}

	var findings []Finding
	seen := map[string]bool{}
	for _, rule := range rules {
		for _, id := range rule.ids {
			if allowed[id] && !seen[rule.title] {
				seen[rule.title] = true
				findings = append(findings, Finding{
					Severity:    rule.severity,
					Category:    "rbac",
					Title:       rule.title,
					Description: fmt.Sprintf("Access review %s returned allowed=true", id),
					Evidence:    "k8s_permissions.high_value_access",
				})
				break
			}
		}
	}
	return findings
}

func evaluateCgroupReleaseAgents(cgroup map[string]any) []Finding {
	if cgroup == nil {
		return nil
	}
	var findings []Finding
	for _, item := range sliceMapsFromAny(cgroup["releaseAgents"]) {
		pathValue := toFindingString(item["path"])
		if pathValue == "" || !boolFromAny(item["present"]) {
			continue
		}
		if boolFromAny(item["writableLikely"]) || boolFromAny(item["writableByCurrentUser"]) {
			findings = append(findings, Finding{
				Severity:    "high",
				Category:    "escape",
				Title:       fmt.Sprintf("Writable cgroup release_agent: %s", pathValue),
				Description: "release_agent is visible and writable from the current context, matching the classic cgroup v1 breakout primitive",
				Evidence:    "proc_sys.breakout_surfaces",
			})
		}
	}

	writableMounts := mapFromAny(cgroup["writableCgroupMounts"])
	if boolFromAny(cgroup["releaseAgentPresent"]) && boolFromAny(writableMounts["writable"]) {
		findings = append(findings, Finding{
			Severity:    "high",
			Category:    "escape",
			Title:       "Cgroup release_agent files visible with writable cgroup mount",
			Description: "release_agent files are present and at least one cgroup filesystem is mounted rw inside the container",
			Evidence:    "proc_sys.breakout_surfaces",
		})
	}
	return findings
}

func evaluateKernelHelperPaths(paths map[string]any) []Finding {
	if paths == nil {
		return nil
	}
	var findings []Finding
	for id, raw := range paths {
		item := mapFromAny(raw)
		if item == nil || !boolFromAny(item["present"]) {
			continue
		}
		if !boolFromAny(item["writableLikely"]) && !boolFromAny(item["writableByCurrentUser"]) {
			continue
		}
		pathValue := toFindingString(item["path"])
		severity := "medium"
		switch id {
		case "core_pattern", "modprobe", "binfmt_misc_register", "uevent_helper", "sysrq_trigger":
			severity = "high"
		}
		findings = append(findings, Finding{
			Severity:    severity,
			Category:    "escape",
			Title:       fmt.Sprintf("Writable kernel control path: %s", pathValue),
			Description: fmt.Sprintf("%s is writable and can affect kernel helper or host-control behavior", id),
			Evidence:    "proc_sys.breakout_surfaces",
		})
	}
	return findings
}

func evaluateSensitiveExposures(exposures map[string]any) []Finding {
	if exposures == nil {
		return nil
	}
	var findings []Finding
	for id, raw := range exposures {
		item := mapFromAny(raw)
		if item == nil || !boolFromAny(item["present"]) {
			continue
		}
		pathValue := toFindingString(item["path"])
		if pathValue == "" {
			continue
		}
		if boolFromAny(item["writableLikely"]) || boolFromAny(item["writableByCurrentUser"]) {
			switch id {
			case "sys_kernel_debug", "sys_kernel_security", "sys_kernel_vmcoreinfo", "efi_vars", "efi_efivars", "sys_firmware":
				findings = append(findings, Finding{
					Severity:    "high",
					Category:    "escape",
					Title:       fmt.Sprintf("Writable sensitive kernel surface: %s", pathValue),
					Description: fmt.Sprintf("%s is writable from the current context", id),
					Evidence:    "proc_sys.breakout_surfaces",
				})
			}
			continue
		}
		if !boolFromAny(item["readableByCurrentUser"]) {
			continue
		}
		switch id {
		case "proc_kcore", "proc_kmem", "proc_mem":
			findings = append(findings, Finding{
				Severity:    "high",
				Category:    "escape",
				Title:       fmt.Sprintf("Readable host memory interface: %s", pathValue),
				Description: fmt.Sprintf("%s is readable from the current context", id),
				Evidence:    "proc_sys.breakout_surfaces",
			})
		case "proc_kmsg", "proc_keys":
			findings = append(findings, Finding{
				Severity:    "medium",
				Category:    "escape",
				Title:       fmt.Sprintf("Readable sensitive proc surface: %s", pathValue),
				Description: fmt.Sprintf("%s is readable from the current context", id),
				Evidence:    "proc_sys.breakout_surfaces",
			})
		}
	}
	return findings
}

func evaluateSecurityProfiles(profiles map[string]any) []Finding {
	if profiles == nil {
		return nil
	}
	var findings []Finding
	apparmor := mapFromAny(profiles["apparmor"])
	if apparmor != nil {
		profile := strings.ToLower(toFindingString(apparmor["profile"]))
		if boolFromAny(apparmor["unconfined"]) || strings.Contains(profile, "unconfined") {
			findings = append(findings, Finding{
				Severity:    "high",
				Category:    "escape",
				Title:       "AppArmor profile is unconfined",
				Description: "Current process attr reports an unconfined AppArmor profile",
				Evidence:    "proc_sys.breakout_surfaces",
			})
		}
		if enabledRaw := toFindingString(apparmor["enabledRaw"]); enabledRaw != "" && !boolFromAny(apparmor["enabled"]) {
			findings = append(findings, Finding{
				Severity:    "medium",
				Category:    "escape",
				Title:       "AppArmor appears disabled",
				Description: fmt.Sprintf("AppArmor enabled flag is %q", enabledRaw),
				Evidence:    "proc_sys.breakout_surfaces",
			})
		}
	}

	selinux := mapFromAny(profiles["selinux"])
	if selinux != nil {
		switch strings.ToLower(toFindingString(selinux["mode"])) {
		case "disabled":
			findings = append(findings, Finding{
				Severity:    "medium",
				Category:    "escape",
				Title:       "SELinux appears disabled",
				Description: "SELinux filesystem is not present in the current root view",
				Evidence:    "proc_sys.breakout_surfaces",
			})
		case "permissive":
			findings = append(findings, Finding{
				Severity:    "medium",
				Category:    "escape",
				Title:       "SELinux is permissive",
				Description: "SELinux enforce flag is 0",
				Evidence:    "proc_sys.breakout_surfaces",
			})
		}
	}
	return findings
}

func evaluateUserNamespaceMapping(userns map[string]any) []Finding {
	if userns == nil {
		return nil
	}
	if boolFromAny(userns["initialUserNamespace"]) {
		return []Finding{{
			Severity:    "medium",
			Category:    "escape",
			Title:       "User namespace is not remapped",
			Description: "uid_map indicates the current process is in the initial user namespace, so container root maps directly to host root",
			Evidence:    "proc_sys.breakout_surfaces",
		}}
	}
	if boolFromAny(userns["containerRootMapsHostRoot"]) {
		return []Finding{{
			Severity:    "medium",
			Category:    "escape",
			Title:       "Container root maps to host root",
			Description: "uid_map starts at container ID 0 and host ID 0, so userns remapping does not isolate root",
			Evidence:    "proc_sys.breakout_surfaces",
		}}
	}
	return nil
}

func evaluateHostVisibility(host map[string]any) []Finding {
	if host == nil {
		return nil
	}
	hostProcesses := stringSliceFromAny(host["hostLikeProcesses"])
	if len(hostProcesses) > 0 {
		return []Finding{{
			Severity:    "high",
			Category:    "escape",
			Title:       fmt.Sprintf("Host-like processes visible: %s", strings.Join(hostProcesses, ", ")),
			Description: "Process table includes host services or kernel process names, suggesting host PID namespace exposure",
			Evidence:    "proc_sys.breakout_surfaces",
		}}
	}
	if boolFromAny(host["procHeavilyPopulated"]) && boolFromAny(host["devHeavilyPopulated"]) {
		return []Finding{{
			Severity:    "medium",
			Category:    "escape",
			Title:       "Host-like /proc and /dev visibility",
			Description: fmt.Sprintf("procPidCount=%s devCharDeviceCount=%s", toFindingString(host["procPidCount"]), toFindingString(host["devCharDeviceCount"])),
			Evidence:    "proc_sys.breakout_surfaces",
		}}
	}
	return nil
}

func indexFacts(facts []model.Fact) map[string]model.Fact {
	out := make(map[string]model.Fact, len(facts))
	for _, f := range facts {
		out[f.ID] = f
	}
	return out
}

func factMap(index map[string]model.Fact, id string) map[string]any {
	f, ok := index[id]
	if !ok {
		return nil
	}
	m, _ := f.Value.(map[string]any)
	if m != nil {
		return m
	}
	if typed, ok := f.Value.(map[string]string); ok {
		out := make(map[string]any, len(typed))
		for k, v := range typed {
			out[k] = v
		}
		return out
	}
	return nil
}

func sliceMapsFromAny(value any) []map[string]any {
	switch v := value.(type) {
	case []map[string]any:
		return v
	case []map[string]string:
		out := make([]map[string]any, 0, len(v))
		for _, item := range v {
			out = append(out, mapFromAny(item))
		}
		return out
	case []any:
		out := make([]map[string]any, 0, len(v))
		for _, item := range v {
			if m := mapFromAny(item); m != nil {
				out = append(out, m)
			}
		}
		return out
	case map[string]any:
		if items, ok := v["items"]; ok {
			return sliceMapsFromAny(items)
		}
		return []map[string]any{v}
	default:
		return nil
	}
}

func mapFromAny(value any) map[string]any {
	switch v := value.(type) {
	case map[string]any:
		return v
	case map[string]string:
		out := make(map[string]any, len(v))
		for key, val := range v {
			out[key] = val
		}
		return out
	default:
		return nil
	}
}

func stringSliceFromAny(value any) []string {
	switch v := value.(type) {
	case []string:
		return v
	case []any:
		out := make([]string, 0, len(v))
		for _, item := range v {
			if s := strings.TrimSpace(toFindingString(item)); s != "" {
				out = append(out, s)
			}
		}
		return out
	case string:
		if strings.TrimSpace(v) == "" {
			return nil
		}
		return []string{v}
	default:
		return nil
	}
}

func toFindingString(value any) string {
	switch v := value.(type) {
	case nil:
		return ""
	case string:
		return v
	case []byte:
		return string(v)
	case fmt.Stringer:
		return v.String()
	default:
		return fmt.Sprint(v)
	}
}

func boolFromAny(value any) bool {
	switch v := value.(type) {
	case bool:
		return v
	case string:
		switch strings.ToLower(strings.TrimSpace(v)) {
		case "1", "t", "true", "y", "yes", "enabled":
			return true
		default:
			return false
		}
	case int:
		return v != 0
	case int64:
		return v != 0
	case uint64:
		return v != 0
	case float64:
		return v != 0
	default:
		return false
	}
}

func dangerousPodCapability(name string) bool {
	normalized := strings.ToUpper(strings.TrimSpace(name))
	normalized = strings.TrimPrefix(normalized, "CAP_")
	switch normalized {
	case "ALL", "SYS_ADMIN", "SYS_MODULE", "SYS_PTRACE", "SYS_RAWIO", "DAC_READ_SEARCH", "DAC_OVERRIDE", "NET_ADMIN", "NET_RAW", "SYSLOG", "BPF", "PERFMON":
		return true
	default:
		return false
	}
}

func dangerousHostPath(value string) bool {
	p := path.Clean("/" + strings.TrimPrefix(strings.ReplaceAll(value, "\\", "/"), "/"))
	dangerous := []string{
		"/",
		"/host",
		"/rootfs",
		"/proc",
		"/sys",
		"/dev",
		"/run",
		"/var/run",
		"/var/lib/kubelet",
		"/var/lib/docker",
		"/var/lib/containerd",
		"/etc",
		"/boot",
		"/root",
		"/bin",
		"/sbin",
		"/usr/bin",
		"/usr/sbin",
	}
	for _, candidate := range dangerous {
		if p == candidate {
			return true
		}
		if candidate != "/" && strings.HasPrefix(p, strings.TrimRight(candidate, "/")+"/") {
			return true
		}
	}
	return false
}

func runcAffectedCVE20195736(version string) bool {
	version = strings.ToLower(strings.TrimSpace(version))
	if version == "" {
		return false
	}
	parts := numericVersionParts(version)
	if len(parts) == 0 {
		return false
	}
	if parts[0] == 0 {
		return true
	}
	if parts[0] > 1 {
		return false
	}
	if len(parts) > 1 && parts[1] > 0 {
		return false
	}
	if strings.Contains(version, "rc") {
		rc := runcRCVersion(version)
		return rc > 0 && rc < 6
	}
	return compareNumericVersion(version, "1.0.0") < 0
}

func runcRCVersion(version string) int {
	idx := strings.Index(version, "rc")
	if idx < 0 {
		return 0
	}
	rest := strings.TrimLeft(version[idx+2:], ".-_")
	digits := ""
	for _, r := range rest {
		if r < '0' || r > '9' {
			break
		}
		digits += string(r)
	}
	if digits == "" {
		return 0
	}
	value, _ := strconv.Atoi(digits)
	return value
}

func containerdAffectedCVE202015257(version string) bool {
	version = strings.TrimSpace(version)
	if version == "" {
		return false
	}
	if compareNumericVersion(version, "1.3.9") < 0 {
		return true
	}
	return compareNumericVersion(version, "1.4.0") >= 0 && compareNumericVersion(version, "1.4.3") < 0
}

func hasStr(values []string, target string) bool {
	for _, v := range values {
		if v == target {
			return true
		}
	}
	return false
}
