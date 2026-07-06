package findings

import (
	"bytes"
	"strings"
	"testing"

	"github.com/ekkoo-z/KubeTrail/internal/model"
)

func TestEvaluateEscapeDetectsCapSysAdmin(t *testing.T) {
	doc := model.Document{
		Facts: []model.Fact{{
			ID: "proc.status_security",
			Value: map[string]any{
				"capabilities": map[string]any{"effective": "0020003fffffffff"},
				"seccomp":      "0",
			},
		}},
	}
	results := EvaluateEscape(doc)
	if len(results) == 0 {
		t.Fatal("expected escape findings")
	}
	found := false
	for _, f := range results {
		if strings.Contains(f.Title, "CAP_SYS_ADMIN") {
			if f.Severity != "high" || f.Confidence != "signal" {
				t.Fatalf("expected CAP_SYS_ADMIN to be high/signal alone, got severity=%s confidence=%s", f.Severity, f.Confidence)
			}
			found = true
		}
	}
	if !found {
		t.Fatal("expected CAP_SYS_ADMIN finding")
	}
}

func TestEvaluateEscapeDetectsRuntimeSocket(t *testing.T) {
	// Socket present without a writableByCurrentUser field: the old code
	// over-reported this as critical. It must now be high/signal (unconfirmed).
	doc := model.Document{
		Facts: []model.Fact{{
			ID:    "filesystem.runtime_sockets",
			Value: []any{map[string]any{"path": "/run/containerd/containerd.sock"}},
		}},
	}
	results := EvaluateEscape(doc)
	var found *Finding
	for i := range results {
		if strings.Contains(results[i].Title, "Runtime socket") {
			found = &results[i]
		}
	}
	if found == nil {
		t.Fatalf("expected runtime socket finding, got %#v", results)
	}
	if found.Severity != "high" || found.Confidence != "signal" {
		t.Fatalf("expected high/signal for unconfirmed socket, got severity=%s confidence=%s", found.Severity, found.Confidence)
	}
}

func TestEvaluateEscapePrefersStructuredPodSpec(t *testing.T) {
	doc := model.Document{
		Facts: []model.Fact{
			{
				ID: "k8s_context.current_pod",
				Value: map[string]any{"spec": map[string]any{
					"hostPID": false,
				}},
			},
			{
				ID: "k8s_profile.current_pod_structured",
				Value: map[string]any{"spec": map[string]any{
					"hostPID": true,
					"containers": []any{map[string]any{
						"name": "app",
						"securityContext": map[string]any{
							"privileged": true,
							"capabilities": map[string]any{
								"add": []any{"SYS_ADMIN"},
							},
						},
					}},
					"volumes": []any{map[string]any{
						"name":     "docker",
						"hostPath": map[string]any{"path": "/var/run/docker.sock"},
					}},
				}},
			},
		},
	}

	results := EvaluateEscape(doc)
	if !hasFinding(results, "Pod spec: hostPID=true") {
		t.Fatalf("expected structured hostPID finding, got %#v", results)
	}
	if !hasFinding(results, "Privileged container: app") {
		t.Fatalf("expected privileged container finding, got %#v", results)
	}
	for _, finding := range results {
		if strings.Contains(finding.Title, "hostPID") && finding.Evidence != "k8s_profile.current_pod_structured" {
			t.Fatalf("expected structured pod evidence, got %#v", finding)
		}
		if strings.Contains(finding.Title, "hostPID") {
			if finding.Severity != "high" || finding.Confidence != "signal" {
				t.Fatalf("expected hostPID to be high/signal alone, got severity=%s confidence=%s", finding.Severity, finding.Confidence)
			}
		}
		if strings.Contains(finding.Title, "Privileged container") && (finding.Severity != "critical" || finding.Confidence != "confirmed") {
			t.Fatalf("expected privileged container critical/confirmed, got severity=%s confidence=%s", finding.Severity, finding.Confidence)
		}
	}
}

func TestEvaluateEscapeDetectsRuntimeVersionCVEs(t *testing.T) {
	doc := model.Document{
		Facts: []model.Fact{{
			ID: "runtime.versions",
			Value: []map[string]any{
				{"name": "docker", "version": "18.09.2", "source": "docker_api"},
				{"name": "runc", "version": "1.0.0-rc5", "source": "cli"},
				{"name": "containerd", "version": "1.4.2", "source": "cli"},
			},
		}},
	}

	results := EvaluateEscape(doc)
	for _, needle := range []string{"Docker CVE-2019-5736", "Runc CVE-2019-5736", "Containerd CVE-2020-15257"} {
		if !hasFinding(results, needle) {
			t.Fatalf("expected %q finding, got %#v", needle, results)
		}
	}
	for _, f := range results {
		if f.Category == "escape" && f.Confidence != "probable" {
			t.Fatalf("runtime CVE findings should be probable, got %#v", f)
		}
	}
}

func TestEvaluateEscapeDetectsProcSysBreakoutSurfaces(t *testing.T) {
	doc := model.Document{
		Facts: []model.Fact{{
			ID: "proc_sys.breakout_surfaces",
			Value: map[string]any{
				"cgroup": map[string]any{
					"releaseAgentPresent": true,
					"releaseAgents": []any{map[string]any{
						"path":           "/sys/fs/cgroup/memory/release_agent",
						"present":        true,
						"writableLikely": true,
					}},
				},
				"kernelHelperPaths": map[string]any{
					"core_pattern": map[string]any{
						"path":           "/proc/sys/kernel/core_pattern",
						"present":        true,
						"writableLikely": true,
					},
				},
				"securityProfiles": map[string]any{
					"apparmor": map[string]any{"profile": "unconfined", "unconfined": true},
					"selinux":  map[string]any{"mode": "Permissive"},
				},
				"userNamespace": map[string]any{
					"initialUserNamespace": true,
				},
				"hostVisibility": map[string]any{
					"hostLikeProcesses": []any{"kthreadd"},
				},
			},
		}},
	}

	results := EvaluateEscape(doc)
	for _, needle := range []string{
		"Writable release_agent",
		"Writable kernel path",
		"AppArmor profile is unconfined",
		"User namespace is not remapped",
		"Host processes visible",
	} {
		if !hasFinding(results, needle) {
			t.Fatalf("expected %q finding, got %#v", needle, results)
		}
	}
}

func TestEvaluateEscapeDetectsWritableBindMountWithoutNosuid(t *testing.T) {
	doc := model.Document{
		Facts: []model.Fact{{
			ID: "filesystem.writable_bind_mounts_without_nosuid",
			Value: map[string]any{"items": []map[string]any{{
				"path":       "/host",
				"confidence": "high",
				"reason":     "Kubernetes hostPath mount source/root",
			}}},
		}},
	}

	results := EvaluateEscape(doc)
	if !hasFinding(results, "Writable bind mount (no nosuid): /host") {
		t.Fatalf("expected writable bind mount finding, got %#v", results)
	}
}

func TestEvaluateRBACDetectsClusterAdmin(t *testing.T) {
	doc := model.Document{
		Facts: []model.Fact{{
			ID:    "k8s_permissions.expanded_wildcards",
			Value: map[string]any{"clusterAdmin": true},
		}},
	}
	results := EvaluateRBAC(doc)
	if len(results) == 0 {
		t.Fatal("expected RBAC findings")
	}
	if results[0].Severity != "critical" || !strings.Contains(results[0].Title, "Cluster-admin") {
		t.Fatalf("unexpected finding: %+v", results[0])
	}
}

func TestEvaluateRBACDetectsHighValueAccess(t *testing.T) {
	doc := model.Document{
		Facts: []model.Fact{{
			ID: "k8s_permissions.high_value_access",
			Value: []any{
				map[string]any{"id": "pods_exec", "allowed": true},
				map[string]any{"id": "secrets_list", "allowed": true},
				map[string]any{"id": "nodes_proxy_get", "allowed": true},
				map[string]any{"id": "pods_create", "allowed": true},
				map[string]any{"id": "configmaps_list", "allowed": true},
			},
		}},
	}
	results := EvaluateRBAC(doc)
	severities := map[string]int{}
	for _, f := range results {
		severities[f.Severity]++
	}
	if severities["critical"] < 2 {
		t.Fatalf("expected at least 2 critical findings, got %d", severities["critical"])
	}
}

func TestEvaluateScanFilter(t *testing.T) {
	doc := model.Document{
		Facts: []model.Fact{
			{ID: "proc.status_security", Value: map[string]any{
				"capabilities": map[string]any{"effective": "0020003fffffffff"},
				"seccomp":      "2",
			}},
			{ID: "k8s_permissions.high_value_access", Value: []any{
				map[string]any{"id": "pods_exec", "allowed": true},
			}},
		},
	}

	escapeOnly := Evaluate(doc, []string{"escape"})
	for _, f := range escapeOnly {
		if f.Category != "escape" {
			t.Fatalf("escape-only scan returned category %q", f.Category)
		}
	}

	rbacOnly := Evaluate(doc, []string{"rbac"})
	for _, f := range rbacOnly {
		if f.Category != "rbac" {
			t.Fatalf("rbac-only scan returned category %q", f.Category)
		}
	}
}

func TestRenderEscapeBoxSeparatesConfirmedFromSignals(t *testing.T) {
	var buf bytes.Buffer
	results := []Finding{
		{Severity: "critical", Category: "escape", Confidence: "probable", Title: "Probable escape: SYS_ADMIN", Evidence: "proc_sys"},
		{Severity: "high", Category: "escape", Confidence: "signal", Title: "CAP_SYS_ADMIN in effective cap", Evidence: "proc.status_security"},
		{Severity: "medium", Category: "lpe", Confidence: "signal", Title: "Dirty Pipe", Evidence: "lpe.kernel"},
	}
	Render(&buf, results, false, "out.json")
	out := buf.String()
	if !strings.Contains(out, "Confirmed / Probable Container Escape") {
		t.Fatalf("missing escape box header: %s", out)
	}
	escapeBoxEnd := strings.Index(out, "Attack Surface Risk Findings")
	if escapeBoxEnd < 0 {
		t.Fatalf("missing surface box header: %s", out)
	}
	probableIdx := strings.Index(out, "Probable escape: SYS_ADMIN")
	if probableIdx < 0 || probableIdx > escapeBoxEnd {
		t.Fatalf("probable escape must appear in the escape box (before surface box): %s", out)
	}
	signalIdx := strings.Index(out, "CAP_SYS_ADMIN in effective cap")
	if signalIdx < escapeBoxEnd {
		t.Fatalf("signal-level escape must remain in surface box, not escape box: %s", out)
	}
}

func TestRenderNoFindings(t *testing.T) {
	var buf bytes.Buffer
	Render(&buf, nil, false, "out.json")
	if !strings.Contains(buf.String(), "No high-risk findings") {
		t.Fatalf("unexpected output: %s", buf.String())
	}
}

func TestRenderWithFindings(t *testing.T) {
	var buf bytes.Buffer
	results := []Finding{
		{Severity: "medium", Category: "lpe", Title: "Dirty Pipe", Evidence: "lpe.kernel"},
		{Severity: "critical", Category: "escape", Title: "CAP_SYS_ADMIN", Evidence: "proc.status_security"},
		{Severity: "high", Category: "rbac", Title: "secrets readable", Evidence: "k8s_permissions"},
	}
	Render(&buf, results, false, "dbus.json")
	out := buf.String()
	if !strings.Contains(out, "Attack Surface Risk Findings") {
		t.Fatal("missing global findings header")
	}
	if !strings.Contains(out, "FINDING") {
		t.Fatal("missing finding column")
	}
	criticalIndex := strings.Index(out, "CAP_SYS_ADMIN")
	highIndex := strings.Index(out, "secrets readable")
	mediumIndex := strings.Index(out, "Dirty Pipe")
	if criticalIndex < 0 || highIndex < 0 || mediumIndex < 0 {
		t.Fatalf("missing expected findings in output: %s", out)
	}
	if !(criticalIndex < highIndex && highIndex < mediumIndex) {
		t.Fatalf("findings were not globally sorted by severity: %s", out)
	}
	if !strings.Contains(out, "1 critical") {
		t.Fatal("missing summary count")
	}
	if !strings.Contains(out, "1 medium") {
		t.Fatal("missing medium summary count")
	}
}

func TestSortBySeverityStable(t *testing.T) {
	results := []Finding{
		{Severity: "medium", Title: "medium-a"},
		{Severity: "critical", Title: "critical-a"},
		{Severity: "high", Title: "high-a"},
		{Severity: "critical", Title: "critical-b"},
	}

	SortBySeverity(results)

	want := []string{"critical-a", "critical-b", "high-a", "medium-a"}
	for i, title := range want {
		if results[i].Title != title {
			t.Fatalf("index %d: got %q, want %q; all=%#v", i, results[i].Title, title, results)
		}
	}
}

func TestRuntimeSocketFactsMergedNoDup(t *testing.T) {
	// filesystem.runtime_sockets is path-only; runtime.sockets carries
	// writableByCurrentUser. The evaluator must merge by path and prefer the
	// permission-aware item, emitting a single writable finding (not an
	// unconfirmed duplicate from the path-only source).
	doc := model.Document{
		Facts: []model.Fact{
			{
				ID:    "filesystem.runtime_sockets",
				Value: []any{map[string]any{"path": "/run/docker.sock"}},
			},
			{
				ID: "runtime.sockets",
				Value: []any{map[string]any{
					"path":                  "/run/docker.sock",
					"writableByCurrentUser": true,
				}},
			},
		},
	}
	results := EvaluateEscape(doc)
	writableCount := 0
	unconfirmedCount := 0
	for _, f := range results {
		if strings.Contains(f.Title, "Runtime socket writable") {
			writableCount++
		}
		if strings.Contains(f.Title, "Runtime socket (write unconfirmed)") {
			unconfirmedCount++
		}
	}
	if writableCount != 1 {
		t.Fatalf("expected exactly one writable socket finding, got %d: %#v", writableCount, results)
	}
	if unconfirmedCount != 0 {
		t.Fatalf("expected no unconfirmed duplicate from path-only fact, got %d: %#v", unconfirmedCount, results)
	}
}

func TestPodSpecHostPathSeverityDistinguishes(t *testing.T) {
	doc := model.Document{
		Facts: []model.Fact{{
			ID: "k8s_profile.current_pod_structured",
			Value: map[string]any{"spec": map[string]any{
				"volumes": []any{
					map[string]any{"name": "root", "hostPath": map[string]any{"path": "/"}},
					map[string]any{"name": "data", "hostPath": map[string]any{"path": "/data"}},
				},
			}},
		}},
	}
	results := EvaluateEscape(doc)
	for _, f := range results {
		switch {
		case strings.HasSuffix(f.Title, "/"):
			if f.Severity != "high" {
				t.Fatalf("sensitive hostPath / should be high, got %s", f.Severity)
			}
		case strings.HasSuffix(f.Title, "/data"):
			if f.Severity != "medium" {
				t.Fatalf("non-sensitive hostPath /data should be medium, got %s", f.Severity)
			}
		}
	}
}

func TestCombineRuleAPrivilegedWithHostSurface(t *testing.T) {
	doc := model.Document{
		Facts: []model.Fact{{
			ID: "k8s_profile.current_pod_structured",
			Value: map[string]any{"spec": map[string]any{
				"containers": []any{map[string]any{
					"name":            "app",
					"securityContext": map[string]any{"privileged": true},
				}},
				"volumes": []any{map[string]any{
					"name":     "root",
					"hostPath": map[string]any{"path": "/"},
				}},
			}},
		}},
	}
	results := EvaluateEscape(doc)
	if !hasFinding(results, "Confirmed escape: privileged + host surface") {
		t.Fatalf("expected rule A confirmed escape, got %#v", results)
	}
	for _, f := range results {
		if strings.Contains(f.Title, "Confirmed escape") {
			if f.Severity != "critical" || f.Confidence != "confirmed" {
				t.Fatalf("expected critical/confirmed, got severity=%s confidence=%s", f.Severity, f.Confidence)
			}
		}
	}
}

func TestCombineRuleBSysAdminWithWritableReleaseAgent(t *testing.T) {
	doc := model.Document{
		Facts: []model.Fact{
			{
				ID: "proc.status_security",
				Value: map[string]any{
					"capabilities": map[string]any{"effective": "0020003fffffffff"},
				},
			},
			{
				ID: "proc_sys.breakout_surfaces",
				Value: map[string]any{
					"cgroup": map[string]any{
						"releaseAgents": []any{map[string]any{
							"path":           "/sys/fs/cgroup/memory/release_agent",
							"present":        true,
							"writableLikely": true,
						}},
					},
				},
			},
		},
	}
	results := EvaluateEscape(doc)
	if !hasFinding(results, "Probable escape: CAP_SYS_ADMIN + writable host surface") {
		t.Fatalf("expected rule B probable escape, got %#v", results)
	}
	for _, f := range results {
		if strings.Contains(f.Title, "Probable escape: CAP_SYS_ADMIN") {
			if f.Severity != "critical" || f.Confidence != "probable" {
				t.Fatalf("expected rule B critical/probable, got severity=%s confidence=%s", f.Severity, f.Confidence)
			}
		}
	}
}

func TestCombineRuleCHostPIDWithWritableBind(t *testing.T) {
	doc := model.Document{
		Facts: []model.Fact{
			{
				ID:    "k8s_profile.current_pod_structured",
				Value: map[string]any{"spec": map[string]any{"hostPID": true}},
			},
			{
				ID: "filesystem.writable_bind_mounts_without_nosuid",
				Value: map[string]any{"items": []map[string]any{{
					"path":       "/host",
					"confidence": "high",
					"reason":     "Kubernetes hostPath mount source/root",
				}}},
			},
		},
	}
	results := EvaluateEscape(doc)
	if !hasFinding(results, "Probable escape: host PID + writable host path") {
		t.Fatalf("expected rule C probable escape, got %#v", results)
	}
	for _, f := range results {
		if strings.Contains(f.Title, "Probable escape: host PID namespace") {
			if f.Severity != "critical" || f.Confidence != "probable" {
				t.Fatalf("expected rule C critical/probable, got severity=%s confidence=%s", f.Severity, f.Confidence)
			}
		}
	}
}

func TestCombineRuleDRuntimeSocketWritable(t *testing.T) {
	doc := model.Document{
		Facts: []model.Fact{{
			ID: "runtime.sockets",
			Value: []any{map[string]any{
				"path":                  "/run/docker.sock",
				"writableByCurrentUser": true,
			}},
		}},
	}
	results := EvaluateEscape(doc)
	if !hasFinding(results, "Runtime socket writable: /run/docker.sock") {
		t.Fatalf("expected writable runtime socket finding, got %#v", results)
	}
	for _, f := range results {
		if strings.Contains(f.Title, "Runtime socket writable") {
			if f.Severity != "critical" || f.Confidence != "probable" {
				t.Fatalf("expected critical/probable, got severity=%s confidence=%s", f.Severity, f.Confidence)
			}
		}
	}
}

func TestSysAdminAloneIsNotUpgraded(t *testing.T) {
	doc := model.Document{
		Facts: []model.Fact{{
			ID: "proc.status_security",
			Value: map[string]any{
				"capabilities": map[string]any{"effective": "0020003fffffffff"},
				"seccomp":      "2",
			},
		}},
	}
	results := EvaluateEscape(doc)
	for _, f := range results {
		if strings.Contains(f.Title, "Probable escape") || strings.Contains(f.Title, "Confirmed escape") {
			t.Fatalf("CAP_SYS_ADMIN alone must not trigger a combine upgrade, got %#v", f)
		}
	}
}

// Regression: collectors emit capabilities as map[string]string (proc.go), not
// map[string]any. evaluateCaps and collectEscapeSignalSet must read cap bits
// through mapFromAny so CAP_SYS_ADMIN is detected and rule B can fire.
func TestCapsDecodedFromMapStringString(t *testing.T) {
	doc := model.Document{
		Facts: []model.Fact{
			{
				ID: "proc.status_security",
				Value: map[string]any{
					"capabilities": map[string]string{
						"effective": "000001ffffffffff", // bits 0..52 set, incl. SYS_ADMIN(21)
					},
					"seccomp":    "0",
					"noNewPrivs": "0",
				},
			},
			{
				ID:    "proc.cgroup_writable",
				Value: map[string]any{"writable": true},
			},
		},
	}
	results := EvaluateEscape(doc)
	var sawSysAdmin bool
	for _, f := range results {
		if f.Title == "CAP_SYS_ADMIN in effective caps" {
			sawSysAdmin = true
		}
	}
	if !sawSysAdmin {
		t.Fatalf("CAP_SYS_ADMIN must be detected from map[string]string caps, got %#v", results)
	}
	if !hasFinding(results, "Probable escape: CAP_SYS_ADMIN + writable host surface") {
		t.Fatalf("SYS_ADMIN + writable cgroup mount should trigger rule B, got %#v", results)
	}
}
