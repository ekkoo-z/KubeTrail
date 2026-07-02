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
		if strings.Contains(f.Title, "CAP_SYS_ADMIN") && f.Severity == "critical" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected CAP_SYS_ADMIN critical finding")
	}
}

func TestEvaluateEscapeDetectsRuntimeSocket(t *testing.T) {
	doc := model.Document{
		Facts: []model.Fact{{
			ID:    "filesystem.runtime_sockets",
			Value: []any{map[string]any{"path": "/run/containerd/containerd.sock"}},
		}},
	}
	results := EvaluateEscape(doc)
	found := false
	for _, f := range results {
		if strings.Contains(f.Title, "Runtime socket") && f.Severity == "critical" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected runtime socket critical finding")
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
		"Writable cgroup release_agent",
		"Writable kernel control path",
		"AppArmor profile is unconfined",
		"User namespace is not remapped",
		"Host-like processes visible",
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
	if !hasFinding(results, "Writable bind mount without nosuid: /host") {
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
	if !strings.Contains(out, "Linux Local Privilege Escalation Risk") {
		t.Fatal("missing lpe section header")
	}
	if !strings.Contains(out, "Container Escape Risk") {
		t.Fatal("missing escape section header")
	}
	if !strings.Contains(out, "RBAC Lateral Movement Risk") {
		t.Fatal("missing RBAC section header")
	}
	if !strings.Contains(out, "1 critical") {
		t.Fatal("missing summary count")
	}
	if !strings.Contains(out, "1 medium") {
		t.Fatal("missing medium summary count")
	}
}
