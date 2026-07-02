package collectors

import (
	"testing"

	"github.com/ekkoo-z/KubeTrail/internal/kube"
	"github.com/ekkoo-z/KubeTrail/internal/model"
)

func TestAccessReviewChecksIncludeClusterScopeAndKubeSystemProbes(t *testing.T) {
	checks := accessReviewChecks("ml-platform")
	byID := make(map[string]accessReviewCheck, len(checks))
	for _, check := range checks {
		if _, exists := byID[check.ID]; exists {
			t.Fatalf("duplicate access review check id: %s", check.ID)
		}
		byID[check.ID] = check
	}

	for _, id := range []string{
		"crd_create",
		"mutatingwebhook_update",
		"validatingwebhook_create",
		"clusterrolebindings_create",
		"nodes_create",
		"storageclass_create",
		"kube_system_pods_create",
		"kube_system_secrets_get",
		"kube_system_secrets_list",
	} {
		if _, ok := byID[id]; !ok {
			t.Fatalf("missing access review check: %s", id)
		}
	}

	if got := byID["kube_system_pods_create"].Attrs.Namespace; got != "kube-system" {
		t.Fatalf("kube_system_pods_create namespace = %q, want kube-system", got)
	}
	if got := byID["kube_system_secrets_get"].Attrs.Namespace; got != "kube-system" {
		t.Fatalf("kube_system_secrets_get namespace = %q, want kube-system", got)
	}
	if got := byID["crd_create"].Attrs.Namespace; got != "" {
		t.Fatalf("crd_create namespace = %q, want cluster-scope empty namespace", got)
	}
}

func TestFocusedAccessReviewChecksUseHighSignalSubset(t *testing.T) {
	focused := accessReviewChecksForMode("ml-platform", model.RBACModeFocused)
	full := accessReviewChecksForMode("ml-platform", model.RBACModeFull)
	if len(focused) == 0 {
		t.Fatal("expected focused checks")
	}
	if len(focused) >= len(full) {
		t.Fatalf("focused checks should be smaller than full: focused=%d full=%d", len(focused), len(full))
	}

	byID := make(map[string]accessReviewCheck, len(focused))
	for _, check := range focused {
		if _, exists := byID[check.ID]; exists {
			t.Fatalf("duplicate focused access review check id: %s", check.ID)
		}
		byID[check.ID] = check
	}

	for _, id := range []string{
		"secrets_list",
		"pods_exec",
		"pods_ephemeralcontainers_patch",
		"serviceaccounts_token_create",
		"nodes_proxy_get",
		"clusterroles_escalate",
		"mutatingwebhook_update",
		"kube_system_secrets_list",
	} {
		if _, ok := byID[id]; !ok {
			t.Fatalf("focused mode missing high-signal check: %s", id)
		}
	}

	for _, id := range []string{
		"configmaps_list",
		"pods_log",
		"events_delete",
		"crd_patch",
		"nodes_get",
	} {
		if _, ok := byID[id]; ok {
			t.Fatalf("focused mode included full-matrix check: %s", id)
		}
	}
}

func TestExpandedWildcardChecksUseDiscoveryForPlatformCRDs(t *testing.T) {
	rules := []kube.ResourceRule{
		{Verbs: []string{"*"}, APIGroups: []string{"jobs.platform.example.io"}, Resources: []string{"*"}},
	}
	checks, _ := expandedWildcardChecks("ml-platform", rules, []kube.APIResource{
		{GroupVersion: "jobs.platform.example.io/v1beta1", Group: "jobs.platform.example.io", Version: "v1beta1", Name: "trainings", Kind: "Training", Namespaced: true},
		{GroupVersion: "jobs.platform.example.io/v1beta1", Group: "jobs.platform.example.io", Version: "v1beta1", Name: "notebooks", Kind: "Notebook", Namespaced: true},
	})

	if len(checks) == 0 {
		t.Fatal("expected expanded wildcard checks")
	}
	assertExpandedCheck(t, checks, "create", "jobs.platform.example.io", "trainings", "ml-platform")
	assertExpandedCheck(t, checks, "patch", "jobs.platform.example.io", "notebooks", "ml-platform")
}

func TestExpandedWildcardChecksKeepClusterScopedResourcesClusterScoped(t *testing.T) {
	rules := []kube.ResourceRule{
		{Verbs: []string{"*"}, APIGroups: []string{"apiextensions.k8s.io"}, Resources: []string{"*"}},
	}
	checks, _ := expandedWildcardChecks("ml-platform", rules, nil)
	assertExpandedCheck(t, checks, "create", "apiextensions.k8s.io", "customresourcedefinitions", "")
}

func TestFocusedWildcardAccessMatrixOnlyReportsClusterAdminEquivalent(t *testing.T) {
	platformWildcard := []kube.ResourceRule{
		{Verbs: []string{"*"}, APIGroups: []string{"jobs.platform.example.io"}, Resources: []string{"*"}},
	}
	result := expandedWildcardAccessMatrixForMode(nil, nil, "ml-platform", platformWildcard, nil, model.RBACModeFocused)
	if result.ClusterAdmin || len(result.Checks) != 0 || result.CheckedCount != 0 {
		t.Fatalf("focused mode should not expand non-admin wildcards: %#v", result)
	}

	clusterAdmin := []kube.ResourceRule{
		{Verbs: []string{"*"}, APIGroups: []string{"*"}, Resources: []string{"*"}},
	}
	result = expandedWildcardAccessMatrixForMode(nil, nil, "ml-platform", clusterAdmin, nil, model.RBACModeFocused)
	if !result.ClusterAdmin || len(result.Checks) != 1 {
		t.Fatalf("focused mode should still report cluster-admin equivalent wildcard: %#v", result)
	}
}

func TestSummarizeDiscoveryResourcesKeepsCountsHashAndHighValueDetails(t *testing.T) {
	resources := []kube.APIResource{
		{GroupVersion: "v1", Group: "", Version: "v1", Name: "secrets", Kind: "Secret", Namespaced: true, Verbs: []string{"get", "list"}},
		{GroupVersion: "example.io/v1", Group: "example.io", Version: "v1", Name: "widgets", Kind: "Widget", Namespaced: true, Verbs: []string{"get", "list", "create"}},
		{GroupVersion: "jobs.platform.example.io/v1", Group: "jobs.platform.example.io", Version: "v1", Name: "trainings", Kind: "Training", Namespaced: true, Verbs: []string{"create"}},
	}

	got := summarizeDiscoveryResources(resources)
	if got["resourceCount"] != 3 {
		t.Fatalf("expected resourceCount=3, got %#v", got)
	}
	groups, _ := got["groups"].([]map[string]any)
	if len(groups) == 0 {
		t.Fatalf("expected group summaries: %#v", got)
	}
	if !groupSummaryHasCounts(groups, "example.io", 1, 0) {
		t.Fatalf("group summary should retain low-signal counts without resource names: %#v", groups)
	}
	if got["omittedLowSignalResourceDetail"] != 1 {
		t.Fatalf("expected one omitted low-signal resource, got %#v", got["omittedLowSignalResourceDetail"])
	}
	if got["resourceIndexSha256"] == "" {
		t.Fatalf("expected resource index hash: %#v", got)
	}
	highValue, _ := got["highValueResources"].([]map[string]any)
	if !compactAPIResourcePresent(highValue, "", "secrets") {
		t.Fatalf("expected secrets in highValueResources: %#v", highValue)
	}
	if !compactAPIResourcePresent(highValue, "jobs.platform.example.io", "trainings") {
		t.Fatalf("expected platform training CRD in highValueResources: %#v", highValue)
	}
}

func TestCompactAccessReviewMatrixOmitsLowSignalDeniedTraceReasons(t *testing.T) {
	got := compactAccessReviewMatrix([]map[string]any{
		{
			"id":                 "pods_create",
			"description":        "create pods",
			"resourceAttributes": kube.ResourceAttributes{Namespace: "ns", Verb: "create", Resource: "pods"},
			"allowed":            false,
			"denied":             false,
			"reason":             "Not Allowed traceID:1234",
			"evaluationError":    "",
		},
		{
			"id":                 "secrets_list",
			"description":        "list secrets",
			"resourceAttributes": kube.ResourceAttributes{Namespace: "ns", Verb: "list", Resource: "secrets"},
			"allowed":            true,
			"denied":             false,
			"reason":             "allowed by test rule",
		},
	})

	if _, ok := got[0]["reason"]; ok {
		t.Fatalf("low-signal denied reason should be omitted: %#v", got[0])
	}
	if got[0]["reasonClass"] != "not_allowed" || got[0]["reasonOmitted"] != true {
		t.Fatalf("expected denied reason metadata, got %#v", got[0])
	}
	if got[1]["reason"] != "allowed by test rule" {
		t.Fatalf("allowed reason should be preserved: %#v", got[1])
	}
}

func assertExpandedCheck(t *testing.T, checks []expandedWildcardCheck, verb, group, resource, namespace string) {
	t.Helper()
	for _, check := range checks {
		if check.Attrs.Verb == verb && check.Attrs.Group == group && check.Attrs.Resource == resource && check.Attrs.Namespace == namespace {
			return
		}
	}
	t.Fatalf("missing expanded check verb=%s group=%s resource=%s namespace=%s", verb, group, resource, namespace)
}

func groupSummaryHasCounts(groups []map[string]any, group string, resourceCount, highValueCount int) bool {
	for _, item := range groups {
		if item["group"] != group {
			continue
		}
		return item["resourceCount"] == resourceCount && item["highValueCount"] == highValueCount
	}
	return false
}

func compactAPIResourcePresent(resources []map[string]any, group, name string) bool {
	for _, resource := range resources {
		if resource["group"] == group && resource["name"] == name {
			return true
		}
	}
	return false
}
