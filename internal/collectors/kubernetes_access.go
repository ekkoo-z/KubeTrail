package collectors

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/ekkoo-z/KubeTrail/internal/kube"
	"github.com/ekkoo-z/KubeTrail/internal/model"
)

const maxExpandedWildcardChecks = 500

type accessReviewCheck struct {
	ID          string
	Description string
	Attrs       kube.ResourceAttributes
}

type expandedWildcardCheck struct {
	ID              string
	Description     string
	Attrs           kube.ResourceAttributes
	SourceRuleIndex int
	SourceRule      kube.ResourceRule
	ExpansionReason string
}

type wildcardExpansionResult struct {
	Checks          []map[string]any
	Errs            []error
	Truncated       bool
	Limit           int
	TotalCandidates int
	CheckedCount    int
	ClusterAdmin    bool
}

type wildcardResourceCandidate struct {
	Group       string
	Version     string
	Resource    string
	Subresource string
	Namespaced  bool
}

var focusedAccessReviewIDs = map[string]bool{
	"secrets_get":                    true,
	"secrets_list":                   true,
	"pods_create":                    true,
	"pods_patch":                     true,
	"pods_exec":                      true,
	"pods_attach":                    true,
	"pods_portforward":               true,
	"pods_ephemeralcontainers_patch": true,
	"deployments_create":             true,
	"daemonsets_create":              true,
	"jobs_create":                    true,
	"cronjobs_create":                true,
	"rolebindings_create":            true,
	"roles_escalate":                 true,
	"roles_bind":                     true,
	"clusterrolebindings_create":     true,
	"clusterroles_escalate":          true,
	"clusterroles_bind":              true,
	"serviceaccounts_token_create":   true,
	"serviceaccounts_impersonate":    true,
	"users_impersonate":              true,
	"groups_impersonate":             true,
	"nodes_proxy_get":                true,
	"nodes_proxy_create":             true,
	"persistentvolumes_create":       true,
	"mutatingwebhook_create":         true,
	"mutatingwebhook_update":         true,
	"mutatingwebhook_patch":          true,
	"csr_approve":                    true,
	"kube_system_pods_create":        true,
	"kube_system_secrets_get":        true,
	"kube_system_secrets_list":       true,
}

func accessReviewChecks(namespace string) []accessReviewCheck {
	return accessReviewChecksForMode(namespace, model.RBACModeFull)
}

func accessReviewChecksForMode(namespace string, mode model.RBACMode) []accessReviewCheck {
	checks := allAccessReviewChecks(namespace)
	if normalizeRBACMode(mode) == model.RBACModeFull {
		return checks
	}
	filtered := make([]accessReviewCheck, 0, len(focusedAccessReviewIDs))
	for _, check := range checks {
		if focusedAccessReviewIDs[check.ID] {
			filtered = append(filtered, check)
		}
	}
	return filtered
}

func allAccessReviewChecks(namespace string) []accessReviewCheck {
	return []accessReviewCheck{
		{"secrets_get", "read a named secret", kube.ResourceAttributes{Namespace: namespace, Verb: "get", Group: "", Version: "v1", Resource: "secrets"}},
		{"secrets_list", "list secrets and receive secret data in list responses", kube.ResourceAttributes{Namespace: namespace, Verb: "list", Group: "", Version: "v1", Resource: "secrets"}},
		{"configmaps_list", "list configmaps", kube.ResourceAttributes{Namespace: namespace, Verb: "list", Group: "", Version: "v1", Resource: "configmaps"}},
		{"pods_create", "create pods in the namespace", kube.ResourceAttributes{Namespace: namespace, Verb: "create", Group: "", Version: "v1", Resource: "pods"}},
		{"pods_patch", "patch existing pods", kube.ResourceAttributes{Namespace: namespace, Verb: "patch", Group: "", Version: "v1", Resource: "pods"}},
		{"pods_exec", "exec into pods through the Kubernetes API", kube.ResourceAttributes{Namespace: namespace, Verb: "create", Group: "", Version: "v1", Resource: "pods", Subresource: "exec"}},
		{"pods_attach", "attach to pod processes", kube.ResourceAttributes{Namespace: namespace, Verb: "create", Group: "", Version: "v1", Resource: "pods", Subresource: "attach"}},
		{"pods_portforward", "open pod port-forward sessions", kube.ResourceAttributes{Namespace: namespace, Verb: "create", Group: "", Version: "v1", Resource: "pods", Subresource: "portforward"}},
		{"pods_log", "read pod logs", kube.ResourceAttributes{Namespace: namespace, Verb: "get", Group: "", Version: "v1", Resource: "pods", Subresource: "log"}},
		{"pods_ephemeralcontainers_patch", "inject ephemeral containers", kube.ResourceAttributes{Namespace: namespace, Verb: "patch", Group: "", Version: "v1", Resource: "pods", Subresource: "ephemeralcontainers"}},
		{"deployments_create", "create deployments", kube.ResourceAttributes{Namespace: namespace, Verb: "create", Group: "apps", Version: "v1", Resource: "deployments"}},
		{"daemonsets_create", "create daemonsets", kube.ResourceAttributes{Namespace: namespace, Verb: "create", Group: "apps", Version: "v1", Resource: "daemonsets"}},
		{"statefulsets_create", "create statefulsets", kube.ResourceAttributes{Namespace: namespace, Verb: "create", Group: "apps", Version: "v1", Resource: "statefulsets"}},
		{"jobs_create", "create jobs", kube.ResourceAttributes{Namespace: namespace, Verb: "create", Group: "batch", Version: "v1", Resource: "jobs"}},
		{"cronjobs_create", "create cronjobs", kube.ResourceAttributes{Namespace: namespace, Verb: "create", Group: "batch", Version: "v1", Resource: "cronjobs"}},
		{"rolebindings_create", "create rolebindings", kube.ResourceAttributes{Namespace: namespace, Verb: "create", Group: "rbac.authorization.k8s.io", Version: "v1", Resource: "rolebindings"}},
		{"roles_escalate", "create roles with permissions the caller does not hold", kube.ResourceAttributes{Namespace: namespace, Verb: "escalate", Group: "rbac.authorization.k8s.io", Version: "v1", Resource: "roles"}},
		{"roles_bind", "bind roles", kube.ResourceAttributes{Namespace: namespace, Verb: "bind", Group: "rbac.authorization.k8s.io", Version: "v1", Resource: "roles"}},
		{"clusterrolebindings_create", "create clusterrolebindings", kube.ResourceAttributes{Verb: "create", Group: "rbac.authorization.k8s.io", Version: "v1", Resource: "clusterrolebindings"}},
		{"clusterroles_escalate", "create clusterroles with permissions the caller does not hold", kube.ResourceAttributes{Verb: "escalate", Group: "rbac.authorization.k8s.io", Version: "v1", Resource: "clusterroles"}},
		{"clusterroles_bind", "bind clusterroles", kube.ResourceAttributes{Verb: "bind", Group: "rbac.authorization.k8s.io", Version: "v1", Resource: "clusterroles"}},
		{"serviceaccounts_token_create", "request service account tokens", kube.ResourceAttributes{Namespace: namespace, Verb: "create", Group: "", Version: "v1", Resource: "serviceaccounts", Subresource: "token"}},
		{"serviceaccounts_impersonate", "impersonate service accounts", kube.ResourceAttributes{Verb: "impersonate", Group: "", Version: "v1", Resource: "serviceaccounts"}},
		{"users_impersonate", "impersonate users", kube.ResourceAttributes{Verb: "impersonate", Group: "", Version: "v1", Resource: "users"}},
		{"groups_impersonate", "impersonate groups", kube.ResourceAttributes{Verb: "impersonate", Group: "", Version: "v1", Resource: "groups"}},
		{"nodes_get", "read node objects", kube.ResourceAttributes{Verb: "get", Group: "", Version: "v1", Resource: "nodes"}},
		{"nodes_list", "list node objects", kube.ResourceAttributes{Verb: "list", Group: "", Version: "v1", Resource: "nodes"}},
		{"nodes_proxy_get", "access kubelet through nodes/proxy with GET", kube.ResourceAttributes{Verb: "get", Group: "", Version: "v1", Resource: "nodes", Subresource: "proxy"}},
		{"nodes_proxy_create", "access kubelet through nodes/proxy with CREATE", kube.ResourceAttributes{Verb: "create", Group: "", Version: "v1", Resource: "nodes", Subresource: "proxy"}},
		{"persistentvolumes_create", "create persistent volumes including possible hostPath PVs", kube.ResourceAttributes{Verb: "create", Group: "", Version: "v1", Resource: "persistentvolumes"}},
		{"persistentvolumeclaims_create", "create persistent volume claims", kube.ResourceAttributes{Namespace: namespace, Verb: "create", Group: "", Version: "v1", Resource: "persistentvolumeclaims"}},
		{"events_delete", "delete events", kube.ResourceAttributes{Namespace: namespace, Verb: "delete", Group: "", Version: "v1", Resource: "events"}},
		{"crd_create", "register cluster-wide CustomResourceDefinitions", kube.ResourceAttributes{Verb: "create", Group: "apiextensions.k8s.io", Version: "v1", Resource: "customresourcedefinitions"}},
		{"crd_patch", "patch existing CustomResourceDefinitions", kube.ResourceAttributes{Verb: "patch", Group: "apiextensions.k8s.io", Version: "v1", Resource: "customresourcedefinitions"}},
		{"mutatingwebhook_create", "register a MutatingWebhookConfiguration", kube.ResourceAttributes{Verb: "create", Group: "admissionregistration.k8s.io", Version: "v1", Resource: "mutatingwebhookconfigurations"}},
		{"mutatingwebhook_update", "update existing MutatingWebhookConfiguration (clientConfig hijack)", kube.ResourceAttributes{Verb: "update", Group: "admissionregistration.k8s.io", Version: "v1", Resource: "mutatingwebhookconfigurations"}},
		{"mutatingwebhook_patch", "patch existing MutatingWebhookConfiguration", kube.ResourceAttributes{Verb: "patch", Group: "admissionregistration.k8s.io", Version: "v1", Resource: "mutatingwebhookconfigurations"}},
		{"validatingwebhook_create", "register a ValidatingWebhookConfiguration", kube.ResourceAttributes{Verb: "create", Group: "admissionregistration.k8s.io", Version: "v1", Resource: "validatingwebhookconfigurations"}},
		{"validatingwebhook_update", "update existing ValidatingWebhookConfiguration", kube.ResourceAttributes{Verb: "update", Group: "admissionregistration.k8s.io", Version: "v1", Resource: "validatingwebhookconfigurations"}},
		{"storageclass_create", "create StorageClass (lateral path via dynamic provisioning)", kube.ResourceAttributes{Verb: "create", Group: "storage.k8s.io", Version: "v1", Resource: "storageclasses"}},
		{"nodes_create", "register Node objects (kubelet bootstrap-style abuse)", kube.ResourceAttributes{Verb: "create", Group: "", Version: "v1", Resource: "nodes"}},
		{"nodes_patch", "patch Node objects (taints/labels/spec)", kube.ResourceAttributes{Verb: "patch", Group: "", Version: "v1", Resource: "nodes"}},
		{"csr_create", "create CertificateSigningRequest", kube.ResourceAttributes{Verb: "create", Group: "certificates.k8s.io", Version: "v1", Resource: "certificatesigningrequests"}},
		{"csr_approve", "approve CertificateSigningRequest", kube.ResourceAttributes{Verb: "update", Group: "certificates.k8s.io", Version: "v1", Resource: "certificatesigningrequests", Subresource: "approval"}},
		{"kube_system_pods_create", "create pods in kube-system", kube.ResourceAttributes{Namespace: "kube-system", Verb: "create", Group: "", Version: "v1", Resource: "pods"}},
		{"kube_system_secrets_get", "read named secrets in kube-system", kube.ResourceAttributes{Namespace: "kube-system", Verb: "get", Group: "", Version: "v1", Resource: "secrets"}},
		{"kube_system_secrets_list", "list secrets in kube-system", kube.ResourceAttributes{Namespace: "kube-system", Verb: "list", Group: "", Version: "v1", Resource: "secrets"}},
	}
}

func accessReviewMatrix(ctx context.Context, client *kube.Client, namespace string, mode model.RBACMode) ([]map[string]any, []error) {
	checks := accessReviewChecksForMode(namespace, mode)
	results := make([]map[string]any, 0, len(checks))
	var errs []error
	for _, check := range checks {
		result, err := client.SelfSubjectAccessReview(ctx, check.Attrs)
		item := map[string]any{
			"id":                 check.ID,
			"description":        check.Description,
			"resourceAttributes": check.Attrs,
		}
		if err != nil {
			item["error"] = err.Error()
			errs = append(errs, err)
		} else {
			item["allowed"] = result.Allowed
			item["denied"] = result.Denied
			item["reason"] = result.Reason
			item["evaluationError"] = result.EvaluationError
		}
		results = append(results, item)
	}
	return results, errs
}

func normalizeRBACMode(mode model.RBACMode) model.RBACMode {
	if mode == model.RBACModeFull {
		return model.RBACModeFull
	}
	return model.RBACModeFocused
}

func expandedWildcardAccessMatrixForMode(ctx context.Context, client *kube.Client, namespace string, rules []kube.ResourceRule, resources []kube.APIResource, mode model.RBACMode) wildcardExpansionResult {
	if normalizeRBACMode(mode) == model.RBACModeFull {
		return expandedWildcardAccessMatrix(ctx, client, namespace, rules, resources)
	}
	if isAdmin, ruleIdx := isClusterAdminEquivalent(rules); isAdmin {
		return wildcardExpansionResult{
			Checks: []map[string]any{{
				"id":              "cluster_admin_equivalent",
				"description":     "rule grants verbs=* resources=* apiGroups=* with no resourceNames restriction",
				"sourceRuleIndex": ruleIdx,
				"sourceRule":      rules[ruleIdx],
				"clusterAdmin":    true,
			}},
			ClusterAdmin: true,
			Limit:        maxExpandedWildcardChecks,
		}
	}
	return wildcardExpansionResult{
		Checks:       []map[string]any{},
		Limit:        maxExpandedWildcardChecks,
		CheckedCount: 0,
	}
}

func expandedWildcardAccessMatrix(ctx context.Context, client *kube.Client, namespace string, rules []kube.ResourceRule, resources []kube.APIResource) wildcardExpansionResult {
	if isAdmin, ruleIdx := isClusterAdminEquivalent(rules); isAdmin {
		return wildcardExpansionResult{
			Checks: []map[string]any{{
				"id":              "cluster_admin_equivalent",
				"description":     "rule grants verbs=* resources=* apiGroups=* with no resourceNames restriction",
				"sourceRuleIndex": ruleIdx,
				"sourceRule":      rules[ruleIdx],
				"clusterAdmin":    true,
			}},
			ClusterAdmin: true,
			Limit:        maxExpandedWildcardChecks,
		}
	}

	checks, totalCandidates := expandedWildcardChecks(namespace, rules, resources)
	results := make([]map[string]any, 0, len(checks))
	var errs []error
	for _, check := range checks {
		result, err := client.SelfSubjectAccessReview(ctx, check.Attrs)
		item := map[string]any{
			"id":                 check.ID,
			"description":        check.Description,
			"resourceAttributes": check.Attrs,
			"sourceRuleIndex":    check.SourceRuleIndex,
			"sourceRule":         check.SourceRule,
			"expansionReason":    check.ExpansionReason,
		}
		if err != nil {
			item["error"] = err.Error()
			errs = append(errs, err)
		} else {
			item["allowed"] = result.Allowed
			item["denied"] = result.Denied
			item["reason"] = result.Reason
			item["evaluationError"] = result.EvaluationError
		}
		results = append(results, item)
	}

	return wildcardExpansionResult{
		Checks:          results,
		Errs:            errs,
		Truncated:       totalCandidates > maxExpandedWildcardChecks,
		Limit:           maxExpandedWildcardChecks,
		TotalCandidates: totalCandidates,
		CheckedCount:    len(checks),
	}
}

func expandedWildcardChecks(namespace string, rules []kube.ResourceRule, resources []kube.APIResource) ([]expandedWildcardCheck, int) {
	var checks []expandedWildcardCheck
	seen := map[string]bool{}
	total := 0
	for index, rule := range rules {
		if !ruleHasWildcard(rule) {
			continue
		}
		candidates := wildcardCandidatesForRule(rule, resources)
		sortCandidatesByPriority(candidates)
		reason := wildcardExpansionReason(rule)
		for _, candidate := range candidates {
			for _, verb := range highRiskWildcardVerbs() {
				attrs := kube.ResourceAttributes{
					Verb:        verb,
					Group:       candidate.Group,
					Version:     candidate.Version,
					Resource:    candidate.Resource,
					Subresource: candidate.Subresource,
				}
				if candidate.Namespaced {
					attrs.Namespace = namespace
				}
				names := rule.ResourceNames
				if len(names) == 0 {
					names = []string{""}
				}
				for _, name := range names {
					attrs.Name = name
					key := accessReviewKey(attrs)
					if seen[key] {
						continue
					}
					seen[key] = true
					total++
					if len(checks) >= maxExpandedWildcardChecks {
						continue
					}
					checks = append(checks, expandedWildcardCheck{
						ID:              "wildcard_" + slugKey(key),
						Description:     fmt.Sprintf("expanded wildcard SSRR rule: %s %s", verb, resourceLabel(attrs)),
						Attrs:           attrs,
						SourceRuleIndex: index,
						SourceRule:      rule,
						ExpansionReason: reason,
					})
				}
			}
		}
	}
	return checks, total
}

func wildcardCandidatesForRule(rule kube.ResourceRule, resources []kube.APIResource) []wildcardResourceCandidate {
	var candidates []wildcardResourceCandidate
	seen := map[string]bool{}
	add := func(candidate wildcardResourceCandidate) {
		if candidate.Resource == "" {
			return
		}
		key := candidate.Group + "/" + candidate.Version + "/" + candidate.Resource + "/" + candidate.Subresource
		if seen[key] {
			return
		}
		seen[key] = true
		candidates = append(candidates, candidate)
	}

	if hasString(rule.Resources, "*") {
		for _, resource := range resources {
			if !apiGroupMatches(rule.APIGroups, resource.Group) || !isSensitiveWildcardResource(resource.Group, resource.Name) {
				continue
			}
			add(wildcardResourceCandidate{
				Group:      resource.Group,
				Version:    resource.Version,
				Resource:   resource.Name,
				Namespaced: resource.Namespaced,
			})
		}
		for _, candidate := range staticWildcardCandidates() {
			if apiGroupMatches(rule.APIGroups, candidate.Group) {
				add(candidate)
			}
		}
		return candidates
	}

	for _, raw := range rule.Resources {
		if raw == "" || raw == "*" {
			continue
		}
		resource, subresource := splitSubresource(raw)
		if hasString(rule.APIGroups, "*") {
			for _, resourceInfo := range resources {
				if resourceInfo.Name != resource {
					continue
				}
				add(wildcardResourceCandidate{
					Group:       resourceInfo.Group,
					Version:     resourceInfo.Version,
					Resource:    resource,
					Subresource: subresource,
					Namespaced:  resourceInfo.Namespaced,
				})
			}
			for _, candidate := range staticWildcardCandidates() {
				if candidate.Resource == resource && candidate.Subresource == subresource {
					add(candidate)
				}
			}
			continue
		}
		for _, group := range normalizedAPIGroups(rule.APIGroups) {
			add(inferWildcardCandidate(group, resource, subresource, resources))
		}
	}
	return candidates
}

func inferWildcardCandidate(group, resource, subresource string, resources []kube.APIResource) wildcardResourceCandidate {
	for _, resourceInfo := range resources {
		if resourceInfo.Group == group && resourceInfo.Name == resource {
			return wildcardResourceCandidate{
				Group:       group,
				Version:     resourceInfo.Version,
				Resource:    resource,
				Subresource: subresource,
				Namespaced:  resourceInfo.Namespaced,
			}
		}
	}
	for _, candidate := range staticWildcardCandidates() {
		if candidate.Group == group && candidate.Resource == resource && candidate.Subresource == subresource {
			return candidate
		}
	}
	return wildcardResourceCandidate{
		Group:       group,
		Resource:    resource,
		Subresource: subresource,
		Namespaced:  !isClusterScopedResource(group, resource),
	}
}

func highRiskWildcardVerbs() []string {
	return []string{"create", "update", "patch", "delete", "escalate", "bind", "impersonate"}
}

func candidatePriority(c wildcardResourceCandidate) int {
	key := c.Group + "/" + c.Resource + "/" + c.Subresource
	switch key {
	case "/secrets/", "/pods/exec", "/nodes/proxy", "/serviceaccounts/token":
		return 0
	case "rbac.authorization.k8s.io/roles/",
		"rbac.authorization.k8s.io/rolebindings/",
		"rbac.authorization.k8s.io/clusterroles/",
		"rbac.authorization.k8s.io/clusterrolebindings/":
		return 1
	case "admissionregistration.k8s.io/mutatingwebhookconfigurations/",
		"admissionregistration.k8s.io/validatingwebhookconfigurations/",
		"certificates.k8s.io/certificatesigningrequests/",
		"certificates.k8s.io/certificatesigningrequests/approval":
		return 2
	case "/pods/", "/pods/ephemeralcontainers", "/serviceaccounts/", "/nodes/",
		"apps/deployments/", "apps/daemonsets/", "apps/statefulsets/",
		"batch/jobs/", "batch/cronjobs/":
		return 3
	case "apiextensions.k8s.io/customresourcedefinitions/",
		"/namespaces/", "/persistentvolumes/":
		return 4
	}
	return 5
}

func sortCandidatesByPriority(candidates []wildcardResourceCandidate) {
	sort.SliceStable(candidates, func(i, j int) bool {
		return candidatePriority(candidates[i]) < candidatePriority(candidates[j])
	})
}

func staticWildcardCandidates() []wildcardResourceCandidate {
	return []wildcardResourceCandidate{
		{Group: "", Version: "v1", Resource: "secrets", Namespaced: true},
		{Group: "", Version: "v1", Resource: "configmaps", Namespaced: true},
		{Group: "", Version: "v1", Resource: "pods", Namespaced: true},
		{Group: "", Version: "v1", Resource: "pods", Subresource: "exec", Namespaced: true},
		{Group: "", Version: "v1", Resource: "pods", Subresource: "ephemeralcontainers", Namespaced: true},
		{Group: "", Version: "v1", Resource: "serviceaccounts", Namespaced: true},
		{Group: "", Version: "v1", Resource: "serviceaccounts", Subresource: "token", Namespaced: true},
		{Group: "", Version: "v1", Resource: "namespaces", Namespaced: false},
		{Group: "", Version: "v1", Resource: "nodes", Namespaced: false},
		{Group: "", Version: "v1", Resource: "nodes", Subresource: "proxy", Namespaced: false},
		{Group: "", Version: "v1", Resource: "persistentvolumes", Namespaced: false},
		{Group: "", Version: "v1", Resource: "persistentvolumeclaims", Namespaced: true},
		{Group: "apps", Version: "v1", Resource: "deployments", Namespaced: true},
		{Group: "apps", Version: "v1", Resource: "daemonsets", Namespaced: true},
		{Group: "apps", Version: "v1", Resource: "statefulsets", Namespaced: true},
		{Group: "batch", Version: "v1", Resource: "jobs", Namespaced: true},
		{Group: "batch", Version: "v1", Resource: "cronjobs", Namespaced: true},
		{Group: "rbac.authorization.k8s.io", Version: "v1", Resource: "roles", Namespaced: true},
		{Group: "rbac.authorization.k8s.io", Version: "v1", Resource: "rolebindings", Namespaced: true},
		{Group: "rbac.authorization.k8s.io", Version: "v1", Resource: "clusterroles", Namespaced: false},
		{Group: "rbac.authorization.k8s.io", Version: "v1", Resource: "clusterrolebindings", Namespaced: false},
		{Group: "apiextensions.k8s.io", Version: "v1", Resource: "customresourcedefinitions", Namespaced: false},
		{Group: "admissionregistration.k8s.io", Version: "v1", Resource: "mutatingwebhookconfigurations", Namespaced: false},
		{Group: "admissionregistration.k8s.io", Version: "v1", Resource: "validatingwebhookconfigurations", Namespaced: false},
		{Group: "storage.k8s.io", Version: "v1", Resource: "storageclasses", Namespaced: false},
		{Group: "certificates.k8s.io", Version: "v1", Resource: "certificatesigningrequests", Namespaced: false},
		{Group: "certificates.k8s.io", Version: "v1", Resource: "certificatesigningrequests", Subresource: "approval", Namespaced: false},
	}
}

func isClusterAdminEquivalent(rules []kube.ResourceRule) (bool, int) {
	for i, rule := range rules {
		if !hasString(rule.Verbs, "*") {
			continue
		}
		if !hasString(rule.Resources, "*") {
			continue
		}
		if !hasString(rule.APIGroups, "*") {
			continue
		}
		if len(rule.ResourceNames) > 0 {
			continue
		}
		return true, i
	}
	return false, -1
}

func ruleHasWildcard(rule kube.ResourceRule) bool {
	return hasString(rule.Verbs, "*") || hasString(rule.Resources, "*") || hasString(rule.APIGroups, "*")
}

func wildcardExpansionReason(rule kube.ResourceRule) string {
	var reasons []string
	if hasString(rule.Verbs, "*") {
		reasons = append(reasons, "verbs=*")
	}
	if hasString(rule.Resources, "*") {
		reasons = append(reasons, "resources=*")
	}
	if hasString(rule.APIGroups, "*") {
		reasons = append(reasons, "apiGroups=*")
	}
	return strings.Join(reasons, ",")
}

func isSensitiveWildcardResource(group, resource string) bool {
	name := strings.ToLower(resource)
	if group != "" && !isStandardKubernetesGroup(group) {
		return true
	}
	for _, marker := range []string{
		"secret", "configmap", "pod", "serviceaccount", "namespace", "node", "role", "binding",
		"webhook", "customresourcedefinition", "storageclass", "persistentvolume", "job",
		"workflow", "deployment", "daemonset", "statefulset", "ingress", "certificate",
		"token", "datastore", "model", "training", "notebook", "pipeline", "serving",
	} {
		if strings.Contains(name, marker) {
			return true
		}
	}
	return false
}

func isStandardKubernetesGroup(group string) bool {
	switch group {
	case "", "apps", "batch", "rbac.authorization.k8s.io", "apiextensions.k8s.io", "admissionregistration.k8s.io", "storage.k8s.io", "certificates.k8s.io", "authorization.k8s.io", "coordination.k8s.io", "networking.k8s.io", "extensions":
		return true
	default:
		return false
	}
}

func isClusterScopedResource(group, resource string) bool {
	switch group + "/" + resource {
	case "/namespaces", "/nodes", "/persistentvolumes",
		"rbac.authorization.k8s.io/clusterroles", "rbac.authorization.k8s.io/clusterrolebindings",
		"apiextensions.k8s.io/customresourcedefinitions",
		"admissionregistration.k8s.io/mutatingwebhookconfigurations",
		"admissionregistration.k8s.io/validatingwebhookconfigurations",
		"storage.k8s.io/storageclasses",
		"certificates.k8s.io/certificatesigningrequests":
		return true
	default:
		return false
	}
}

func normalizedAPIGroups(groups []string) []string {
	if len(groups) == 0 {
		return []string{""}
	}
	return groups
}

func apiGroupMatches(ruleGroups []string, group string) bool {
	if len(ruleGroups) == 0 {
		return group == ""
	}
	for _, ruleGroup := range ruleGroups {
		if ruleGroup == "*" || ruleGroup == group {
			return true
		}
	}
	return false
}

func splitSubresource(value string) (string, string) {
	resource, subresource, ok := strings.Cut(value, "/")
	if !ok {
		return value, ""
	}
	return resource, subresource
}

func accessReviewKey(attrs kube.ResourceAttributes) string {
	return strings.Join([]string{attrs.Namespace, attrs.Verb, attrs.Group, attrs.Version, attrs.Resource, attrs.Subresource, attrs.Name}, "|")
}

func resourceLabel(attrs kube.ResourceAttributes) string {
	group := attrs.Group
	if group == "" {
		group = "core"
	}
	resource := attrs.Resource
	if attrs.Subresource != "" {
		resource += "/" + attrs.Subresource
	}
	if attrs.Namespace != "" {
		return group + "/" + resource + " namespace=" + attrs.Namespace
	}
	return group + "/" + resource
}

func slugKey(value string) string {
	value = strings.ReplaceAll(value, "|", "_")
	var b strings.Builder
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z':
			b.WriteRune(r)
		case r >= 'A' && r <= 'Z':
			b.WriteRune(r)
		case r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '_' || r == '-' || r == '.':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	return strings.Trim(b.String(), "_")
}

func hasString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
