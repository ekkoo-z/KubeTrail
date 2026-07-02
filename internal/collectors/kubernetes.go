package collectors

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/ekkoo-z/KubeTrail/internal/kube"
	"github.com/ekkoo-z/KubeTrail/internal/model"
)

func collectKubernetesContext(ctx context.Context, cctx *Context) ([]model.Fact, []model.ErrorEntry) {
	client, err := cctx.KubeClient()
	if err != nil {
		return []model.Fact{fact("k8s_context.unavailable", "kubernetes", "client", false, map[string]any{
			"inKubernetes": cctx.InKubernetes(),
			"namespace":    cctx.Namespace(),
			"apiServer":    cctx.APIServer(),
			"error":        err.Error(),
		})}, []model.ErrorEntry{errEntry("kubernetes client", err)}
	}

	var facts []model.Fact
	var errs []model.ErrorEntry

	version, err := client.ServerVersion(ctx)
	if err != nil {
		errs = append(errs, errEntry("/version", err))
	} else {
		facts = append(facts, fact("k8s_context.version", "kubernetes", "/version", false, version))
	}

	resources, discoveryErrs := client.Discover(ctx)
	for _, err := range discoveryErrs {
		errs = append(errs, errEntry("discovery", err))
	}
	facts = append(facts, fact("k8s_context.discovery", "kubernetes", "discovery", false, summarizeDiscoveryResources(resources)))

	namespace := client.Namespace
	if namespace == "" {
		namespace = cctx.Namespace()
	}
	podName, _ := os.Hostname()
	if cctx.InKubernetes() && namespace != "" && podName != "" {
		pod, err := client.GetPod(ctx, namespace, podName)
		if err != nil {
			errs = append(errs, errEntry(fmt.Sprintf("pods/%s", podName), err))
		} else {
			facts = append(facts, fact("k8s_context.current_pod", "kubernetes", "pod", false, pod))
		}
	}

	return facts, errs
}

func collectKubernetesPermissions(ctx context.Context, cctx *Context) ([]model.Fact, []model.ErrorEntry) {
	client, err := cctx.KubeClient()
	if err != nil {
		return nil, []model.ErrorEntry{errEntry("kubernetes client", err)}
	}
	namespace := client.Namespace
	if namespace == "" {
		namespace = cctx.Namespace()
	}
	if namespace == "" {
		return nil, []model.ErrorEntry{{Source: "namespace", Message: "namespace not available"}}
	}

	status, err := client.SelfSubjectRulesReview(ctx, namespace)
	if err != nil {
		return nil, []model.ErrorEntry{errEntry("selfsubjectrulesreviews", err)}
	}

	rbacMode := normalizeRBACMode(cctx.Options.RBACMode)
	var resources []kube.APIResource
	var discoveryErrs []error
	if rbacMode == model.RBACModeFull {
		resources, discoveryErrs = client.Discover(ctx)
	}
	matrix, matrixErrs := accessReviewMatrix(ctx, client, namespace, rbacMode)
	expandedResult := expandedWildcardAccessMatrixForMode(ctx, client, namespace, status.ResourceRules, resources, rbacMode)
	errs := make([]model.ErrorEntry, 0, len(discoveryErrs)+len(matrixErrs)+len(expandedResult.Errs))
	for _, err := range discoveryErrs {
		errs = append(errs, errEntry("discovery expanded_wildcards", err))
	}
	for _, err := range matrixErrs {
		errs = append(errs, errEntry("selfsubjectaccessreviews", err))
	}
	for _, err := range expandedResult.Errs {
		errs = append(errs, errEntry("selfsubjectaccessreviews expanded_wildcards", err))
	}
	return []model.Fact{
		fact("k8s_permissions.rbac_mode", "kubernetes", "configuration", false, map[string]any{
			"mode":                  rbacMode,
			"highValueCheckCount":   len(matrix),
			"expandedWildcardCount": expandedResult.CheckedCount,
		}),
		fact("k8s_permissions.self_subject_rules", "kubernetes", "authorization.k8s.io/v1", false, compactRulesReview(status)),
		fact("k8s_permissions.high_value_access", "kubernetes", "authorization.k8s.io/v1", false, compactAccessReviewMatrix(matrix)),
		fact("k8s_permissions.expanded_wildcards", "kubernetes", "authorization.k8s.io/v1", false, map[string]any{
			"rbacMode":        rbacMode,
			"checks":          compactAccessReviewMatrix(expandedResult.Checks),
			"truncated":       expandedResult.Truncated,
			"limit":           expandedResult.Limit,
			"totalCandidates": expandedResult.TotalCandidates,
			"checkedCount":    expandedResult.CheckedCount,
			"clusterAdmin":    expandedResult.ClusterAdmin,
		}),
	}, errs
}

func collectKubernetesObjects(ctx context.Context, cctx *Context) ([]model.Fact, []model.ErrorEntry) {
	client, err := cctx.KubeClient()
	if err != nil {
		return nil, []model.ErrorEntry{errEntry("kubernetes client", err)}
	}

	resources, discoveryErrs := client.Discover(ctx)
	var errs []model.ErrorEntry
	for _, err := range discoveryErrs {
		errs = append(errs, errEntry("discovery", err))
	}

	namespace := client.Namespace
	if namespace == "" {
		namespace = cctx.Namespace()
	}
	namespaces := []string{namespace}

	rules, ruleErr := client.SelfSubjectRulesReview(ctx, namespace)
	if ruleErr != nil {
		errs = append(errs, errEntry("selfsubjectrulesreviews", ruleErr))
		if cctx.Options.APIScope == model.APIScopePermitted {
			return []model.Fact{fact("k8s_objects.skipped", "kubernetes", "authorization", false, map[string]any{
				"reason": "permitted API scope requires SelfSubjectRulesReview",
			})}, errs
		}
	}

	var facts []model.Fact
	if cctx.Options.APIScope == model.APIScopePermitted && canListResourceName(rules.ResourceRules, "", "namespaces") {
		nsResource := kube.APIResource{GroupVersion: "v1", Version: "v1", Name: "namespaces", Kind: "Namespace", Namespaced: false}
		list, err := client.ListResource(ctx, nsResource, "", cctx.Options.MaxItems)
		if err != nil {
			errs = append(errs, errEntry("namespaces", err))
		} else {
			facts = append(facts, fact("k8s_objects.namespaces", "kubernetes", "namespaces", false, list))
			namespaces = namespaceNames(list, namespace)
		}
	}

	sort.Slice(resources, func(i, j int) bool {
		if resources[i].GroupVersion == resources[j].GroupVersion {
			return resources[i].Name < resources[j].Name
		}
		return resources[i].GroupVersion < resources[j].GroupVersion
	})

	var listed []map[string]any
	for _, resource := range resources {
		if !kube.HasVerb(resource.Verbs, "list") {
			continue
		}
		if cctx.Options.APIScope == model.APIScopePermitted && len(rules.ResourceRules) > 0 && !kube.CanList(rules.ResourceRules, resource) {
			continue
		}
		if resource.Namespaced {
			for _, ns := range namespaces {
				if ns == "" {
					continue
				}
				list, err := client.ListResource(ctx, resource, ns, cctx.Options.MaxItems)
				if err != nil {
					errs = append(errs, errEntry(resource.GroupVersion+"/"+resource.Name+" namespace="+ns, err))
					continue
				}
				listed = append(listed, map[string]any{
					"groupVersion": resource.GroupVersion,
					"resource":     resource.Name,
					"kind":         resource.Kind,
					"namespaced":   true,
					"namespace":    ns,
					"list":         list,
				})
			}
			continue
		}
		list, err := client.ListResource(ctx, resource, "", cctx.Options.MaxItems)
		if err != nil {
			errs = append(errs, errEntry(resource.GroupVersion+"/"+resource.Name, err))
			continue
		}
		listed = append(listed, map[string]any{
			"groupVersion": resource.GroupVersion,
			"resource":     resource.Name,
			"kind":         resource.Kind,
			"namespaced":   false,
			"list":         list,
		})
	}

	facts = append(facts, fact("k8s_objects.permitted_lists", "kubernetes", "kubernetes api", true, map[string]any{
		"apiScope":   cctx.Options.APIScope,
		"namespaces": namespaces,
		"items":      listed,
		"maxItems":   cctx.Options.MaxItems,
	}))
	return facts, errs
}

func canListResourceName(rules []kube.ResourceRule, group, resource string) bool {
	return kube.CanList(rules, kube.APIResource{Group: group, Name: resource})
}

func namespaceNames(list map[string]any, fallback string) []string {
	seen := map[string]bool{}
	var out []string
	if fallback != "" {
		seen[fallback] = true
		out = append(out, fallback)
	}
	items, _ := list["items"].([]any)
	for _, raw := range items {
		item, _ := raw.(map[string]any)
		meta, _ := item["metadata"].(map[string]any)
		name, _ := meta["name"].(string)
		if name != "" && !seen[name] {
			seen[name] = true
			out = append(out, name)
		}
	}
	return out
}

func summarizeDiscoveryResources(resources []kube.APIResource) map[string]any {
	sorted := append([]kube.APIResource(nil), resources...)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].GroupVersion == sorted[j].GroupVersion {
			return sorted[i].Name < sorted[j].Name
		}
		return sorted[i].GroupVersion < sorted[j].GroupVersion
	})

	type groupSummary struct {
		group              string
		versions           map[string]bool
		resourceCount      int
		namespacedCount    int
		clusterScopedCount int
		highValueCount     int
	}
	groups := map[string]*groupSummary{}
	var highValue []map[string]any
	for _, resource := range sorted {
		group := resource.Group
		bucket := groups[group]
		if bucket == nil {
			bucket = &groupSummary{group: group, versions: map[string]bool{}}
			groups[group] = bucket
		}
		bucket.versions[resource.Version] = true
		bucket.resourceCount++
		if resource.Namespaced {
			bucket.namespacedCount++
		} else {
			bucket.clusterScopedCount++
		}
		if highSignalDiscoveryResource(resource) {
			bucket.highValueCount++
			highValue = append(highValue, compactDiscoveryResource(resource))
		}
	}

	groupValues := make([]map[string]any, 0, len(groups))
	for _, bucket := range groups {
		versions := make([]string, 0, len(bucket.versions))
		for version := range bucket.versions {
			versions = append(versions, version)
		}
		sort.Strings(versions)
		groupValues = append(groupValues, map[string]any{
			"group":              bucket.group,
			"versions":           versions,
			"resourceCount":      bucket.resourceCount,
			"namespacedCount":    bucket.namespacedCount,
			"clusterScopedCount": bucket.clusterScopedCount,
			"highValueCount":     bucket.highValueCount,
		})
	}
	sort.Slice(groupValues, func(i, j int) bool {
		return groupValues[i]["group"].(string) < groupValues[j]["group"].(string)
	})

	return map[string]any{
		"resourceCount":                  len(sorted),
		"groupCount":                     len(groupValues),
		"groups":                         groupValues,
		"highValueResourceCount":         len(highValue),
		"highValueResources":             highValue,
		"omittedLowSignalResourceDetail": len(sorted) - len(highValue),
		"resourceIndexSha256":            discoveryResourceIndexHash(sorted),
		"resourceIndexEncoding":          "groupVersion\\tgroup\\tversion\\tname\\tkind\\tnamespaced\\tverbs",
		"note":                           "groups contains counts only; highValueResources keeps structured details for likely analysis pivots",
	}
}

func compactDiscoveryResource(resource kube.APIResource) map[string]any {
	item := map[string]any{
		"groupVersion": resource.GroupVersion,
		"group":        resource.Group,
		"version":      resource.Version,
		"name":         resource.Name,
		"kind":         resource.Kind,
		"namespaced":   resource.Namespaced,
	}
	if verbs := discoveryVerbsOfInterest(resource.Verbs); len(verbs) > 0 {
		item["verbs"] = verbs
	}
	return item
}

func discoveryVerbsOfInterest(verbs []string) []string {
	want := map[string]bool{
		"get": true, "list": true, "create": true, "update": true, "patch": true,
		"delete": true, "deletecollection": true, "escalate": true, "bind": true, "impersonate": true,
	}
	var out []string
	for _, verb := range verbs {
		if want[verb] {
			out = append(out, verb)
		}
	}
	return out
}

func discoveryResourceIndexHash(resources []kube.APIResource) string {
	var b strings.Builder
	for _, resource := range resources {
		verbs := append([]string(nil), resource.Verbs...)
		sort.Strings(verbs)
		b.WriteString(resource.GroupVersion)
		b.WriteByte('\t')
		b.WriteString(resource.Group)
		b.WriteByte('\t')
		b.WriteString(resource.Version)
		b.WriteByte('\t')
		b.WriteString(resource.Name)
		b.WriteByte('\t')
		b.WriteString(resource.Kind)
		b.WriteByte('\t')
		if resource.Namespaced {
			b.WriteString("namespaced")
		} else {
			b.WriteString("cluster")
		}
		b.WriteByte('\t')
		b.WriteString(strings.Join(verbs, ","))
		b.WriteByte('\n')
	}
	return sha256HexString(b.String())
}

func highSignalDiscoveryResource(resource kube.APIResource) bool {
	key := resource.Group + "/" + resource.Name
	switch key {
	case "/secrets", "/pods", "/serviceaccounts", "/namespaces", "/nodes", "/persistentvolumes", "/persistentvolumeclaims",
		"apps/deployments", "apps/daemonsets", "apps/statefulsets",
		"batch/jobs", "batch/cronjobs",
		"rbac.authorization.k8s.io/roles", "rbac.authorization.k8s.io/rolebindings", "rbac.authorization.k8s.io/clusterroles", "rbac.authorization.k8s.io/clusterrolebindings",
		"apiextensions.k8s.io/customresourcedefinitions",
		"admissionregistration.k8s.io/mutatingwebhookconfigurations", "admissionregistration.k8s.io/validatingwebhookconfigurations",
		"admissionregistration.k8s.io/validatingadmissionpolicies", "admissionregistration.k8s.io/validatingadmissionpolicybindings",
		"storage.k8s.io/storageclasses",
		"certificates.k8s.io/certificatesigningrequests",
		"networking.k8s.io/networkpolicies", "networking.k8s.io/ingresses",
		"gateway.networking.k8s.io/gateways", "gateway.networking.k8s.io/httproutes":
		return true
	}
	name := strings.ToLower(resource.Name + " " + resource.Kind + " " + resource.Group)
	for _, marker := range []string{
		"secret", "token", "credential", "pod", "exec", "workload", "role", "binding", "webhook", "admission",
		"policy", "gateway", "route", "networkpolicy", "certificate", "workflow", "pipeline", "training",
		"notebook", "serving", "model", "job", "cronjob", "operator", "ray", "spark", "kubeflow", "kubevirt",
	} {
		if strings.Contains(name, marker) {
			return true
		}
	}
	return false
}

func compactRulesReview(status kube.RulesReviewStatus) kube.RulesReviewStatus {
	status.Raw = nil
	return status
}

func compactAccessReviewMatrix(items []map[string]any) []map[string]any {
	out := make([]map[string]any, 0, len(items))
	for _, item := range items {
		compact := map[string]any{}
		for _, key := range []string{"id", "description", "resourceAttributes", "sourceRuleIndex", "sourceRule", "expansionReason", "clusterAdmin", "error"} {
			if value, ok := item[key]; ok {
				compact[key] = value
			}
		}
		allowed, hasAllowed := item["allowed"].(bool)
		if hasAllowed {
			compact["allowed"] = allowed
		}
		denied, hasDenied := item["denied"].(bool)
		if denied {
			compact["denied"] = true
		}
		reason, _ := item["reason"].(string)
		evaluationError, _ := item["evaluationError"].(string)
		if allowed || denied || evaluationError != "" || !lowSignalAccessDeniedReason(reason) {
			if reason != "" {
				compact["reason"] = reason
			}
			if hasDenied && !denied {
				compact["denied"] = false
			}
			if evaluationError != "" {
				compact["evaluationError"] = evaluationError
			}
		} else if reason != "" {
			compact["reasonClass"] = accessReasonClass(reason)
			compact["reasonOmitted"] = true
		}
		out = append(out, compact)
	}
	return out
}

func lowSignalAccessDeniedReason(reason string) bool {
	class := accessReasonClass(reason)
	return class == "not_allowed" || class == "forbidden"
}

func accessReasonClass(reason string) string {
	lower := strings.ToLower(reason)
	switch {
	case strings.Contains(lower, "not allowed"):
		return "not_allowed"
	case strings.Contains(lower, "forbidden"):
		return "forbidden"
	case strings.Contains(lower, "no opinion"):
		return "no_opinion"
	case strings.TrimSpace(reason) == "":
		return ""
	default:
		return "other"
	}
}
