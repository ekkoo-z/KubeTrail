package collectors

import (
	"context"
	"os"
	"regexp"
	"sort"
	"strings"

	"github.com/ekkoo-z/KubeTrail/internal/kube"
	"github.com/ekkoo-z/KubeTrail/internal/model"
)

var podUIDPattern = regexp.MustCompile(`(?i)pod([0-9a-f]{8}[-_][0-9a-f]{4}[-_][0-9a-f]{4}[-_][0-9a-f]{4}[-_][0-9a-f]{12})`)

func collectKubernetesProfile(ctx context.Context, cctx *Context) ([]model.Fact, []model.ErrorEntry) {
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

	var facts []model.Fact
	var errs []model.ErrorEntry

	pod, resolution, resolveErrs := resolveCurrentPod(ctx, cctx, client, namespace)
	errs = append(errs, resolveErrs...)
	facts = append(facts, fact("k8s_profile.current_pod_resolution", "kubernetes", "pod", false, resolution))
	if pod == nil {
		return facts, errs
	}

	profile := summarizePod(pod)
	facts = append(facts, fact("k8s_profile.current_pod_structured", "kubernetes", "pod", true, profile))
	facts = append(facts, fact("k8s_profile.current_pod_references", "kubernetes", "pod", false, podReferences(pod)))

	owners, ownerErrs := ownerChain(ctx, client, namespace, ownerRefs(pod), 5)
	errs = append(errs, ownerErrs...)
	facts = append(facts, fact("k8s_profile.owner_chain", "kubernetes", "ownerReferences", false, owners))

	namespaceFacts, namespaceErrs := namespaceContext(ctx, client, namespace)
	errs = append(errs, namespaceErrs...)
	facts = append(facts, fact("k8s_profile.namespace_context", "kubernetes", "namespace", false, namespaceFacts))

	nodeName := stringFromPath(pod, "spec", "nodeName")
	if nodeName != "" {
		node, err := client.GetResource(ctx, kube.APIResource{GroupVersion: "v1", Version: "v1", Name: "nodes", Kind: "Node"}, "", nodeName)
		if err != nil {
			errs = append(errs, errEntry("nodes/"+nodeName, err))
		} else {
			facts = append(facts, fact("k8s_profile.node_context", "kubernetes", "node", false, summarizeNode(node)))
		}
	}

	network, networkErrs := networkContext(ctx, client, namespace)
	errs = append(errs, networkErrs...)
	facts = append(facts, fact("k8s_profile.network_context", "kubernetes", "network api", false, network))

	policies, policyErrs := policyAndSecurityComponents(ctx, client, namespace)
	errs = append(errs, policyErrs...)
	facts = append(facts, fact("k8s_profile.policy_security_components", "kubernetes", "policy api", false, policies))

	return facts, errs
}

func resolveCurrentPod(ctx context.Context, cctx *Context, client *kube.Client, namespace string) (map[string]any, map[string]any, []model.ErrorEntry) {
	var errs []model.ErrorEntry
	candidates := uniqueStrings([]string{
		cctx.Env["POD_NAME"],
		cctx.Env["MY_POD_NAME"],
		cctx.Env["HOSTNAME"],
		mustHostname(),
	})
	podUID := podUIDFromCgroup(cctx)
	containerIDs := containerIDsFromCgroup(cctx)
	resolution := map[string]any{
		"namespace":              namespace,
		"nameCandidates":         candidates,
		"podUIDFromCgroup":       podUID,
		"containerIDsFromCgroup": containerIDs,
	}

	for _, name := range candidates {
		if name == "" {
			continue
		}
		pod, err := client.GetPod(ctx, namespace, name)
		if err != nil {
			errs = append(errs, errEntry("pods/"+name, err))
			continue
		}
		resolution["method"] = "get_by_name"
		resolution["matchedName"] = name
		return pod, resolution, errs
	}

	list, err := client.ListResource(ctx, kube.APIResource{GroupVersion: "v1", Version: "v1", Name: "pods", Kind: "Pod", Namespaced: true}, namespace, cctx.Options.MaxItems)
	if err != nil {
		errs = append(errs, errEntry("pods list", err))
		resolution["method"] = "unresolved"
		return nil, resolution, errs
	}

	pod := matchPodFromList(list, podUID, containerIDs, candidates)
	if pod != nil {
		resolution["method"] = "list_match"
		resolution["matchedName"] = stringFromPath(pod, "metadata", "name")
		resolution["matchedUID"] = stringFromPath(pod, "metadata", "uid")
		return pod, resolution, errs
	}

	resolution["method"] = "unresolved"
	return nil, resolution, errs
}

func summarizePod(pod map[string]any) map[string]any {
	spec := mapFromPath(pod, "spec")
	status := mapFromPath(pod, "status")
	meta := mapFromPath(pod, "metadata")
	return map[string]any{
		"metadata": map[string]any{
			"name":              meta["name"],
			"namespace":         meta["namespace"],
			"uid":               meta["uid"],
			"labels":            meta["labels"],
			"annotations":       meta["annotations"],
			"ownerReferences":   meta["ownerReferences"],
			"creationTimestamp": meta["creationTimestamp"],
		},
		"spec": map[string]any{
			"nodeName":                     spec["nodeName"],
			"serviceAccountName":           spec["serviceAccountName"],
			"automountServiceAccountToken": spec["automountServiceAccountToken"],
			"hostNetwork":                  spec["hostNetwork"],
			"hostPID":                      spec["hostPID"],
			"hostIPC":                      spec["hostIPC"],
			"hostUsers":                    spec["hostUsers"],
			"dnsPolicy":                    spec["dnsPolicy"],
			"dnsConfig":                    spec["dnsConfig"],
			"hostAliases":                  spec["hostAliases"],
			"imagePullSecrets":             spec["imagePullSecrets"],
			"securityContext":              spec["securityContext"],
			"volumes":                      summarizeVolumes(sliceFromPath(pod, "spec", "volumes")),
			"containers":                   summarizeContainers(sliceFromPath(pod, "spec", "containers")),
			"initContainers":               summarizeContainers(sliceFromPath(pod, "spec", "initContainers")),
			"ephemeralContainers":          summarizeContainers(sliceFromPath(pod, "spec", "ephemeralContainers")),
		},
		"status": map[string]any{
			"phase":                      status["phase"],
			"podIP":                      status["podIP"],
			"podIPs":                     status["podIPs"],
			"hostIP":                     status["hostIP"],
			"startTime":                  status["startTime"],
			"containerStatuses":          summarizeContainerStatuses(sliceFromPath(pod, "status", "containerStatuses")),
			"initContainerStatuses":      summarizeContainerStatuses(sliceFromPath(pod, "status", "initContainerStatuses")),
			"ephemeralContainerStatuses": summarizeContainerStatuses(sliceFromPath(pod, "status", "ephemeralContainerStatuses")),
		},
	}
}

func podReferences(pod map[string]any) map[string]any {
	spec := mapFromPath(pod, "spec")
	refs := map[string]any{
		"serviceAccountName":     spec["serviceAccountName"],
		"imagePullSecrets":       namesFromObjects(sliceFromPath(pod, "spec", "imagePullSecrets")),
		"secrets":                []string{},
		"configMaps":             []string{},
		"projectedTokens":        []map[string]any{},
		"persistentVolumeClaims": []string{},
		"hostPaths":              []map[string]any{},
	}
	secretSet := map[string]bool{}
	configMapSet := map[string]bool{}
	pvcSet := map[string]bool{}
	var projectedTokens []map[string]any
	var hostPaths []map[string]any

	for _, raw := range sliceFromPath(pod, "spec", "volumes") {
		vol, _ := raw.(map[string]any)
		if secret := mapFromAny(vol["secret"]); secret != nil {
			addString(secretSet, stringValueAny(secret["secretName"]))
		}
		if cm := mapFromAny(vol["configMap"]); cm != nil {
			addString(configMapSet, stringValueAny(cm["name"]))
		}
		if pvc := mapFromAny(vol["persistentVolumeClaim"]); pvc != nil {
			addString(pvcSet, stringValueAny(pvc["claimName"]))
		}
		if hp := mapFromAny(vol["hostPath"]); hp != nil {
			hostPaths = append(hostPaths, map[string]any{"name": vol["name"], "path": hp["path"], "type": hp["type"]})
		}
		if projected := mapFromAny(vol["projected"]); projected != nil {
			for _, sourceRaw := range sliceFromAny(projected["sources"]) {
				source, _ := sourceRaw.(map[string]any)
				if secret := mapFromAny(source["secret"]); secret != nil {
					addString(secretSet, stringValueAny(secret["name"]))
				}
				if cm := mapFromAny(source["configMap"]); cm != nil {
					addString(configMapSet, stringValueAny(cm["name"]))
				}
				if token := mapFromAny(source["serviceAccountToken"]); token != nil {
					projectedTokens = append(projectedTokens, token)
				}
			}
		}
	}
	for _, containerSet := range [][]any{
		sliceFromPath(pod, "spec", "containers"),
		sliceFromPath(pod, "spec", "initContainers"),
		sliceFromPath(pod, "spec", "ephemeralContainers"),
	} {
		for _, raw := range containerSet {
			container, _ := raw.(map[string]any)
			for _, envRaw := range sliceFromAny(container["env"]) {
				env, _ := envRaw.(map[string]any)
				valueFrom := mapFromAny(env["valueFrom"])
				if valueFrom == nil {
					continue
				}
				if secretKeyRef := mapFromAny(valueFrom["secretKeyRef"]); secretKeyRef != nil {
					addString(secretSet, stringValueAny(secretKeyRef["name"]))
				}
				if configMapKeyRef := mapFromAny(valueFrom["configMapKeyRef"]); configMapKeyRef != nil {
					addString(configMapSet, stringValueAny(configMapKeyRef["name"]))
				}
			}
			for _, envFromRaw := range sliceFromAny(container["envFrom"]) {
				envFrom, _ := envFromRaw.(map[string]any)
				if secretRef := mapFromAny(envFrom["secretRef"]); secretRef != nil {
					addString(secretSet, stringValueAny(secretRef["name"]))
				}
				if configMapRef := mapFromAny(envFrom["configMapRef"]); configMapRef != nil {
					addString(configMapSet, stringValueAny(configMapRef["name"]))
				}
			}
		}
	}

	refs["secrets"] = setToSortedSlice(secretSet)
	refs["configMaps"] = setToSortedSlice(configMapSet)
	refs["persistentVolumeClaims"] = setToSortedSlice(pvcSet)
	refs["projectedTokens"] = projectedTokens
	refs["hostPaths"] = hostPaths
	return refs
}

func ownerChain(ctx context.Context, client *kube.Client, namespace string, refs []map[string]any, depth int) ([]map[string]any, []model.ErrorEntry) {
	var out []map[string]any
	var errs []model.ErrorEntry
	currentRefs := refs
	for level := 0; level < depth && len(currentRefs) > 0; level++ {
		ref := currentRefs[0]
		resource, ok := ownerResource(stringValueAny(ref["apiVersion"]), stringValueAny(ref["kind"]))
		if !ok {
			out = append(out, map[string]any{"level": level, "reference": ref, "resolved": false})
			break
		}
		obj, err := client.GetResource(ctx, resource, namespace, stringValueAny(ref["name"]))
		if err != nil {
			errs = append(errs, errEntry(resource.Name+"/"+stringValueAny(ref["name"]), err))
			out = append(out, map[string]any{"level": level, "reference": ref, "resolved": false, "error": err.Error()})
			break
		}
		summary := map[string]any{
			"level":      level,
			"kind":       stringFromPath(obj, "kind"),
			"apiVersion": stringFromPath(obj, "apiVersion"),
			"metadata": map[string]any{
				"name":            stringFromPath(obj, "metadata", "name"),
				"namespace":       stringFromPath(obj, "metadata", "namespace"),
				"uid":             stringFromPath(obj, "metadata", "uid"),
				"labels":          mapFromPath(obj, "metadata", "labels"),
				"ownerReferences": sliceFromPath(obj, "metadata", "ownerReferences"),
			},
			"spec": summarizeControllerSpec(obj),
		}
		out = append(out, summary)
		currentRefs = ownerRefs(obj)
	}
	return out, errs
}

func namespaceContext(ctx context.Context, client *kube.Client, namespace string) (map[string]any, []model.ErrorEntry) {
	var errs []model.ErrorEntry
	out := map[string]any{}
	ns, err := client.GetResource(ctx, kube.APIResource{GroupVersion: "v1", Version: "v1", Name: "namespaces", Kind: "Namespace"}, "", namespace)
	if err != nil {
		errs = append(errs, errEntry("namespaces/"+namespace, err))
	} else {
		out["namespace"] = ns
	}
	for key, resource := range map[string]kube.APIResource{
		"resourceQuotas":  {GroupVersion: "v1", Version: "v1", Name: "resourcequotas", Kind: "ResourceQuota", Namespaced: true},
		"limitRanges":     {GroupVersion: "v1", Version: "v1", Name: "limitranges", Kind: "LimitRange", Namespaced: true},
		"serviceAccounts": {GroupVersion: "v1", Version: "v1", Name: "serviceaccounts", Kind: "ServiceAccount", Namespaced: true},
		"events":          {GroupVersion: "v1", Version: "v1", Name: "events", Kind: "Event", Namespaced: true},
	} {
		list, err := client.ListResource(ctx, resource, namespace, 100)
		if err != nil {
			errs = append(errs, errEntry(resource.Name, err))
			continue
		}
		out[key] = list
	}
	return out, errs
}

func networkContext(ctx context.Context, client *kube.Client, namespace string) (map[string]any, []model.ErrorEntry) {
	var errs []model.ErrorEntry
	out := map[string]any{}
	for key, resource := range map[string]kube.APIResource{
		"services":        {GroupVersion: "v1", Version: "v1", Name: "services", Kind: "Service", Namespaced: true},
		"endpoints":       {GroupVersion: "v1", Version: "v1", Name: "endpoints", Kind: "Endpoints", Namespaced: true},
		"endpointSlices":  {GroupVersion: "discovery.k8s.io/v1", Group: "discovery.k8s.io", Version: "v1", Name: "endpointslices", Kind: "EndpointSlice", Namespaced: true},
		"networkPolicies": {GroupVersion: "networking.k8s.io/v1", Group: "networking.k8s.io", Version: "v1", Name: "networkpolicies", Kind: "NetworkPolicy", Namespaced: true},
		"ingresses":       {GroupVersion: "networking.k8s.io/v1", Group: "networking.k8s.io", Version: "v1", Name: "ingresses", Kind: "Ingress", Namespaced: true},
		"gateways":        {GroupVersion: "gateway.networking.k8s.io/v1", Group: "gateway.networking.k8s.io", Version: "v1", Name: "gateways", Kind: "Gateway", Namespaced: true},
		"httpRoutes":      {GroupVersion: "gateway.networking.k8s.io/v1", Group: "gateway.networking.k8s.io", Version: "v1", Name: "httproutes", Kind: "HTTPRoute", Namespaced: true},
	} {
		list, err := client.ListResource(ctx, resource, namespace, 100)
		if err != nil {
			errs = append(errs, errEntry(resource.GroupVersion+"/"+resource.Name, err))
			continue
		}
		out[key] = list
	}
	return out, errs
}

func policyAndSecurityComponents(ctx context.Context, client *kube.Client, namespace string) (map[string]any, []model.ErrorEntry) {
	var errs []model.ErrorEntry
	out := map[string]any{}
	for key, resource := range map[string]kube.APIResource{
		"mutatingWebhookConfigurations":     {GroupVersion: "admissionregistration.k8s.io/v1", Group: "admissionregistration.k8s.io", Version: "v1", Name: "mutatingwebhookconfigurations", Kind: "MutatingWebhookConfiguration"},
		"validatingWebhookConfigurations":   {GroupVersion: "admissionregistration.k8s.io/v1", Group: "admissionregistration.k8s.io", Version: "v1", Name: "validatingwebhookconfigurations", Kind: "ValidatingWebhookConfiguration"},
		"validatingAdmissionPolicies":       {GroupVersion: "admissionregistration.k8s.io/v1", Group: "admissionregistration.k8s.io", Version: "v1", Name: "validatingadmissionpolicies", Kind: "ValidatingAdmissionPolicy"},
		"validatingAdmissionPolicyBindings": {GroupVersion: "admissionregistration.k8s.io/v1", Group: "admissionregistration.k8s.io", Version: "v1", Name: "validatingadmissionpolicybindings", Kind: "ValidatingAdmissionPolicyBinding"},
		"kyvernoClusterPolicies":            {GroupVersion: "kyverno.io/v1", Group: "kyverno.io", Version: "v1", Name: "clusterpolicies", Kind: "ClusterPolicy"},
		"gatekeeperConstraints":             {GroupVersion: "constraints.gatekeeper.sh/v1beta1", Group: "constraints.gatekeeper.sh", Version: "v1beta1", Name: "k8spspprivilegedcontainer", Kind: "K8sPSPPrivilegedContainer"},
		"ciliumNetworkPolicies":             {GroupVersion: "cilium.io/v2", Group: "cilium.io", Version: "v2", Name: "ciliumnetworkpolicies", Kind: "CiliumNetworkPolicy", Namespaced: true},
		"ciliumClusterwideNetworkPolicies":  {GroupVersion: "cilium.io/v2", Group: "cilium.io", Version: "v2", Name: "ciliumclusterwidenetworkpolicies", Kind: "CiliumClusterwideNetworkPolicy"},
	} {
		ns := ""
		if resource.Namespaced {
			ns = namespace
		}
		list, err := client.ListResource(ctx, resource, ns, 100)
		if err != nil {
			errs = append(errs, errEntry(resource.GroupVersion+"/"+resource.Name, err))
			continue
		}
		out[key] = list
	}
	return out, errs
}

func summarizeNode(node map[string]any) map[string]any {
	return map[string]any{
		"metadata": map[string]any{
			"name":        stringFromPath(node, "metadata", "name"),
			"uid":         stringFromPath(node, "metadata", "uid"),
			"labels":      mapFromPath(node, "metadata", "labels"),
			"annotations": mapFromPath(node, "metadata", "annotations"),
		},
		"spec": map[string]any{
			"taints":        sliceFromPath(node, "spec", "taints"),
			"podCIDR":       stringFromPath(node, "spec", "podCIDR"),
			"podCIDRs":      sliceFromPath(node, "spec", "podCIDRs"),
			"providerID":    stringFromPath(node, "spec", "providerID"),
			"unschedulable": mapFromPath(node, "spec")["unschedulable"],
		},
		"status": map[string]any{
			"addresses":   sliceFromPath(node, "status", "addresses"),
			"capacity":    mapFromPath(node, "status", "capacity"),
			"allocatable": mapFromPath(node, "status", "allocatable"),
			"nodeInfo":    mapFromPath(node, "status", "nodeInfo"),
			"conditions":  sliceFromPath(node, "status", "conditions"),
		},
	}
}

func summarizeControllerSpec(obj map[string]any) map[string]any {
	spec := mapFromPath(obj, "spec")
	return map[string]any{
		"replicas":                   spec["replicas"],
		"selector":                   spec["selector"],
		"templateMetadata":           mapFromPath(obj, "spec", "template", "metadata"),
		"templateSpec":               summarizePodTemplateSpec(mapFromPath(obj, "spec", "template", "spec")),
		"jobTemplateMetadata":        mapFromPath(obj, "spec", "jobTemplate", "metadata"),
		"jobTemplateSpec":            mapFromPath(obj, "spec", "jobTemplate", "spec"),
		"schedule":                   spec["schedule"],
		"concurrencyPolicy":          spec["concurrencyPolicy"],
		"successfulJobsHistoryLimit": spec["successfulJobsHistoryLimit"],
		"failedJobsHistoryLimit":     spec["failedJobsHistoryLimit"],
	}
}

func summarizePodTemplateSpec(spec map[string]any) map[string]any {
	if len(spec) == 0 {
		return nil
	}
	return map[string]any{
		"serviceAccountName": spec["serviceAccountName"],
		"hostNetwork":        spec["hostNetwork"],
		"hostPID":            spec["hostPID"],
		"hostIPC":            spec["hostIPC"],
		"securityContext":    spec["securityContext"],
		"volumes":            summarizeVolumes(sliceFromAny(spec["volumes"])),
		"containers":         summarizeContainers(sliceFromAny(spec["containers"])),
		"initContainers":     summarizeContainers(sliceFromAny(spec["initContainers"])),
	}
}

func summarizeContainers(values []any) []map[string]any {
	out := make([]map[string]any, 0, len(values))
	for _, raw := range values {
		container, _ := raw.(map[string]any)
		if container == nil {
			continue
		}
		out = append(out, map[string]any{
			"name":            container["name"],
			"image":           container["image"],
			"imagePullPolicy": container["imagePullPolicy"],
			"command":         container["command"],
			"args":            container["args"],
			"ports":           container["ports"],
			"env":             container["env"],
			"envFrom":         container["envFrom"],
			"volumeMounts":    container["volumeMounts"],
			"securityContext": container["securityContext"],
			"resources":       container["resources"],
			"readinessProbe":  container["readinessProbe"],
			"livenessProbe":   container["livenessProbe"],
			"startupProbe":    container["startupProbe"],
		})
	}
	return out
}

func summarizeVolumes(values []any) []map[string]any {
	out := make([]map[string]any, 0, len(values))
	for _, raw := range values {
		volume, _ := raw.(map[string]any)
		if volume == nil {
			continue
		}
		item := map[string]any{"name": volume["name"], "type": volumeType(volume)}
		for _, key := range []string{"secret", "configMap", "projected", "hostPath", "persistentVolumeClaim", "csi", "nfs", "emptyDir", "downwardAPI", "serviceAccountToken"} {
			if value, ok := volume[key]; ok {
				item[key] = value
			}
		}
		out = append(out, item)
	}
	return out
}

func summarizeContainerStatuses(values []any) []map[string]any {
	out := make([]map[string]any, 0, len(values))
	for _, raw := range values {
		status, _ := raw.(map[string]any)
		if status == nil {
			continue
		}
		out = append(out, map[string]any{
			"name":         status["name"],
			"ready":        status["ready"],
			"restartCount": status["restartCount"],
			"image":        status["image"],
			"imageID":      status["imageID"],
			"containerID":  status["containerID"],
			"state":        status["state"],
			"lastState":    status["lastState"],
		})
	}
	return out
}

func volumeType(volume map[string]any) string {
	for _, key := range []string{"secret", "configMap", "projected", "hostPath", "persistentVolumeClaim", "csi", "nfs", "emptyDir", "downwardAPI", "serviceAccountToken"} {
		if _, ok := volume[key]; ok {
			return key
		}
	}
	return "unknown"
}

func ownerResource(apiVersion, kind string) (kube.APIResource, bool) {
	switch kind {
	case "ReplicaSet":
		return kube.APIResource{GroupVersion: "apps/v1", Group: "apps", Version: "v1", Name: "replicasets", Kind: kind, Namespaced: true}, true
	case "Deployment":
		return kube.APIResource{GroupVersion: "apps/v1", Group: "apps", Version: "v1", Name: "deployments", Kind: kind, Namespaced: true}, true
	case "DaemonSet":
		return kube.APIResource{GroupVersion: "apps/v1", Group: "apps", Version: "v1", Name: "daemonsets", Kind: kind, Namespaced: true}, true
	case "StatefulSet":
		return kube.APIResource{GroupVersion: "apps/v1", Group: "apps", Version: "v1", Name: "statefulsets", Kind: kind, Namespaced: true}, true
	case "Job":
		return kube.APIResource{GroupVersion: "batch/v1", Group: "batch", Version: "v1", Name: "jobs", Kind: kind, Namespaced: true}, true
	case "CronJob":
		return kube.APIResource{GroupVersion: "batch/v1", Group: "batch", Version: "v1", Name: "cronjobs", Kind: kind, Namespaced: true}, true
	case "ReplicationController":
		return kube.APIResource{GroupVersion: "v1", Version: "v1", Name: "replicationcontrollers", Kind: kind, Namespaced: true}, true
	default:
		_ = apiVersion
		return kube.APIResource{}, false
	}
}

func ownerRefs(obj map[string]any) []map[string]any {
	var out []map[string]any
	for _, raw := range sliceFromPath(obj, "metadata", "ownerReferences") {
		ref, _ := raw.(map[string]any)
		if ref != nil {
			out = append(out, ref)
		}
	}
	return out
}

func podUIDFromCgroup(cctx *Context) string {
	data, err := os.ReadFile(cctx.RootPath("/proc/self/cgroup"))
	if err != nil {
		return ""
	}
	match := podUIDPattern.FindStringSubmatch(string(data))
	if len(match) < 2 {
		return ""
	}
	return normalizeUID(match[1])
}

func containerIDsFromCgroup(cctx *Context) []string {
	data, err := os.ReadFile(cctx.RootPath("/proc/self/cgroup"))
	if err != nil {
		return nil
	}
	return uniqueStrings(containerIDPattern.FindAllString(string(data), -1))
}

func matchPodFromList(list map[string]any, podUID string, containerIDs []string, candidates []string) map[string]any {
	candidateSet := map[string]bool{}
	for _, value := range candidates {
		if value != "" {
			candidateSet[value] = true
		}
	}
	containerSet := map[string]bool{}
	for _, value := range containerIDs {
		containerSet[value] = true
	}
	for _, raw := range sliceFromAny(list["items"]) {
		pod, _ := raw.(map[string]any)
		if pod == nil {
			continue
		}
		if podUID != "" && normalizeUID(stringFromPath(pod, "metadata", "uid")) == podUID {
			return pod
		}
		if candidateSet[stringFromPath(pod, "metadata", "name")] {
			return pod
		}
		for _, statusRaw := range sliceFromPath(pod, "status", "containerStatuses") {
			status, _ := statusRaw.(map[string]any)
			id := stringValueAny(status["containerID"])
			for containerID := range containerSet {
				if strings.Contains(id, containerID) {
					return pod
				}
			}
		}
	}
	return nil
}

func mapFromPath(value map[string]any, keys ...string) map[string]any {
	current := value
	for _, key := range keys {
		next, _ := current[key].(map[string]any)
		if next == nil {
			return nil
		}
		current = next
	}
	return current
}

func stringFromPath(value map[string]any, keys ...string) string {
	current := value
	for i, key := range keys {
		raw, ok := current[key]
		if !ok {
			return ""
		}
		if i == len(keys)-1 {
			return stringValueAny(raw)
		}
		next, _ := raw.(map[string]any)
		if next == nil {
			return ""
		}
		current = next
	}
	return ""
}

func sliceFromPath(value map[string]any, keys ...string) []any {
	current := value
	for i, key := range keys {
		raw, ok := current[key]
		if !ok {
			return nil
		}
		if i == len(keys)-1 {
			return sliceFromAny(raw)
		}
		next, _ := raw.(map[string]any)
		if next == nil {
			return nil
		}
		current = next
	}
	return nil
}

func mapFromAny(value any) map[string]any {
	out, _ := value.(map[string]any)
	return out
}

func sliceFromAny(value any) []any {
	out, _ := value.([]any)
	return out
}

func stringValueAny(value any) string {
	out, _ := value.(string)
	return out
}

func mustHostname() string {
	hostname, _ := os.Hostname()
	return hostname
}

func normalizeUID(value string) string {
	return strings.ToLower(strings.ReplaceAll(value, "_", "-"))
}

func uniqueStrings(values []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, value := range values {
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	return out
}

func namesFromObjects(values []any) []string {
	var out []string
	for _, raw := range values {
		obj, _ := raw.(map[string]any)
		if name := stringValueAny(obj["name"]); name != "" {
			out = append(out, name)
		}
	}
	return uniqueStrings(out)
}

func addString(set map[string]bool, value string) {
	if value != "" {
		set[value] = true
	}
}

func setToSortedSlice(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for value := range set {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}
