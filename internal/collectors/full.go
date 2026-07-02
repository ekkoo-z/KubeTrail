package collectors

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/ekkoo-z/KubeTrail/internal/model"
	"github.com/ekkoo-z/KubeTrail/internal/sysprobe"
)

func collectDNSServices(ctx context.Context, _ *Context) ([]model.Fact, []model.ErrorEntry) {
	type query struct {
		ID      string
		Service string
		Proto   string
		Name    string
	}
	queries := []query{
		{ID: "wildcard", Service: "any", Proto: "any", Name: "svc.cluster.local"},
		{ID: "kubernetes_default", Service: "https", Proto: "tcp", Name: "kubernetes.default.svc.cluster.local"},
		{ID: "kube_dns", Service: "dns", Proto: "udp", Name: "kube-dns.kube-system.svc.cluster.local"},
	}

	results := []map[string]any{}
	var errs []model.ErrorEntry
	for _, q := range queries {
		select {
		case <-ctx.Done():
			errs = append(errs, errEntry("dns", ctx.Err()))
			return []model.Fact{fact("dns_services.results", "network", "dns", false, results)}, errs
		default:
		}
		cname, records, err := net.LookupSRV(q.Service, q.Proto, q.Name)
		if err != nil {
			errs = append(errs, errEntry(q.ID, err))
			continue
		}
		items := make([]map[string]any, 0, len(records))
		for _, record := range records {
			items = append(items, map[string]any{
				"target":   record.Target,
				"port":     record.Port,
				"priority": record.Priority,
				"weight":   record.Weight,
			})
		}
		results = append(results, map[string]any{
			"id":      q.ID,
			"cname":   cname,
			"records": items,
		})
	}
	return []model.Fact{fact("dns_services.results", "network", "dns", false, results)}, errs
}

type cloudMetadataEndpoint struct {
	Provider string
	Method   string
	URL      string
	Headers  map[string]string
	TokenURL string
}

func cloudMetadataEndpoints() []cloudMetadataEndpoint {
	// Signal source: well-known cloud instance metadata services reachable from
	// the workload network namespace. Requires egress to link-local or provider
	// metadata DNS endpoints. Positive evidence is an HTTP response body/status;
	// negative evidence is connection refused, timeout, DNS failure, or 4xx.
	return []cloudMetadataEndpoint{
		{Provider: "aws", URL: "http://169.254.169.254/latest/meta-data/"},
		{Provider: "aws_identity", URL: "http://169.254.169.254/latest/dynamic/instance-identity/document"},
		{Provider: "azure", URL: "http://169.254.169.254/metadata/instance?api-version=2021-02-01", Headers: map[string]string{"Metadata": "true"}},
		{Provider: "gcp", URL: "http://metadata.google.internal/computeMetadata/v1/?recursive=true", Headers: map[string]string{"Metadata-Flavor": "Google"}},
		{Provider: "alibaba", URL: "http://100.100.100.200/latest/meta-data/"},
		{Provider: "tencent", URL: "http://metadata.tencentyun.com/latest/meta-data/"},
		{Provider: "tencent_cam_role_list", URL: "http://metadata.tencentyun.com/latest/meta-data/cam/security-credentials/"},
		{Provider: "huawei_openstack", URL: "http://169.254.169.254/openstack/latest/meta_data.json"},
		{Provider: "huawei_security_key", URL: "http://169.254.169.254/openstack/latest/securitykey"},
		{Provider: "huawei_ec2_compatible", URL: "http://169.254.169.254/latest/meta-data/"},
		{
			Provider: "huawei_openstack_v2",
			URL:      "http://169.254.169.254/openstack/latest/meta_data.json",
			TokenURL: "http://169.254.169.254/meta-data/latest/api/token",
		},
		{Provider: "oracle", URL: "http://192.0.0.192/latest/meta-data/"},
		{Provider: "digitalocean", URL: "http://169.254.169.254/metadata/v1/"},
	}
}

func collectCloudMetadata(ctx context.Context, _ *Context) ([]model.Fact, []model.ErrorEntry) {
	endpoints := cloudMetadataEndpoints()
	client := http.Client{Timeout: 100 * time.Millisecond}
	results := make([]map[string]any, 0, len(endpoints))
	var errs []model.ErrorEntry
	for _, endpoint := range endpoints {
		reqCtx, cancel := context.WithTimeout(ctx, 150*time.Millisecond)
		headers := copyHeaders(endpoint.Headers)
		item := map[string]any{
			"provider": endpoint.Provider,
			"url":      endpoint.URL,
			"method":   endpointMethod(endpoint),
		}
		if endpoint.TokenURL != "" {
			token, tokenInfo, err := requestCloudMetadataToken(reqCtx, &client, endpoint.TokenURL)
			item["token"] = tokenInfo
			if err != nil {
				cancel()
				item["reachable"] = false
				item["error"] = err.Error()
				results = append(results, item)
				continue
			}
			headers["X-Metadata-Token"] = token
		}
		req, err := http.NewRequestWithContext(reqCtx, endpointMethod(endpoint), endpoint.URL, nil)
		if err != nil {
			cancel()
			errs = append(errs, errEntry(endpoint.URL, err))
			continue
		}
		for key, value := range headers {
			req.Header.Set(key, value)
		}
		resp, err := client.Do(req)
		if err != nil {
			cancel()
			item["reachable"] = false
			item["error"] = err.Error()
			results = append(results, item)
			continue
		}
		data, readErr := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
		resp.Body.Close()
		cancel()
		item["reachable"] = true
		item["statusCode"] = resp.StatusCode
		item["bytes"] = len(data)
		item["body"] = string(data)
		if readErr != nil {
			item["readError"] = readErr.Error()
		}
		results = append(results, item)
	}

	return []model.Fact{fact("cloud_metadata.endpoints", "cloud", "http", true, results)}, errs
}

func requestCloudMetadataToken(ctx context.Context, client *http.Client, url string) (string, map[string]any, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, url, nil)
	if err != nil {
		return "", map[string]any{"url": url, "reachable": false}, err
	}
	req.Header.Set("X-Metadata-Token-Ttl-Seconds", "21600")
	resp, err := client.Do(req)
	if err != nil {
		return "", map[string]any{"url": url, "reachable": false, "error": err.Error()}, err
	}
	defer resp.Body.Close()
	data, readErr := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	info := map[string]any{
		"url":        url,
		"method":     http.MethodPut,
		"reachable":  true,
		"statusCode": resp.StatusCode,
		"bytes":      len(data),
	}
	if len(data) > 0 {
		sum := sha256.Sum256(data)
		info["sha256"] = hex.EncodeToString(sum[:])
	}
	if readErr != nil {
		info["readError"] = readErr.Error()
		return "", info, readErr
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", info, errStatus(resp.Status)
	}
	return string(data), info, nil
}

func endpointMethod(endpoint cloudMetadataEndpoint) string {
	if endpoint.Method != "" {
		return endpoint.Method
	}
	return http.MethodGet
}

func copyHeaders(headers map[string]string) map[string]string {
	out := map[string]string{}
	for key, value := range headers {
		out[key] = value
	}
	return out
}

type errStatus string

func (e errStatus) Error() string { return "metadata token request returned " + string(e) }

func collectAdmissionDryRun(ctx context.Context, cctx *Context) ([]model.Fact, []model.ErrorEntry) {
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

	tests := map[string]map[string]any{
		"baseline":      podSpec("kubetrail-baseline-", map[string]any{}),
		"privileged":    podSpec("kubetrail-privileged-", map[string]any{"securityContext": map[string]any{"privileged": true}}),
		"host_pid":      withPodSpec(podSpec("kubetrail-hostpid-", map[string]any{}), "hostPID", true),
		"host_network":  withPodSpec(podSpec("kubetrail-hostnet-", map[string]any{}), "hostNetwork", true),
		"host_path":     withHostPath(podSpec("kubetrail-hostpath-", map[string]any{})),
		"cap_sys_admin": podSpec("kubetrail-caps-", map[string]any{"securityContext": map[string]any{"capabilities": map[string]any{"add": []string{"SYS_ADMIN"}}}}),
		"seccomp_unconfined": withPodSpec(podSpec("kubetrail-seccomp-", map[string]any{}), "securityContext", map[string]any{
			"seccompProfile": map[string]any{"type": "Unconfined"},
		}),
	}

	results := []map[string]any{}
	var errs []model.ErrorEntry
	for name, spec := range tests {
		resp, err := client.DryRunPod(ctx, namespace, spec)
		if err != nil {
			results = append(results, map[string]any{
				"name":    name,
				"allowed": false,
				"error":   err.Error(),
			})
			continue
		}
		results = append(results, map[string]any{
			"name":     name,
			"allowed":  true,
			"response": resp,
		})
	}

	return []model.Fact{fact("admission_dryrun.pods", "kubernetes", "dryRun=All", false, results)}, errs
}

func collectSyscalls(ctx context.Context, _ *Context) ([]model.Fact, []model.ErrorEntry) {
	results := sysprobe.RunMatrix(ctx)
	return []model.Fact{fact("syscalls.matrix", "process", "syscall", false, results)}, nil
}

func podSpec(generateName string, containerFields map[string]any) map[string]any {
	container := map[string]any{
		"name":    "probe",
		"image":   "registry.k8s.io/pause:3.9",
		"command": []string{"/pause"},
	}
	for key, value := range containerFields {
		container[key] = value
	}
	return map[string]any{
		"apiVersion": "v1",
		"kind":       "Pod",
		"metadata": map[string]any{
			"generateName": generateName,
			"labels": map[string]any{
				"app.kubernetes.io/name":       "kubetrail",
				"app.kubernetes.io/component":  "admission-dryrun",
				"app.kubernetes.io/managed-by": "kubetrail-server",
			},
		},
		"spec": map[string]any{
			"restartPolicy": "Never",
			"containers":    []any{container},
		},
	}
}

func withPodSpec(pod map[string]any, key string, value any) map[string]any {
	spec, _ := pod["spec"].(map[string]any)
	spec[key] = value
	return pod
}

func withHostPath(pod map[string]any) map[string]any {
	spec, _ := pod["spec"].(map[string]any)
	spec["volumes"] = []any{
		map[string]any{
			"name": "host-root",
			"hostPath": map[string]any{
				"path": "/",
				"type": "Directory",
			},
		},
	}
	containers, _ := spec["containers"].([]any)
	container, _ := containers[0].(map[string]any)
	container["volumeMounts"] = []any{
		map[string]any{
			"name":      "host-root",
			"mountPath": "/host",
			"readOnly":  true,
		},
	}
	return pod
}
