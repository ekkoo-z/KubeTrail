package kube

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
)

var defaultClusterExtensionGVR = schema.GroupVersionResource{
	Group:    "cluster.example.io",
	Version:  "v1",
	Resource: "clusterextensions",
}

type ClusterExtensionInfo struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace,omitempty"`
	Endpoint  string `json:"endpoint,omitempty"`
	ProxyPath string `json:"proxyPath"`
	Status    string `json:"status,omitempty"`
}

func ClusterExtensionProxyPath(name string) string {
	gvr := clusterExtensionGVR()
	return fmt.Sprintf("/apis/%s/%s/%s/%s/proxy",
		gvr.Group, gvr.Version,
		gvr.Resource, name)
}

func ListClusterExtensions(ctx context.Context, opts ConnectOptions) ([]ClusterExtensionInfo, error) {
	opts.APIPathPrefix = ""
	c, err := New(opts)
	if err != nil {
		return nil, err
	}
	dyn, err := dynamic.NewForConfig(c.Config)
	if err != nil {
		return nil, fmt.Errorf("dynamic client: %w", err)
	}
	list, err := dyn.Resource(clusterExtensionGVR()).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list clusterextensions: %w", err)
	}
	out := make([]ClusterExtensionInfo, 0, len(list.Items))
	for _, it := range list.Items {
		out = append(out, infoFromUnstructured(it))
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func clusterExtensionGVR() schema.GroupVersionResource {
	gvr := defaultClusterExtensionGVR
	if group := strings.TrimSpace(os.Getenv("KUBETRAIL_CLUSTER_EXTENSION_GROUP")); group != "" {
		gvr.Group = group
	}
	if version := strings.TrimSpace(os.Getenv("KUBETRAIL_CLUSTER_EXTENSION_VERSION")); version != "" {
		gvr.Version = version
	}
	if resource := strings.TrimSpace(os.Getenv("KUBETRAIL_CLUSTER_EXTENSION_RESOURCE")); resource != "" {
		gvr.Resource = resource
	}
	return gvr
}

func infoFromUnstructured(it unstructured.Unstructured) ClusterExtensionInfo {
	name := it.GetName()
	info := ClusterExtensionInfo{
		Name:      name,
		Namespace: it.GetNamespace(),
		ProxyPath: ClusterExtensionProxyPath(name),
	}
	if ep, found, _ := unstructured.NestedString(it.Object, "spec", "access", "endpoint"); found {
		info.Endpoint = ep
	}
	if ph, found, _ := unstructured.NestedString(it.Object, "status", "phase"); found {
		info.Status = ph
	} else if cond, found, _ := unstructured.NestedString(it.Object, "status", "conditions"); found {
		info.Status = cond
	}
	return info
}
