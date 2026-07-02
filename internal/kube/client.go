package kube

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"

	authv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	_ "k8s.io/client-go/plugin/pkg/client/auth"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

type Options struct {
	Root       string
	Env        map[string]string
	Kubeconfig string
	QPS        float32
	Burst      int
}

type Client struct {
	BaseURL   string
	Namespace string
	Token     string
	CAPath    string

	Config    *rest.Config
	Typed     kubernetes.Interface
	Dynamic   dynamic.Interface
	Discovery discovery.DiscoveryInterface
}

type APIResource struct {
	GroupVersion string   `json:"groupVersion"`
	Group        string   `json:"group"`
	Version      string   `json:"version"`
	Name         string   `json:"name"`
	Kind         string   `json:"kind"`
	Namespaced   bool     `json:"namespaced"`
	Verbs        []string `json:"verbs,omitempty"`
}

type ResourceRule struct {
	Verbs         []string `json:"verbs"`
	APIGroups     []string `json:"apiGroups"`
	Resources     []string `json:"resources"`
	ResourceNames []string `json:"resourceNames,omitempty"`
}

type RulesReviewStatus struct {
	ResourceRules    []ResourceRule   `json:"resourceRules,omitempty"`
	NonResourceRules []map[string]any `json:"nonResourceRules,omitempty"`
	Incomplete       bool             `json:"incomplete,omitempty"`
	EvaluationError  string           `json:"evaluationError,omitempty"`
	Raw              map[string]any   `json:"raw,omitempty"`
}

type ResourceAttributes struct {
	Namespace   string `json:"namespace,omitempty"`
	Verb        string `json:"verb,omitempty"`
	Group       string `json:"group,omitempty"`
	Version     string `json:"version,omitempty"`
	Resource    string `json:"resource,omitempty"`
	Subresource string `json:"subresource,omitempty"`
	Name        string `json:"name,omitempty"`
}

type AccessReviewResult struct {
	ResourceAttributes ResourceAttributes `json:"resourceAttributes"`
	Allowed            bool               `json:"allowed"`
	Denied             bool               `json:"denied,omitempty"`
	Reason             string             `json:"reason,omitempty"`
	EvaluationError    string             `json:"evaluationError,omitempty"`
}

const (
	defaultRequestTimeout = 15 * time.Second
	defaultQPS            = float32(50)
	defaultBurst          = 100
)

func ServiceAccountPaths() []string {
	return []string{
		"/run/secrets/kubernetes.io/serviceaccount",
		"/var/run/secrets/kubernetes.io/serviceaccount",
	}
}

func NewClient(opts Options) (*Client, error) {
	var cfg *rest.Config
	var namespace string
	var err error

	if opts.Kubeconfig != "" {
		cfg, namespace, err = configFromKubeconfig(opts.Kubeconfig)
	} else {
		cfg, namespace, err = configFromInCluster(opts)
	}
	if err != nil {
		return nil, err
	}

	return newClientFromConfig(cfg, namespace, opts)
}

func NewClientFromRestConfig(cfg *rest.Config, namespace string, opts Options) (*Client, error) {
	return newClientFromConfig(cfg, namespace, opts)
}

func NewClientWithBearerToken(base *Client, token, namespace string, opts Options) (*Client, error) {
	cfg := rest.CopyConfig(base.Config)
	cfg.BearerToken = token
	cfg.BearerTokenFile = ""
	cfg.Username = ""
	cfg.Password = ""
	cfg.AuthProvider = nil
	cfg.ExecProvider = nil
	cfg.Impersonate = rest.ImpersonationConfig{}
	cfg.TLSClientConfig.CertData = nil
	cfg.TLSClientConfig.KeyData = nil
	cfg.TLSClientConfig.CertFile = ""
	cfg.TLSClientConfig.KeyFile = ""
	return newClientFromConfig(cfg, namespace, opts)
}

func newClientFromConfig(cfg *rest.Config, namespace string, opts Options) (*Client, error) {
	cfg = rest.CopyConfig(cfg)
	configureRESTClient(cfg, opts)

	typed, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, err
	}
	dyn, err := dynamic.NewForConfig(cfg)
	if err != nil {
		return nil, err
	}
	disco, err := discovery.NewDiscoveryClientForConfig(cfg)
	if err != nil {
		return nil, err
	}

	return &Client{
		BaseURL:   strings.TrimRight(cfg.Host, "/"),
		Namespace: namespace,
		Token:     cfg.BearerToken,
		CAPath:    cfg.CAFile,
		Config:    cfg,
		Typed:     typed,
		Dynamic:   dyn,
		Discovery: disco,
	}, nil
}

func configureRESTClient(cfg *rest.Config, opts Options) {
	cfg.Timeout = defaultRequestTimeout
	cfg.UserAgent = "kubetrail-server"
	if opts.QPS > 0 {
		cfg.QPS = opts.QPS
	} else {
		cfg.QPS = defaultQPS
	}
	if opts.Burst > 0 {
		cfg.Burst = opts.Burst
	} else {
		cfg.Burst = defaultBurst
	}
}

func configFromInCluster(opts Options) (*rest.Config, string, error) {
	cfg, err := rest.InClusterConfig()
	if err != nil {
		return nil, "", err
	}
	namespace := readNamespace(opts.Root)
	if namespace == "" {
		namespace = opts.Env["POD_NAMESPACE"]
	}
	return cfg, namespace, nil
}

func configFromKubeconfig(path string) (*rest.Config, string, error) {
	cfg, err := clientcmd.BuildConfigFromFlags("", path)
	if err != nil {
		return nil, "", err
	}

	namespace := ""
	raw, err := clientcmd.LoadFromFile(path)
	if err == nil {
		if ctx := raw.Contexts[raw.CurrentContext]; ctx != nil {
			namespace = ctx.Namespace
		}
	}
	return cfg, namespace, nil
}

func readNamespace(root string) string {
	for _, saPath := range ServiceAccountPaths() {
		data, err := os.ReadFile(rootPath(root, filepath.Join(saPath, "namespace")))
		if err == nil {
			return strings.TrimSpace(string(data))
		}
	}
	return ""
}

func (c *Client) ServerVersion(ctx context.Context) (map[string]any, error) {
	version, err := c.Discovery.ServerVersion()
	if err != nil {
		return nil, err
	}
	return toMap(version)
}

func (c *Client) Discover(ctx context.Context) ([]APIResource, []error) {
	_ = ctx
	lists, err := c.Discovery.ServerPreferredResources()
	var errs []error
	if err != nil {
		errs = append(errs, err)
	}

	var resources []APIResource
	for _, list := range lists {
		if list == nil {
			continue
		}
		gv, parseErr := schema.ParseGroupVersion(list.GroupVersion)
		if parseErr != nil {
			errs = append(errs, parseErr)
			continue
		}
		for _, res := range list.APIResources {
			if strings.Contains(res.Name, "/") {
				continue
			}
			resources = append(resources, APIResource{
				GroupVersion: list.GroupVersion,
				Group:        gv.Group,
				Version:      gv.Version,
				Name:         res.Name,
				Kind:         res.Kind,
				Namespaced:   res.Namespaced,
				Verbs:        res.Verbs,
			})
		}
	}
	return resources, errs
}

func (c *Client) SelfSubjectRulesReview(ctx context.Context, namespace string) (RulesReviewStatus, error) {
	review, err := c.Typed.AuthorizationV1().SelfSubjectRulesReviews().Create(ctx, &authv1.SelfSubjectRulesReview{
		Spec: authv1.SelfSubjectRulesReviewSpec{
			Namespace: namespace,
		},
	}, metav1.CreateOptions{})
	if err != nil {
		return RulesReviewStatus{}, err
	}

	statusData, _ := json.Marshal(review.Status)
	var status RulesReviewStatus
	_ = json.Unmarshal(statusData, &status)
	return status, nil
}

func (c *Client) SelfSubjectAccessReview(ctx context.Context, attrs ResourceAttributes) (AccessReviewResult, error) {
	review, err := c.Typed.AuthorizationV1().SelfSubjectAccessReviews().Create(ctx, &authv1.SelfSubjectAccessReview{
		Spec: authv1.SelfSubjectAccessReviewSpec{
			ResourceAttributes: &authv1.ResourceAttributes{
				Namespace:   attrs.Namespace,
				Verb:        attrs.Verb,
				Group:       attrs.Group,
				Version:     attrs.Version,
				Resource:    attrs.Resource,
				Subresource: attrs.Subresource,
				Name:        attrs.Name,
			},
		},
	}, metav1.CreateOptions{})
	if err != nil {
		return AccessReviewResult{}, err
	}
	return AccessReviewResult{
		ResourceAttributes: attrs,
		Allowed:            review.Status.Allowed,
		Denied:             review.Status.Denied,
		Reason:             review.Status.Reason,
		EvaluationError:    review.Status.EvaluationError,
	}, nil
}

func (c *Client) ListResource(ctx context.Context, resource APIResource, namespace string, limit int) (map[string]any, error) {
	gvr := groupVersionResource(resource)
	opts := metav1.ListOptions{}
	if limit > 0 {
		opts.Limit = int64(limit)
	}

	var list *unstructured.UnstructuredList
	var err error
	if resource.Namespaced {
		list, err = c.Dynamic.Resource(gvr).Namespace(namespace).List(ctx, opts)
	} else {
		list, err = c.Dynamic.Resource(gvr).List(ctx, opts)
	}
	if err != nil {
		return nil, err
	}
	return unstructuredToMap(list)
}

func (c *Client) GetResource(ctx context.Context, resource APIResource, namespace, name string) (map[string]any, error) {
	gvr := groupVersionResource(resource)
	var obj *unstructured.Unstructured
	var err error
	if resource.Namespaced {
		obj, err = c.Dynamic.Resource(gvr).Namespace(namespace).Get(ctx, name, metav1.GetOptions{})
	} else {
		obj, err = c.Dynamic.Resource(gvr).Get(ctx, name, metav1.GetOptions{})
	}
	if err != nil {
		return nil, err
	}
	return unstructuredToMap(obj)
}

func (c *Client) GetPod(ctx context.Context, namespace, name string) (map[string]any, error) {
	pod, err := c.Typed.CoreV1().Pods(namespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	return toMap(pod)
}

func (c *Client) DryRunPod(ctx context.Context, namespace string, pod map[string]any) (map[string]any, error) {
	obj := &unstructured.Unstructured{Object: pod}
	created, err := c.Dynamic.Resource(schema.GroupVersionResource{
		Group:    "",
		Version:  "v1",
		Resource: "pods",
	}).Namespace(namespace).Create(ctx, obj, metav1.CreateOptions{DryRun: []string{metav1.DryRunAll}})
	if err != nil {
		return nil, err
	}
	return unstructuredToMap(created)
}

func CanList(rules []ResourceRule, resource APIResource) bool {
	for _, rule := range rules {
		if !containsVerb(rule.Verbs, "list") {
			continue
		}
		if !containsResource(rule.APIGroups, resource.Group) {
			continue
		}
		if containsResource(rule.Resources, resource.Name) || containsResource(rule.Resources, "*") {
			return true
		}
	}
	return false
}

func HasVerb(verbs []string, verb string) bool {
	return containsVerb(verbs, verb)
}

func groupVersionResource(resource APIResource) schema.GroupVersionResource {
	return schema.GroupVersionResource{
		Group:    resource.Group,
		Version:  resource.Version,
		Resource: resource.Name,
	}
}

func containsVerb(values []string, want string) bool {
	for _, value := range values {
		if value == "*" || value == want {
			return true
		}
	}
	return false
}

func containsResource(values []string, want string) bool {
	for _, value := range values {
		if value == "*" || value == want {
			return true
		}
	}
	return false
}

func toMap(value any) (map[string]any, error) {
	data, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	var out map[string]any
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func unstructuredToMap(value runtime.Object) (map[string]any, error) {
	switch typed := value.(type) {
	case *unstructured.Unstructured:
		return typed.UnstructuredContent(), nil
	case *unstructured.UnstructuredList:
		return typed.UnstructuredContent(), nil
	}
	out, err := runtime.DefaultUnstructuredConverter.ToUnstructured(value)
	if err == nil {
		return out, nil
	}
	data, marshalErr := json.Marshal(value)
	if marshalErr != nil {
		return nil, errors.Join(err, marshalErr)
	}
	var fallback map[string]any
	if unmarshalErr := json.Unmarshal(data, &fallback); unmarshalErr != nil {
		return nil, errors.Join(err, unmarshalErr)
	}
	return fallback, nil
}

func rootPath(root, path string) string {
	if root == "" || root == "/" {
		return path
	}
	return filepath.Join(root, strings.TrimPrefix(path, "/"))
}
