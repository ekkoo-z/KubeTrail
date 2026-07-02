package kube

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"k8s.io/client-go/discovery"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

type AuthType string

const (
	AuthKubeconfig AuthType = "kubeconfig"
	AuthToken      AuthType = "token"
)

type ConnectOptions struct {
	Type            AuthType
	KubeconfigBytes []byte
	KubeconfigPath  string
	APIServer       string
	Token           string
	CAData          []byte
	Insecure        bool
	Namespace       string
	APIPathPrefix   string
}

type Client struct {
	Config    *rest.Config
	Clientset *kubernetes.Clientset
	Discovery discovery.DiscoveryInterface
	Namespace string
}

func New(opts ConnectOptions) (*Client, error) {
	var (
		cfg *rest.Config
		ns  string
		err error
	)
	switch opts.Type {
	case AuthKubeconfig:
		cfg, ns, err = configFromKubeconfig(opts)
	case AuthToken:
		cfg, ns, err = configFromToken(opts)
	default:
		return nil, fmt.Errorf("unknown auth type: %s", opts.Type)
	}
	if err != nil {
		return nil, err
	}
	if opts.Namespace != "" {
		ns = opts.Namespace
	}
	if ns == "" {
		ns = "default"
	}
	if p := strings.TrimSpace(opts.APIPathPrefix); p != "" {
		cfg.Host = strings.TrimRight(cfg.Host, "/") + "/" + strings.TrimLeft(p, "/")
	}
	applyDefaults(cfg)
	cs, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("build clientset: %w", err)
	}
	return &Client{Config: cfg, Clientset: cs, Discovery: cs.Discovery(), Namespace: ns}, nil
}

func configFromKubeconfig(opts ConnectOptions) (*rest.Config, string, error) {
	var raw []byte
	if len(opts.KubeconfigBytes) > 0 {
		raw = opts.KubeconfigBytes
	} else if opts.KubeconfigPath != "" {
		b, err := os.ReadFile(opts.KubeconfigPath)
		if err != nil {
			return nil, "", fmt.Errorf("read kubeconfig: %w", err)
		}
		raw = b
	} else {
		return nil, "", fmt.Errorf("kubeconfig bytes or path required")
	}
	clientCfg, err := clientcmd.NewClientConfigFromBytes(raw)
	if err != nil {
		return nil, "", fmt.Errorf("parse kubeconfig: %w", err)
	}
	restCfg, err := clientCfg.ClientConfig()
	if err != nil {
		return nil, "", fmt.Errorf("rest config: %w", err)
	}
	ns, _, _ := clientCfg.Namespace()
	return restCfg, ns, nil
}

func configFromToken(opts ConnectOptions) (*rest.Config, string, error) {
	if opts.APIServer == "" || opts.Token == "" {
		return nil, "", fmt.Errorf("apiServer and token are required for token auth")
	}
	cfg := &rest.Config{
		Host:        opts.APIServer,
		BearerToken: opts.Token,
		TLSClientConfig: rest.TLSClientConfig{
			CAData:   opts.CAData,
			Insecure: opts.Insecure,
		},
	}
	ns := opts.Namespace
	if ns == "" {
		ns = namespaceFromSAToken(opts.Token)
	}
	return cfg, ns, nil
}

func namespaceFromSAToken(token string) string {
	parts := strings.Split(strings.TrimSpace(token), ".")
	if len(parts) < 2 {
		return ""
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		padded := parts[1] + strings.Repeat("=", (4-len(parts[1])%4)%4)
		payload, err = base64.StdEncoding.DecodeString(padded)
		if err != nil {
			return ""
		}
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		return ""
	}
	if k8s, ok := claims["kubernetes.io"].(map[string]any); ok {
		if ns, ok := k8s["namespace"].(string); ok && ns != "" {
			return ns
		}
	}
	if ns, ok := claims["kubernetes.io/serviceaccount/namespace"].(string); ok && ns != "" {
		return ns
	}
	return ""
}

func applyDefaults(cfg *rest.Config) {
	if cfg.QPS == 0 {
		cfg.QPS = 50
	}
	if cfg.Burst == 0 {
		cfg.Burst = 100
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 15 * time.Second
	}
	cfg.UserAgent = "kubetrail-desktop/0.1"
}

func (c *Client) ServerVersion(_ context.Context) (string, error) {
	v, err := c.Discovery.ServerVersion()
	if err != nil {
		return "", err
	}
	return v.GitVersion, nil
}
