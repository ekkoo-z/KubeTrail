package collectors

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/ekkoo-z/KubeTrail/internal/kube"
	"github.com/ekkoo-z/KubeTrail/internal/model"
)

const (
	saTokenAuditCollectorID = "sa_token_audit"
	saTokenAuditPageLimit   = int64(500)
)

type serviceAccountTokenSecret struct {
	Namespace      string
	Name           string
	UID            string
	CreatedAt      string
	ServiceAccount string
	Token          string
}

func CollectServiceAccountTokenAudit(ctx context.Context, cctx *Context, version string) model.SATokenAuditDocument {
	start := time.Now()
	hostname, _ := os.Hostname()
	doc := model.SATokenAuditDocument{
		SchemaVersion: model.SATokenAuditSchemaVersion,
		Run: model.RunInfo{
			ID:          start.UTC().Format("20060102T150405.000000000Z"),
			StartedAt:   start.UTC().Format(time.RFC3339Nano),
			Hostname:    hostname,
			ToolVersion: version,
			Args:        cctx.Options.Args,
		},
		Mode: cctx.Options.Mode,
		Target: model.TargetInfo{
			InKubernetes: cctx.InKubernetes(),
			Namespace:    cctx.Namespace(),
			PodName:      hostname,
			APIServer:    cctx.APIServer(),
		},
		Source: model.SATokenAuditSource{
			ResourceTypes: []string{string(corev1.SecretTypeServiceAccountToken)},
			Note:          "legacy ServiceAccount token Secrets visible to the caller; projected/bound tokens are not created or requested",
		},
	}
	defer func() {
		finished := time.Now()
		doc.Run.FinishedAt = finished.UTC().Format(time.RFC3339Nano)
		doc.Run.DurationMs = finished.Sub(start).Milliseconds()
	}()

	client, err := cctx.KubeClient()
	if err != nil {
		doc.Errors = append(doc.Errors, saTokenAuditErr("kubernetes client", err))
		return doc
	}

	namespace := client.Namespace
	if namespace == "" {
		namespace = cctx.Namespace()
	}
	namespaces, errs := serviceAccountTokenAuditNamespaces(ctx, client, namespace)
	doc.Errors = append(doc.Errors, errs...)
	doc.Source.Namespaces = namespaces
	if len(namespaces) == 0 {
		if namespace == "" {
			doc.Errors = append(doc.Errors, model.ErrorEntry{Collector: saTokenAuditCollectorID, Source: "namespace", Message: "namespace not available"})
		}
		return doc
	}

	for _, ns := range namespaces {
		secrets, secretErrs := serviceAccountTokenSecrets(ctx, client, ns)
		doc.Errors = append(doc.Errors, secretErrs...)
		for _, secret := range secrets {
			doc.Items = append(doc.Items, auditServiceAccountToken(ctx, cctx, client, secret))
		}
	}
	sort.Slice(doc.Items, func(i, j int) bool {
		if doc.Items[i].Namespace == doc.Items[j].Namespace {
			return doc.Items[i].SecretName < doc.Items[j].SecretName
		}
		return doc.Items[i].Namespace < doc.Items[j].Namespace
	})
	return doc
}

func serviceAccountTokenAuditNamespaces(ctx context.Context, client *kube.Client, fallback string) ([]string, []model.ErrorEntry) {
	namespaces, err := listNamespaceNames(ctx, client)
	if err == nil {
		if len(namespaces) == 0 && fallback != "" {
			return []string{fallback}, nil
		}
		return namespaces, nil
	}
	if fallback == "" {
		return nil, []model.ErrorEntry{saTokenAuditErr("namespaces", err)}
	}
	return []string{fallback}, []model.ErrorEntry{saTokenAuditErr("namespaces", err)}
}

func listNamespaceNames(ctx context.Context, client *kube.Client) ([]string, error) {
	var out []string
	opts := metav1.ListOptions{Limit: saTokenAuditPageLimit}
	for {
		list, err := client.Typed.CoreV1().Namespaces().List(ctx, opts)
		if err != nil {
			return nil, err
		}
		for _, namespace := range list.Items {
			if namespace.Name != "" {
				out = append(out, namespace.Name)
			}
		}
		if list.Continue == "" {
			break
		}
		opts.Continue = list.Continue
	}
	sort.Strings(out)
	return uniqueStrings(out), nil
}

func serviceAccountTokenSecrets(ctx context.Context, client *kube.Client, namespace string) ([]serviceAccountTokenSecret, []model.ErrorEntry) {
	if namespace == "" {
		return nil, []model.ErrorEntry{{Collector: saTokenAuditCollectorID, Source: "secrets", Message: "namespace not available"}}
	}
	opts := metav1.ListOptions{Limit: saTokenAuditPageLimit}
	var out []serviceAccountTokenSecret
	var errs []model.ErrorEntry
	for {
		list, err := client.Typed.CoreV1().Secrets(namespace).List(ctx, opts)
		if err != nil {
			return out, append(errs, saTokenAuditErr("secrets namespace="+namespace, err))
		}
		for _, secret := range list.Items {
			if secret.Type != corev1.SecretTypeServiceAccountToken {
				continue
			}
			token := string(secret.Data[corev1.ServiceAccountTokenKey])
			if token == "" {
				errs = append(errs, model.ErrorEntry{
					Collector: saTokenAuditCollectorID,
					Source:    "secrets/" + secret.Name,
					Message:   "service account token Secret has no token data",
				})
				continue
			}
			out = append(out, serviceAccountTokenSecret{
				Namespace:      secret.Namespace,
				Name:           secret.Name,
				UID:            string(secret.UID),
				CreatedAt:      formatMetaTime(secret.CreationTimestamp),
				ServiceAccount: secret.Annotations[corev1.ServiceAccountNameKey],
				Token:          token,
			})
		}
		if list.Continue == "" {
			break
		}
		opts.Continue = list.Continue
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Namespace == out[j].Namespace {
			return out[i].Name < out[j].Name
		}
		return out[i].Namespace < out[j].Namespace
	})
	return out, errs
}

func auditServiceAccountToken(ctx context.Context, cctx *Context, baseClient *kube.Client, secret serviceAccountTokenSecret) model.SATokenAuditItem {
	sum := sha256.Sum256([]byte(secret.Token))
	claims, jwtErr := jwtClaims(secret.Token)
	serviceAccount := secret.ServiceAccount
	if serviceAccount == "" {
		serviceAccount = stringClaim(claims, "kubernetes.io/serviceaccount/service-account.name")
	}
	item := model.SATokenAuditItem{
		Namespace:       secret.Namespace,
		ServiceAccount:  serviceAccount,
		SecretName:      secret.Name,
		SecretUID:       secret.UID,
		SecretCreatedAt: secret.CreatedAt,
		Token:           secret.Token,
		TokenSHA256:     hex.EncodeToString(sum[:]),
		TokenBytes:      len(secret.Token),
		JWTClaims:       claims,
		Permissions: model.SATokenAuditPermission{
			Namespace: secret.Namespace,
		},
	}
	if jwtErr != nil {
		item.JWTError = jwtErr.Error()
	}

	tokenClient, err := kube.NewClientWithBearerToken(baseClient, secret.Token, secret.Namespace, kube.Options{
		QPS:   cctx.Options.KubeQPS,
		Burst: cctx.Options.KubeBurst,
	})
	if err != nil {
		item.Errors = append(item.Errors, saTokenAuditErr("token client "+secret.Namespace+"/"+secret.Name, err))
		return item
	}

	permissions, errs := auditTokenPermissions(ctx, tokenClient, secret.Namespace, cctx.Options.RBACMode)
	item.Permissions = permissions
	item.Errors = append(item.Errors, errs...)
	return item
}

func auditTokenPermissions(ctx context.Context, client *kube.Client, namespace string, mode model.RBACMode) (model.SATokenAuditPermission, []model.ErrorEntry) {
	rbacMode := normalizeRBACMode(mode)
	permissions := model.SATokenAuditPermission{
		Namespace: namespace,
		RBACMode:  rbacMode,
	}
	var errs []model.ErrorEntry

	status, err := client.SelfSubjectRulesReview(ctx, namespace)
	if err != nil {
		errs = append(errs, saTokenAuditErr("selfsubjectrulesreviews namespace="+namespace, err))
	} else {
		permissions.SelfSubjectRules = status
	}

	matrix, matrixErrs := accessReviewMatrix(ctx, client, namespace, rbacMode)
	permissions.HighValueAccess = matrix
	for _, err := range matrixErrs {
		errs = append(errs, saTokenAuditErr("selfsubjectaccessreviews namespace="+namespace, err))
	}

	if err != nil {
		return permissions, errs
	}
	var resources []kube.APIResource
	if rbacMode == model.RBACModeFull {
		var discoveryErrs []error
		resources, discoveryErrs = client.Discover(ctx)
		permissions.DiscoveryResources = len(resources)
		for _, err := range discoveryErrs {
			errs = append(errs, saTokenAuditErr("discovery expanded_wildcards namespace="+namespace, err))
		}
	}
	expandedResult := expandedWildcardAccessMatrixForMode(ctx, client, namespace, status.ResourceRules, resources, rbacMode)
	permissions.ExpandedWildcards = expandedResult.Checks
	for _, err := range expandedResult.Errs {
		errs = append(errs, saTokenAuditErr("selfsubjectaccessreviews expanded_wildcards namespace="+namespace, err))
	}
	return permissions, errs
}

func jwtClaims(token string) (map[string]any, error) {
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return nil, fmt.Errorf("token is not a JWT")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, err
	}
	return claims, nil
}

func stringClaim(claims map[string]any, key string) string {
	if claims == nil {
		return ""
	}
	value, _ := claims[key].(string)
	return value
}

func formatMetaTime(value metav1.Time) string {
	if value.IsZero() {
		return ""
	}
	return value.UTC().Format(time.RFC3339Nano)
}

func saTokenAuditErr(source string, err error) model.ErrorEntry {
	return model.ErrorEntry{Collector: saTokenAuditCollectorID, Source: source, Message: err.Error()}
}
