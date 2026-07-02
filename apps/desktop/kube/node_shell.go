package kube

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	authv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
)

const (
	defaultNodeShellImage = "docker.io/nicolaka/netshoot:v0.13"
	nodeShellImageEnv     = "KUBETRAIL_NODE_SHELL_IMAGE"
	nodeShellNamespace    = "default"
	nodeShellPrefix       = "kubetrail-node-"
)

type NodeShellAccess struct {
	Namespace        string `json:"namespace"`
	HelperPod        string `json:"helperPod"`
	Image            string `json:"image"`
	HelperRunning    bool   `json:"helperRunning"`
	RequiresCreate   bool   `json:"requiresCreate"`
	GetPodAllowed    bool   `json:"getPodAllowed"`
	CreatePodAllowed bool   `json:"createPodAllowed"`
	ExecAllowed      bool   `json:"execAllowed"`
	GetPodReason     string `json:"getPodReason,omitempty"`
	CreatePodReason  string `json:"createPodReason,omitempty"`
	ExecReason       string `json:"execReason,omitempty"`
}

func nodeShellImage() string {
	if image := strings.TrimSpace(os.Getenv(nodeShellImageEnv)); image != "" {
		return image
	}
	return defaultNodeShellImage
}

func nodeShellPodName(nodeName string) string {
	name := nodeShellPrefix + nodeName
	if len(name) > 63 {
		name = name[:63]
	}
	return name
}

func (c *Client) CheckNodeShellAccess(ctx context.Context, nodeName string) (*NodeShellAccess, error) {
	podName := nodeShellPodName(nodeName)
	res := &NodeShellAccess{
		Namespace:      nodeShellNamespace,
		HelperPod:      podName,
		Image:          nodeShellImage(),
		RequiresCreate: true,
	}

	var err error
	res.GetPodAllowed, res.GetPodReason, err = c.selfSubjectResourceAllowed(ctx, nodeShellNamespace, "get", "pods", "")
	if err != nil {
		return nil, fmt.Errorf("check get pods access: %w", err)
	}
	res.CreatePodAllowed, res.CreatePodReason, err = c.selfSubjectResourceAllowed(ctx, nodeShellNamespace, "create", "pods", "")
	if err != nil {
		return nil, fmt.Errorf("check create pods access: %w", err)
	}
	res.ExecAllowed, res.ExecReason, err = c.selfSubjectResourceAllowed(ctx, nodeShellNamespace, "create", "pods", "exec")
	if err != nil {
		return nil, fmt.Errorf("check create pods/exec access: %w", err)
	}

	if !res.GetPodAllowed {
		return res, nil
	}

	existing, getErr := c.Clientset.CoreV1().Pods(nodeShellNamespace).Get(ctx, podName, metav1.GetOptions{})
	if getErr == nil {
		res.HelperRunning = existing.Status.Phase == corev1.PodRunning
		res.RequiresCreate = existing.Status.Phase == corev1.PodFailed || existing.Status.Phase == corev1.PodSucceeded
		return res, nil
	}
	if k8serrors.IsNotFound(getErr) {
		res.RequiresCreate = true
		return res, nil
	}
	return nil, fmt.Errorf("get node shell pod: %w", getErr)
}

func (c *Client) EnsureNodeShellPod(ctx context.Context, nodeName string) (ns, pod, container string, err error) {
	podName := nodeShellPodName(nodeName)
	containerName := "shell"
	zero := int64(0)
	needCreate := false

	// Check if already running.
	existing, getErr := c.Clientset.CoreV1().Pods(nodeShellNamespace).Get(ctx, podName, metav1.GetOptions{})
	if getErr == nil && existing.Status.Phase == corev1.PodRunning {
		return nodeShellNamespace, podName, containerName, nil
	}
	if getErr == nil && (existing.Status.Phase == corev1.PodFailed || existing.Status.Phase == corev1.PodSucceeded) {
		if err := c.Clientset.CoreV1().Pods(nodeShellNamespace).Delete(ctx, podName, metav1.DeleteOptions{GracePeriodSeconds: &zero}); err != nil && !k8serrors.IsNotFound(err) {
			return "", "", "", fmt.Errorf("delete stale node shell pod: %w", err)
		}
		if err := wait.PollUntilContextTimeout(ctx, 500*time.Millisecond, 10*time.Second, true, func(ctx context.Context) (bool, error) {
			_, err := c.Clientset.CoreV1().Pods(nodeShellNamespace).Get(ctx, podName, metav1.GetOptions{})
			if k8serrors.IsNotFound(err) {
				return true, nil
			}
			return false, err
		}); err != nil {
			return "", "", "", fmt.Errorf("wait stale node shell pod deletion: %w", err)
		}
		needCreate = true
	}
	if getErr != nil && !k8serrors.IsNotFound(getErr) {
		return "", "", "", fmt.Errorf("get node shell pod: %w", getErr)
	}
	if k8serrors.IsNotFound(getErr) {
		needCreate = true
	}

	if needCreate {
		privileged := true
		hostPID := true
		image := nodeShellImage()
		spec := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      podName,
				Namespace: nodeShellNamespace,
				Labels: map[string]string{
					"app.kubernetes.io/managed-by": "kubetrail",
					"kubetrail/purpose":            "node-shell",
					"kubetrail/node":               nodeName,
				},
			},
			Spec: corev1.PodSpec{
				NodeName:      nodeName,
				HostNetwork:   true,
				HostPID:       hostPID,
				RestartPolicy: corev1.RestartPolicyNever,
				Containers: []corev1.Container{
					{
						Name:            containerName,
						Image:           image,
						Command:         []string{"sh", "-c", "sleep 7200"},
						Stdin:           true,
						ImagePullPolicy: corev1.PullIfNotPresent,
						SecurityContext: &corev1.SecurityContext{
							Privileged: &privileged,
							RunAsUser:  &zero,
						},
						VolumeMounts: []corev1.VolumeMount{
							{Name: "host-root", MountPath: "/host", ReadOnly: false},
						},
					},
				},
				Volumes: []corev1.Volume{
					{
						Name: "host-root",
						VolumeSource: corev1.VolumeSource{
							HostPath: &corev1.HostPathVolumeSource{Path: "/"},
						},
					},
				},
				TerminationGracePeriodSeconds: &zero,
			},
		}
		if _, err := c.Clientset.CoreV1().Pods(nodeShellNamespace).Create(ctx, spec, metav1.CreateOptions{}); err != nil {
			return "", "", "", fmt.Errorf("create node shell pod: %w", err)
		}
	}

	// Wait for Running.
	if err := wait.PollUntilContextTimeout(ctx, 1*time.Second, 90*time.Second, true, func(ctx context.Context) (bool, error) {
		p, err := c.Clientset.CoreV1().Pods(nodeShellNamespace).Get(ctx, podName, metav1.GetOptions{})
		if err != nil {
			return false, nil
		}
		if p.Status.Phase == corev1.PodRunning {
			return true, nil
		}
		if p.Status.Phase == corev1.PodFailed || p.Status.Phase == corev1.PodSucceeded {
			return false, fmt.Errorf("node shell pod terminated: %s", p.Status.Phase)
		}
		return false, nil
	}); err != nil {
		return "", "", "", fmt.Errorf("wait node shell pod: %w", err)
	}

	return nodeShellNamespace, podName, containerName, nil
}

func (c *Client) selfSubjectResourceAllowed(ctx context.Context, namespace, verb, resource, subresource string) (bool, string, error) {
	review, err := c.Clientset.AuthorizationV1().SelfSubjectAccessReviews().Create(ctx, &authv1.SelfSubjectAccessReview{
		Spec: authv1.SelfSubjectAccessReviewSpec{
			ResourceAttributes: &authv1.ResourceAttributes{
				Namespace:   namespace,
				Verb:        verb,
				Group:       "",
				Version:     "v1",
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

func (c *Client) DeleteNodeShellPod(ctx context.Context, nodeName string) error {
	podName := nodeShellPodName(nodeName)
	err := c.Clientset.CoreV1().Pods(nodeShellNamespace).Delete(ctx, podName, metav1.DeleteOptions{})
	if k8serrors.IsNotFound(err) {
		return nil
	}
	return err
}

func (c *Client) ListNodeFiles(ctx context.Context, nodeName, dir string) ([]FileEntry, error) {
	ns, pod, container, err := c.EnsureNodeShellPod(ctx, nodeName)
	if err != nil {
		return nil, err
	}
	// Files on the node are under /host in the debug pod.
	hostDir := "/host" + dir
	return c.ListPodFiles(ctx, ns, pod, container, hostDir)
}

func (c *Client) ReadNodeFile(ctx context.Context, nodeName, remotePath string, maxBytes int64) ([]byte, error) {
	ns, pod, container, err := c.EnsureNodeShellPod(ctx, nodeName)
	if err != nil {
		return nil, err
	}
	return c.ReadPodFile(ctx, ns, pod, container, "/host"+remotePath, maxBytes)
}

func (c *Client) DownloadNodeFile(ctx context.Context, nodeName, remotePath, localPath string) error {
	ns, pod, container, err := c.EnsureNodeShellPod(ctx, nodeName)
	if err != nil {
		return err
	}
	return c.DownloadPodFile(ctx, ns, pod, container, "/host"+remotePath, localPath)
}

func (c *Client) UploadNodeFile(ctx context.Context, nodeName, localPath, remoteDir string) error {
	ns, pod, container, err := c.EnsureNodeShellPod(ctx, nodeName)
	if err != nil {
		return err
	}
	return c.UploadPodFile(ctx, ns, pod, container, localPath, "/host"+remoteDir)
}

func (c *Client) DeleteNodeFile(ctx context.Context, nodeName, target string) error {
	ns, pod, container, err := c.EnsureNodeShellPod(ctx, nodeName)
	if err != nil {
		return err
	}
	return c.DeletePodFile(ctx, ns, pod, container, "/host"+target)
}
