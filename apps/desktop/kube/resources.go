package kube

import (
	"context"
	"fmt"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type Namespace struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Age    string `json:"age"`
}

type PodInfo struct {
	Namespace   string   `json:"namespace"`
	Name        string   `json:"name"`
	Status      string   `json:"status"`
	Ready       string   `json:"ready"`
	Restarts    int32    `json:"restarts"`
	Age         string   `json:"age"`
	Node        string   `json:"node"`
	PodIP       string   `json:"podIP"`
	Containers  []string `json:"containers"`
	HostNetwork bool     `json:"hostNetwork"`
	HostPID     bool     `json:"hostPID"`
	Privileged  bool     `json:"privileged"`
}

type NodeInfo struct {
	Name       string `json:"name"`
	Status     string `json:"status"`
	Roles      string `json:"roles"`
	Age        string `json:"age"`
	Version    string `json:"version"`
	InternalIP string `json:"internalIP"`
	OS         string `json:"os"`
	Kernel     string `json:"kernel"`
	Runtime    string `json:"runtime"`
}

func (c *Client) ListNamespaces(ctx context.Context) ([]Namespace, error) {
	list, err := c.Clientset.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
	if err == nil {
		out := make([]Namespace, 0, len(list.Items))
		for i := range list.Items {
			n := &list.Items[i]
			out = append(out, Namespace{Name: n.Name, Status: string(n.Status.Phase), Age: ageOf(n.CreationTimestamp)})
		}
		return out, nil
	}
	if !k8serrors.IsForbidden(err) {
		return nil, err
	}
	ns := c.Namespace
	if ns == "" {
		ns = "default"
	}
	if n, getErr := c.Clientset.CoreV1().Namespaces().Get(ctx, ns, metav1.GetOptions{}); getErr == nil {
		return []Namespace{{Name: n.Name, Status: string(n.Status.Phase), Age: ageOf(n.CreationTimestamp)}}, nil
	}
	return []Namespace{{Name: ns, Status: "Restricted", Age: "-"}}, nil
}

func (c *Client) ListPods(ctx context.Context, namespace string) ([]PodInfo, error) {
	list, err := c.Clientset.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		if namespace == "" && k8serrors.IsForbidden(err) {
			fallback := c.Namespace
			if fallback == "" {
				fallback = "default"
			}
			list, err = c.Clientset.CoreV1().Pods(fallback).List(ctx, metav1.ListOptions{})
			if err != nil {
				return nil, fmt.Errorf("list pods in %q (after cluster-scope forbidden): %w", fallback, err)
			}
		} else {
			return nil, err
		}
	}
	out := make([]PodInfo, 0, len(list.Items))
	for i := range list.Items {
		out = append(out, podInfoFromPod(&list.Items[i]))
	}
	return out, nil
}

func podInfoFromPod(p *corev1.Pod) PodInfo {
	ready, total := 0, len(p.Spec.Containers)
	var restarts int32
	for _, cs := range p.Status.ContainerStatuses {
		if cs.Ready {
			ready++
		}
		restarts += cs.RestartCount
	}
	containers := make([]string, 0, total)
	privileged := false
	for i := range p.Spec.Containers {
		c := &p.Spec.Containers[i]
		containers = append(containers, c.Name)
		if c.SecurityContext != nil && c.SecurityContext.Privileged != nil && *c.SecurityContext.Privileged {
			privileged = true
		}
	}
	status := string(p.Status.Phase)
	if p.DeletionTimestamp != nil {
		status = "Terminating"
	}
	for _, cs := range p.Status.ContainerStatuses {
		if cs.State.Waiting != nil && cs.State.Waiting.Reason != "" {
			status = cs.State.Waiting.Reason
			break
		}
	}
	return PodInfo{
		Namespace:   p.Namespace,
		Name:        p.Name,
		Status:      status,
		Ready:       fmt.Sprintf("%d/%d", ready, total),
		Restarts:    restarts,
		Age:         ageOf(p.CreationTimestamp),
		Node:        p.Spec.NodeName,
		PodIP:       p.Status.PodIP,
		Containers:  containers,
		HostNetwork: p.Spec.HostNetwork,
		HostPID:     p.Spec.HostPID,
		Privileged:  privileged,
	}
}

func (c *Client) ListNodes(ctx context.Context) ([]NodeInfo, error) {
	list, err := c.Clientset.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		if k8serrors.IsForbidden(err) {
			return []NodeInfo{}, nil
		}
		return nil, err
	}
	out := make([]NodeInfo, 0, len(list.Items))
	for i := range list.Items {
		n := &list.Items[i]
		status := "NotReady"
		for _, cond := range n.Status.Conditions {
			if cond.Type == corev1.NodeReady && cond.Status == corev1.ConditionTrue {
				status = "Ready"
			}
		}
		var roles []string
		for k := range n.Labels {
			if strings.HasPrefix(k, "node-role.kubernetes.io/") {
				roles = append(roles, strings.TrimPrefix(k, "node-role.kubernetes.io/"))
			}
		}
		roleStr := strings.Join(roles, ",")
		if roleStr == "" {
			roleStr = "<none>"
		}
		ip := ""
		for _, a := range n.Status.Addresses {
			if a.Type == corev1.NodeInternalIP {
				ip = a.Address
				break
			}
		}
		out = append(out, NodeInfo{
			Name:       n.Name,
			Status:     status,
			Roles:      roleStr,
			Age:        ageOf(n.CreationTimestamp),
			Version:    n.Status.NodeInfo.KubeletVersion,
			InternalIP: ip,
			OS:         n.Status.NodeInfo.OSImage,
			Kernel:     n.Status.NodeInfo.KernelVersion,
			Runtime:    n.Status.NodeInfo.ContainerRuntimeVersion,
		})
	}
	return out, nil
}

type PodDetail struct {
	Pod            PodInfo           `json:"pod"`
	Labels         map[string]string `json:"labels"`
	Annotations    map[string]string `json:"annotations"`
	Conditions     []string          `json:"conditions"`
	Events         []string          `json:"events"`
	ServiceAccount string            `json:"serviceAccount"`
	Volumes        []string          `json:"volumes"`
}

func (c *Client) DescribePod(ctx context.Context, ns, name string) (*PodDetail, error) {
	p, err := c.Clientset.CoreV1().Pods(ns).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	d := &PodDetail{
		Pod:            podInfoFromPod(p),
		Labels:         p.Labels,
		Annotations:    p.Annotations,
		ServiceAccount: p.Spec.ServiceAccountName,
	}
	for _, cond := range p.Status.Conditions {
		d.Conditions = append(d.Conditions, fmt.Sprintf("%s=%s %s", cond.Type, cond.Status, cond.Message))
	}
	for _, v := range p.Spec.Volumes {
		d.Volumes = append(d.Volumes, v.Name)
	}
	evs, err := c.Clientset.CoreV1().Events(ns).List(ctx, metav1.ListOptions{
		FieldSelector: fmt.Sprintf("involvedObject.name=%s,involvedObject.kind=Pod", name),
	})
	if err == nil {
		for _, e := range evs.Items {
			d.Events = append(d.Events, fmt.Sprintf("[%s] %s: %s", e.Type, e.Reason, e.Message))
		}
	}
	return d, nil
}

func ageOf(ts metav1.Time) string {
	d := time.Since(ts.Time)
	switch {
	case d.Hours() >= 24*365:
		return fmt.Sprintf("%dy", int(d.Hours()/24/365))
	case d.Hours() >= 24:
		return fmt.Sprintf("%dd", int(d.Hours()/24))
	case d.Hours() >= 1:
		return fmt.Sprintf("%dh", int(d.Hours()))
	case d.Minutes() >= 1:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	default:
		if d < 0 {
			return "0s"
		}
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
}
