---
name: kubelet-runtime-etcd-bypass
description: Analyze kubelet, node subresource, etcd, container runtime socket, and static pod paths that bypass normal Kubernetes API admission and audit controls.
---

# Kubelet Runtime Etcd Bypass

Use this skill when facts mention kubelet API, node subresources, `nodes/proxy`, etcd, container runtime sockets, Docker/containerd/CRI-O, kubelet certificates, kubelet config, or static pod manifests.

Scope boundary:

- Owns component-level bypass paths around API server admission and audit.
- Use `k8s-rbac-analysis` for the permission grant that enables `nodes/proxy` or node subresource access.
- Use `pod-escape-surface` for socket or host paths mounted inside the current container.
- Use `observability-defense-evasion` for logging impact after identifying the bypass.

High-value evidence:

- `nodes/proxy`, `nodes/exec`, `nodes/log`, `nodes/stats`, or broad `nodes/*` RBAC allows.
- Direct kubelet API reachability, anonymous access, webhook auth disabled, read-only port, or command/log endpoint evidence.
- Container runtime sockets: `/var/run/docker.sock`, `/run/containerd/containerd.sock`, CRI-O sockets, parent directory mounts.
- Etcd endpoint, etcd client cert/key paths, exposed port 2379/2380, API server etcd client material.
- Static pod manifest directories or URL sources, writable kubelet config or pod manifest paths.
- Node credential material such as kubelet client certificate, bootstrap kubeconfig, or cloud node identity hints.

Finding rules:

- Confirmed high: direct kubelet exec/log access, runtime socket write access, etcd client material, or writable static pod manifest path.
- Medium: `nodes/proxy` allow, kubelet API reachable, runtime socket present but writeability unknown, etcd endpoint reachable without client proof.
- Low: component path or config hint only.
- Unknown: probing disabled in safe mode or API/network collection denied.

Useful templates:

- `nodes-proxy-verify`
- `kubelet-api-verify`
- `runtime-socket-verify`
- `etcd-access-verify`
- `static-pod-manifest-review`

Output notes:

- Explicitly state when an action bypasses admission control or Kubernetes audit.
- Treat `nodes/proxy` as active/high-risk even when the verb is `get`.
- Keep validation plans read-only unless the user asks for full-mode side-effecting checks.
