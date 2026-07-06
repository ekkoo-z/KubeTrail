---
name: pod-escape-surface
description: Analyze pod-local escape surfaces such as privileged containers, hostPath, hostPID, hostNetwork, capabilities, runtime sockets, mounts, devices, and namespaces.
---

# Pod Escape Surface

Use this skill when the result contains local filesystem, mount, device, process, capability, namespace, runtime, or Pod profile facts.

Scope boundary:

- Owns the security posture of an already observed Pod/container and its local host-escape conditions.
- Do not score the permission to create a new dangerous Pod here; use `k8s-rbac-analysis` and `admission-policy-governance`.
- Do not score direct kubelet, runtime socket, or etcd API exposure here unless it is observed as a local mount or socket inside the container; use `kubelet-runtime-etcd-bypass` for component APIs.
- Do not score cloud identity; use `cloud-metadata-analysis`.

High-value signals:

- Privileged container or broad Linux capabilities.
- `hostPath` mounts, especially `/`, `/var/run`, `/run`, `/var/lib/kubelet`, `/etc`, `/proc`, `/sys`.
- Docker, containerd, CRI-O, kubelet, or CNI sockets.
- hostPID, hostIPC, hostNetwork, or shared process namespace.
- Writable projected tokens, service account token mounts, or unusual secret/config mounts.
- Device exposure under `/dev`.
- `NoNewPrivs=false`, missing seccomp/AppArmor/SELinux hints, or broad capability bounding set.

Finding rules:

- Capability 解码铁律

1. 先展开二进制，再翻译。 收到 hex 值必须写出完整 32 位二进制，逐 bit 标注 cap 名称。禁止跳过展开直接列举。
2. 高价值 cap 必须双列有/无。 CAP_SYS_ADMIN(20)、CAP_SYS_MODULE(16)、CAP_SYS_PTRACE(19)、CAP_SYS_RAWIO(17)、CAP_NET_ADMIN(12) — 有写有，没有写没有，禁止只列有的

- Confirmed high: privileged plus host root or runtime socket; hostPID plus writable hostPath; dangerous capability plus matching host mount/device.
- Medium: single strong primitive such as hostPath to sensitive path, hostNetwork, hostPID, broad caps, or runtime socket existence without write evidence.
- Low: weak hardening only, such as missing seccomp/AppArmor hints with no active escape primitive.
- Unknown: pod spec missing or local collection denied.

Map findings to these EXP templates when evidence supports them:

- `runtime-socket-verify`

Side-effecting templates (explicit authorization required):

- `pod-privileged`
- `pod-hostpath`
- `pod-hostpid`
- `pod-hostnetwork`

Do not claim a container escape is guaranteed. State the preconditions needed for a controlled validation.
