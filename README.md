<h1 align="center">KubeTrail（云迹）</h1>

<p align="center">中文 | <a href="./docs/README.en.md">English</a><br></p>

<div align="center">

![Go](https://img.shields.io/badge/Go-1.26%2B-00ADD8?style=flat-square&logo=go&logoColor=white)
![Kubernetes](https://img.shields.io/badge/Kubernetes-client--go-326CE5?style=flat-square&logo=kubernetes&logoColor=white)
![Mode](https://img.shields.io/badge/Mode-safe%20%7C%20full-4B5563?style=flat-square)
![Desktop](https://img.shields.io/badge/Desktop-Wails%20%2B%20Vue-42B883?style=flat-square)
![AI](https://img.shields.io/badge/AI-Claude%20%7C%20Codex-111827?style=flat-square)

</div>

> [!WARNING]
> KubeTrail 仅用于已明确授权的 Kubernetes 集群、命名空间、Pod 或实验环境中的安全测试、红队评估、防御验证和安全审计。任何未授权使用都可能违法，使用者需自行承担相应责任。

KubeTrail 是一个面向 Kubernetes 授权红队评估与防御验证的容器内态势感知、攻击面发现和 AI 辅助攻防编排工具。它从 Pod 内或受控测试环境收集本地环境、ServiceAccount、Kubernetes API 权限、逃逸面、凭据痕迹和云元数据等证据，输出结构化 JSON，供客户端后续审计、复盘、交互式分析、EXP 验证计划、报告生成以及受控动态攻击验证使用。

## 主要特性

- **容器内原生采集**：Pod 内直接使用 in-cluster ServiceAccount 访问 Kubernetes API，不依赖 `kubectl` 或额外运维工具。
- **分级安全模式**：`safe` 聚焦本地只读与 Kubernetes API 只读证据采集；`full` 才启用网络探测、Admission dry-run 和 syscall 探测等主动验证。
- **攻击面证据聚合**：统一收集 ServiceAccount、RBAC、Pod 安全上下文、runtime socket、hostPath、cgroup、`/proc`、`/sys`、LPE、凭据痕迹和云 metadata 信号。
- **敏感数据外发防护**：支持 `raw`、`redact`、`metadata` 三种敏感数据策略，Agent 默认通过引用处理敏感证据，降低 token、密钥和凭据原文进入大模型或外部服务的风险。
- **AI 动态攻防编排**：Agent 支持 Claude/Codex provider，可结合采集结果、攻击面技能、EXP Forge、C2 MCP 和实时回传，在授权范围内动态调整验证路径。
- **本地后渗透工作台**：桌面端统一管理 kubeconfig、Pod/Node 交互、端口转发、文件访问和 C2 MCP 会话，用于证据复核、权限汇聚和后续操作编排。
- **Node 级执行验证**：通过受控模板创建特权容器并进入目标 Node 主机视角，验证 hostPath、hostPID、runtime socket 和节点级权限暴露。
- **快捷权限维持**：内置 ServiceAccount/RBAC、CSR、sidecar patch、pull secret、CronJob/Deployment 等模板说明与清理提示，便于快速生成、验证和复盘权限维持路径。

备注：C2 编排通过 MCP 协议对接外部自有基础设施，仓库仅保留集成入口与调用约束，不包含 C2 服务端实现。

## 快速使用

### 环境要求

- Go 1.26 或更新版本。
- Node.js 18+，用于 `apps/agent` 和桌面端前端。
- Wails，用于开发或构建 `apps/desktop`。
- 可选：本机 `claude` 或 `codex` CLI，用于桌面端调用本地 Agent SDK 运行时。

### 构建

构建采集器：

```bash
go build -o kubetrail-server ./cmd/kubetrail-server
```

构建 release 包：

```bash
./scripts/build-release.sh
```

release 脚本会运行 `go test ./...`，使用 `-trimpath`、`-buildvcs=false`、去除调试/符号信息并清空 Go build ID，然后生成多平台 `kubetrail-server-*` 和 `SHA256SUMS`。

打包桌面端和 Agent 运行资源：

```bash
./build.sh
```

### 常用运行

Pod 内基线采集：

```bash
./kubetrail-server -m safe -o dbus.json
```

本地 kubeconfig 测试：

```bash
./kubetrail-server -m safe -k ~/.kube/config -o dbus.json
```

转交报告或调用 Agent 前，降低敏感材料外发风险：

```bash
./kubetrail-server -m safe -v metadata -c=false -o dbus.json
```

深度 RBAC 审计：

```bash
./kubetrail-server -m safe -s rbac -r full -o rbac.json
```

聚焦本地提权和容器逃逸面：

```bash
./kubetrail-server -m safe -s lpe,escape -o local-attack-surface.json
```

授权范围允许主动验证时运行完整模式：

```bash
./kubetrail-server -m full -o full.json
```

导出可见 ServiceAccount token Secret 并逐个审计权限：

```bash
./kubetrail-server -m safe -secret secret-audit.json -r full -o dbus.json
```

## 采集模式

| 模式 | 行为 | 可能副作用 |
| --- | --- | --- |
| `safe` | 默认模式。本地只读采集和 Kubernetes API 只读采集。 | API read/list/review 请求。 |
| `full` | 包含 `safe`，并增加 DNS 服务发现、云元数据 HTTP 探测、Admission dry-run 和 syscall 探测。 | DNS 查询、HTTP 请求、dry-run create 请求和 syscall 尝试。 |

建议先运行 `safe` 确认授权边界、审计要求和输出规模，再按需运行 `full`。

## 服务端参数

| 参数 | 默认值 | 作用 |
| --- | --- | --- |
| `--mode` / `-m` | `safe` | 采集模式：`safe` 或 `full`。 |
| `--output` / `-o` | `dbus.json` | 主结果 JSON 输出路径；`-` 表示 stdout。 |
| `--pretty` / `-p` | `false` | 格式化 JSON。 |
| `--timeout` / `-t` | `60s` | 整体采集超时。超时后输出已采集到的部分事实和错误。 |
| `--sensitive` / `-v` | `raw` | 敏感 fact 处理：`raw`、`redact`、`metadata`。 |
| `--rbac-mode` / `-r` | `focused` | RBAC 审计深度：`focused` 查高价值路径；`full` 执行完整矩阵和 wildcard 扩展。 |
| `--scan` / `-s` | `all` | 限定采集类别，支持逗号分隔，如 `-s lpe,rbac`。 |
| `--credential-sweep` / `-c` | `true` | 常见凭据文件扫描，默认开启；用 `-c=false` 关闭。 |
| `--secretoutput path` / `-secret path` | 空 | 输出单独的 ServiceAccount token 审计 JSON，包含可见 legacy token Secret 原文和权限审计。 |
| `--kubeconfig` / `-k` | 空 | 使用本地 kubeconfig；为空时使用 in-cluster ServiceAccount。 |
| `--max-items` / `-n` | `100` | 每个 Kubernetes list 请求最多返回的对象数。 |

## 红队常见使用方法

以下流程默认发生在已授权的演练、评估或实验环境中。实际执行前应确认目标集群、命名空间、Pod、凭据和主动验证动作均在授权范围内。

1. 容器落点基线采集

   在已获得的容器 shell、调试容器或测试 Pod 内上传并运行 `kubetrail-server`，优先使用 `safe` 模式建立基线证据。

   ```bash
   ./kubetrail-server -m safe -o dbus.json
   ```

   重点关注当前身份、命名空间、ServiceAccount、挂载卷、运行时 socket、hostPath、特权容器、Linux capability、进程/namespace/cgroup 线索和 Kubernetes API 可见性。

2. RBAC 和横向路径确认

   默认 `safe` 采集已经包含常见 RBAC 高价值矩阵，适合快速判断当前 ServiceAccount 是否具备横向、提权或集群接管潜力。需要覆盖更完整权限面时，可单独运行 RBAC 深度审计。

   ```bash
   ./kubetrail-server -m safe -s rbac -r full -o rbac.json
   ```

   `-r full` 会扩展 SSRR/SSAR、wildcard 和 discovery 相关检查，API Server 调用量会高于默认 focused 模式；如果防守方监控 apiserver 审计日志或异常调用特征，该行为可能被发现。

   常见高价值信号包括 `secrets get/list`、`pods create`、`pods/exec`、`pods/attach`、`pods/portforward`、`pods/ephemeralcontainers patch`、`serviceaccounts/token create`、RBAC `bind/escalate`、`impersonate`、workload controller 写权限、mutating webhook 写权限和 `nodes/proxy`。

3. 本地提权和逃逸面聚焦

   如果只想减少 Kubernetes 对象枚举噪声，聚焦容器本地逃逸面和 LPE 线索：

   ```bash
   ./kubetrail-server -m safe -s lpe,escape -o local-attack-surface.json
   ```

   常见关注点包括特权容器、host namespace、hostPath、Docker/containerd/CRI socket、危险 capability、可写敏感路径、proc/sys 暴露、节点本地网络和已知 LPE 环境特征。

4. 主动验证前置检查

   只有在授权范围允许产生可观测请求时才运行 `full`。该模式会增加 DNS 查询、云元数据 HTTP 探测、Admission dry-run 和 syscall 探测。

   ```bash
   ./kubetrail-server -m full -r focused -o full.json
   ```

   `full` 适合验证云 metadata 可达性、Admission 策略约束、服务发现暴露和本地 syscall 行为，但不应作为首次无差别扫描动作。

5. 可见 ServiceAccount token 审计

   当授权目标包含 legacy ServiceAccount token Secret 审计时，可导出当前身份可见的 token 并逐个检查权限。

   ```bash
   ./kubetrail-server -m safe -secret secret-audit.json -r full -o dbus.json
   ```

   `secret-audit.json` 包含原始 token，必须按高敏凭据保存、传输和销毁。

6. Agent 辅助分析和 EXP 计划

   把 `dbus.json` 交给 `apps/agent`，让 Agent 基于事实列出攻击面、证据、风险排序和验证模板。

   ```bash
   cd apps/agent
   npm run chat -- --input ../../dbus.json --message "按证据列出当前最高价值攻击面、验证路径和清理建议"
   npm run exp -- list
   ```

   生成 EXP bundle 前，应先确认模板参数、目标命名空间、ServiceAccount、镜像和清理命令都符合演练授权。

7. 桌面端联动

   桌面端适合在评估过程中持续浏览资源、导入扫描结果、查看 Pod/Node 上下文、管理 Agent 对话和生成验证材料。

   ```bash
   cd apps/desktop
   wails dev
   ```

   对 Pod terminal、Node terminal、端口转发、持久化资源创建和 shadow kubeconfig 等交互功能，应按演练规则单独确认授权，因为这些动作可能改变集群状态或留下审计记录。

## Kubernetes API 行为

KubeTrail 不调用 `kubectl`。Pod 内运行时，它通过当前容器挂载的 ServiceAccount 访问 Kubernetes API；本地测试时可通过 `--kubeconfig` 指定 kubeconfig。

采集结果取决于当前身份实际拥有的权限：

- 只能读取当前命名空间时，输出会聚焦当前 namespace 和当前工作负载。
- 具备跨命名空间读取权限时，会收集更完整的资源和权限证据。
- API 请求被拒绝时，会记录结构化错误并继续输出已采集事实。
- `nodes/proxy` 等高风险权限只作为授权信号记录；直接主动探测属于 `full` 或客户端 EXP 验证计划。

## 敏感数据处理

默认 `--sensitive raw` 会保留原始证据，适合本地授权研究，但输出应按敏感评估材料处理。

结果需要离开操作者工作站或进入报告流程时，建议使用：

```bash
./kubetrail-server --mode safe --sensitive redact --output dbus.json
```

或只保留元数据：

```bash
./kubetrail-server --mode safe --sensitive metadata --output dbus.json
```

`credential_sweep` 默认开启，可能采集 Kubernetes、云厂商、镜像仓库、CI/CD 和 workload identity 相关凭据文件。`--secretoutput` 是显式 opt-in，会导出原始 token。

## 桌面端

`apps/desktop` 是实验性 Wails 桌面端，后端为 Go，前端为 Vue + Element Plus。当前能力包括：

- 保存和测试集群连接。
- 浏览 namespace、Pod、Node 和相关资源。
- 查看 Pod 日志，进入 Pod terminal，上传/下载/读取/删除 Pod 文件。
- 通过 helper Pod、chroot 或 nsenter 进入 Node terminal，并浏览 Node 文件。
- 端口转发和预设 recon。
- 导入或运行 KubeTrail 扫描结果。
- 管理 Agent 配置、技能、聊天会话、EXP 模板和报告导出。
- 辅助生成持久化资源、ServiceAccount token 和 shadow kubeconfig。

开发运行：

```bash
cd apps/desktop
wails dev
```

Node Shell helper Pod 默认使用：

```text
docker.io/nicolaka/netshoot:v0.13
```

可通过环境变量覆盖：

```bash
export KUBETRAIL_NODE_SHELL_IMAGE=registry.example.com/security/netshoot:latest
```

桌面端不内置 `claude` 或 `codex` CLI。请确保对应 CLI 在 `PATH` 中，或设置 `KUBETRAIL_AGENT_PATH_TO_CLAUDE` / `KUBETRAIL_AGENT_PATH_TO_CODEX`。

## 检测能力矩阵

KubeTrail 的 server 负责采集事实和生成启发式 findings；Agent、EXP Forge 和桌面端负责把事实转成验证计划、受控动作和复盘报告。

### Linux 提权 / K8s 容器漏洞

| 检测项 | 主要证据/组件 | 验证与边界 |
| --- | --- | --- |
| Dirty Frag RxRPC CVE-2026-43500 | `lpe.kernel`、`lpe.kernel_config`、`lpe.modules`、`lpe.sysctls` | 需要 RxRPC 可达性以及 namespace/capability 前置条件。 |
| Dirty Frag xfrm-ESP CVE-2026-43284 | `lpe.kernel`、`lpe.kernel_config`、`lpe.modules`、`lpe.sysctls` | 需要 xfrm/ESP 可达性以及 userns 或 `CAP_SYS_ADMIN` 前置条件。 |
| PackageKit TOCTOU CVE-2026-41651 | `lpe.packages` | 仅作为版本信号；D-Bus activation、服务可达性和发行版补丁需复核。 |
| Copy Fail AF_ALG CVE-2026-31431 | `lpe.kernel`、`lpe.kernel_config` | 检测 AF_ALG AEAD/authenc 相关内核配置和版本区间。 |
| sudo chroot LPE CVE-2025-32463 | `lpe.packages`、`lpe.suid_tools` | 识别 sudo 1.9.14-1.9.17 区间信号；需要结合补丁状态和本地前置条件确认。 |
| nf_tables CVE-2024-1086 | `lpe.kernel`、`lpe.modules`、`lpe.sysctls` | 检测 nf_tables、userns 和内核区间；`CONFIG_INIT_ON_ALLOC_DEFAULT_ON` 等 caveat 会降低置信度。 |
| OverlayFS CVE-2023-0386 | `lpe.kernel`、`lpe.modules`、`lpe.filesystems`、`lpe.sysctls` | 关注 OverlayFS、FUSE、userns 和内核版本组合；需复核发行版补丁。 |
| Dirty Pipe CVE-2022-0847 | `lpe.kernel` | 检测内核版本区间；容器隔离、补丁回溯和写目标条件需复核。 |
| fs_context CVE-2022-0185 | `lpe.kernel`、`lpe.sysctls`、`lpe.process_security` | 需要内核区间以及 userns 或 `CAP_SYS_ADMIN` 等前置条件。 |
| sudo Baron Samedit CVE-2021-3156 | `lpe.packages`、`lpe.suid_tools` | 基于 sudo 版本、SUID 和当前 SUID 转换条件推断；发行版 backport 需要复核。 |
| PwnKit pkexec CVE-2021-4034 | `lpe.packages`、`lpe.suid_tools` | 检测 polkit/policykit 版本和 setuid `pkexec`；可用 `cve-2021-4034-pwnkit` 做授权验证。 |
| Ubuntu OverlayFS CVE-2021-3493 | `lpe.kernel`、`lpe.modules`、`lpe.filesystems`、`lpe.sysctls` | 针对 Ubuntu 内核和 OverlayFS/userns 条件的启发式信号。 |
| eBPF ALU32 CVE-2021-3490 | `lpe.kernel`、`lpe.kernel_config`、`lpe.sysctls` | 需要内核区间与 BPF 前置条件；版本命中不等于可利用。 |
| eBPF verifier CVE-2017-16995 | `lpe.kernel`、`lpe.kernel_config`、`lpe.sysctls` | 需要内核区间、`CONFIG_BPF_SYSCALL` 和 unprivileged BPF 条件同时满足。 |
| setuid screen CVE-2017-5618 | `lpe.packages`、`lpe.suid_tools` | 检测 screen 4.5.0 和 setuid screen；真实利用需确认二进制来源和挂载限制。 |
| Dirty COW CVE-2016-5195 | `lpe.kernel` | 检测旧内核区间；属于低置信版本信号，需结合补丁状态确认。 |
| 高危 Linux capability | `proc.status_security`、`lpe.process_security` | 解码 `CapEff`，识别 `CAP_SYS_ADMIN`、`CAP_SYS_MODULE`、`CAP_SYS_PTRACE`、`CAP_SYS_RAWIO`、`CAP_NET_ADMIN` 等。 |
| Seccomp 关闭 | `proc.status_security` | `Seccomp=0` 会生成 escape finding；代表 syscall 过滤缺失。 |
| `NoNewPrivs` 关闭 | `proc.status_security` | `NoNewPrivs=0` 会放大 SUID 和 exec transition 类提权条件。 |
| host namespace 共享 | `proc.namespaces_self`、`proc.namespaces_pid1` | 识别 PID、network、mount namespace 与 PID 1 相同的情况。 |
| cgroup 可写 | `proc.cgroup_writable` | 检测 cgroup 文件系统 rw 挂载；safe 模式只读判断，不写控制路径。 |
| block device 写权限 | `proc.cgroup_devices`、`filesystem.devices` | 检测 cgroup devices 是否允许写 block device。 |
| cgroup `release_agent` | `proc_sys.breakout_surfaces` | 检测 release_agent 文件和可写 cgroup mount，定位 classic cgroup v1 breakout 条件。 |
| kernel helper path 暴露 | `proc_sys.breakout_surfaces` | 检测 `core_pattern`、`modprobe` 等 helper path 暴露和可写风险。 |
| 敏感 `/proc`、`/sys` 暴露 | `proc_sys.breakout_surfaces` | 识别敏感 proc/sys 路径、AppArmor/SELinux/userns/host 进程可见性信号。 |
| Docker socket 暴露 | `filesystem.runtime_sockets`、`runtime.sockets` | 检测 Docker socket 可见性、权限和 Docker API 响应；可用 `runtime-socket-verify` 复核。 |
| containerd socket 暴露 | `filesystem.runtime_sockets`、`runtime.sockets` | 检测 containerd socket 路径和当前用户可写性。 |
| CRI-O / CRI socket 暴露 | `filesystem.runtime_sockets`、`runtime.sockets` | 检测 CRI 类 socket，作为容器逃逸和节点控制信号。 |
| Docker/runc/containerd 版本风险 | `runtime.versions` | 识别 Docker、runc、containerd 已知风险版本区间；仍需补丁状态确认。 |
| hostPath 挂载 | `filesystem.volume_hints`、`k8s_profile.current_pod_structured` | 识别当前容器或 Pod spec 中的 hostPath；可用 `pod-hostpath` 做受控验证。 |
| 可写 bind mount 且无 `nosuid` | `filesystem.writable_bind_mounts_without_nosuid` | 识别可能放大 SUID 提权的挂载条件。 |
| privileged 容器 | `k8s_profile.current_pod_structured`、`k8s_context.current_pod` | 当前 Pod 容器 `privileged=true` 会生成 critical escape finding。 |
| hostPID | `k8s_profile.current_pod_structured`、`admission_dryrun.pods` | 识别当前 Pod hostPID，或在 `full` 模式验证 Admission 是否允许创建 hostPID Pod。 |
| hostNetwork | `k8s_profile.current_pod_structured`、`admission_dryrun.pods` | 识别当前 Pod hostNetwork，或用 dry-run 验证策略是否拦截。 |
| hostIPC | `k8s_profile.current_pod_structured` | 识别当前 Pod 是否共享 host IPC namespace。 |
| Unconfined seccomp | `k8s_profile.current_pod_structured`、`admission_dryrun.pods` | 识别 Pod/Container 级 `seccompProfile.type=Unconfined`。 |
| 危险 Pod capability | `k8s_profile.current_pod_structured`、`admission_dryrun.pods` | 识别 Pod spec 中添加的高危 capability，如 `SYS_ADMIN`。 |
| syscall 行为探测 | `syscalls.matrix` | `full` 模式执行 `keyctl`、`perf_event_open`、`mount` 等本地 syscall probe。 |

### K8s RBAC 权限检测

| 检测项 | 主要证据/组件 | 验证与边界 |
| --- | --- | --- |
| 当前用户身份 | `identity.current_user` | 采集 UID、GID、EUID、EGID 和 username。 |
| Kubernetes 环境变量 | `environment.kubernetes` | 识别 API Server 环境变量、Pod 内运行迹象和基础环境上下文。 |
| secret-like 环境变量 | `environment.secret_like` | 标记 token、password、secret、access key 等敏感环境变量名和值。 |
| ServiceAccount token 挂载 | `serviceaccount.mounted` | 采集 token、CA、namespace 文件；原文受 `--sensitive` 控制。 |
| ServiceAccount 未挂载 | `serviceaccount.not_found` | 记录默认 SA 路径不存在的情况，便于判断 token automount 状态。 |
| Kubernetes API 可达性 | `k8s_context.version`、`k8s_context.unavailable` | 读取 `/version` 或记录 client 初始化/访问失败。 |
| Kubernetes Discovery 资源面 | `k8s_context.discovery` | 汇总 API groups、resource count 和 high-value resources。 |
| 当前 Pod 解析 | `k8s_profile.current_pod_resolution` | 通过 hostname、env、cgroup Pod UID、container ID 等定位当前 Pod。 |
| 当前 Pod 结构化画像 | `k8s_profile.current_pod_structured` | 汇总 Pod metadata、securityContext、containers、volumes、status 等。 |
| Secret 引用 | `k8s_profile.current_pod_references` | 识别 secret volume、secret env、projected source 和 imagePullSecrets。 |
| ConfigMap 引用 | `k8s_profile.current_pod_references` | 识别 configMap volume、env 和 envFrom 来源。 |
| PVC 引用 | `k8s_profile.current_pod_references` | 识别 Pod 绑定的 persistentVolumeClaim。 |
| projected token 引用 | `k8s_profile.current_pod_references` | 识别 projected ServiceAccount token 的 audience、path、expiration 等线索。 |
| Pod owner chain | `k8s_profile.owner_chain` | 追踪 Deployment、DaemonSet、StatefulSet、Job、CronJob 等上层控制器。 |
| Namespace 上下文 | `k8s_profile.namespace_context` | 汇总 Namespace 标签、注解和 Pod Security Admission 相关信号。 |
| Node 上下文 | `k8s_profile.node_context` | 在有权限时汇总当前 Node 的 OS、labels、taints、addresses 等。 |
| NetworkPolicy 上下文 | `k8s_profile.network_context` | 汇总 NetworkPolicy、Service、Ingress、Gateway 等网络对象信号。 |
| Admission/Policy 组件 | `k8s_profile.policy_security_components` | 识别 PSA、webhook、Gatekeeper/Kyverno 类策略组件和配置面。 |
| SSRR 权限规则 | `k8s_permissions.self_subject_rules` | 记录当前身份在命名空间内的 SelfSubjectRulesReview 结果。 |
| Secret 读权限 | `k8s_permissions.high_value_access` | 检查 `secrets get/list`、`kube-system secrets get/list` 等高价值读权限。 |
| Pod 创建权限 | `k8s_permissions.high_value_access` | 检查 `pods create`，用于工作负载创建、逃逸验证和持久化前置判断。 |
| Pod exec/attach 权限 | `k8s_permissions.high_value_access`、`pods-exec-verify` | 检查 `pods/exec`、`pods/attach` 横向能力，可生成只读验证命令。 |
| Pod portforward 权限 | `k8s_permissions.high_value_access` | 检查 `pods/portforward`，用于内部服务访问路径判断。 |
| ephemeral container 权限 | `k8s_permissions.high_value_access`、`ephemeralcontainers-patch` | 检查 `pods/ephemeralcontainers patch/update`，可生成受控 patch 验证材料。 |
| ServiceAccount token 创建 | `k8s_permissions.high_value_access` | 检查 `serviceaccounts/token create`，用于短期 token minting 风险判断。 |
| RBAC bind 权限 | `k8s_permissions.high_value_access`、`rbac-bind-escalate-verify` | 检查 Role/ClusterRole bind 能力，默认先生成 preflight，不直接创建绑定。 |
| RBAC escalate 权限 | `k8s_permissions.high_value_access`、`rbac-bind-escalate-verify` | 检查 Role/ClusterRole escalate 能力，属于高危提权前置。 |
| impersonate 权限 | `k8s_permissions.high_value_access`、`impersonate-verify` | 检查 users、groups、serviceaccounts impersonate 能力。 |
| `nodes/proxy` 权限 | `k8s_permissions.high_value_access`、`nodes-proxy-verify` | 记录 kubelet API 绕过信号；主动探测由 Agent/桌面端按授权执行。 |
| MutatingWebhook 控制权限 | `k8s_permissions.high_value_access` | 检查 mutating webhook create/update/patch，属于全局请求拦截和持久化入口。 |
| RoleBinding 创建权限 | `k8s_permissions.high_value_access` | 检查 RoleBinding/ClusterRoleBinding create 能力。 |
| DaemonSet 创建权限 | `k8s_permissions.high_value_access` | 检查 DaemonSet create，作为节点级落点和资源滥用入口。 |
| wildcard/cluster-admin 等价 | `k8s_permissions.expanded_wildcards` | `focused` 识别 cluster-admin 等价；`--rbac-mode full` 扩展更多 wildcard 候选。 |
| 可 list Namespace | `k8s_objects.namespaces` | 有权限时枚举 namespaces，用于判断跨 namespace 可见范围。 |
| 可 list 对象清单 | `k8s_objects.permitted_lists` | 只列当前身份可 list 的资源，受 `--max-items` 截断。 |
| CRD/Operator 资源面 | `k8s_context.discovery`、`k8s_objects.permitted_lists`、`operator-crd-abuse-review` | 识别 CRD、operator、controller 和可被间接滥用的自定义资源。 |
| legacy SA token Secret 审计 | `--secretoutput` / `-secret` | 显式导出可见 legacy token Secret、JWT claims 和逐 token SSRR/SSAR。 |
| 常见凭据文件扫描 | `credential_sweep.files` | 默认开启，覆盖 Kubernetes、云厂商、registry、CI/CD、kubeconfig、Docker config 等路径。 |
| 云 metadata 可达性 | `cloud_metadata.endpoints`、`cloud-metadata-verify` | `full` 会产生 metadata HTTP 请求；Agent 模板默认只读验证。 |
| 云身份只读验证 | `cloud-identity-verify` | 生成云 caller identity 类只读命令，需要操作者环境已有授权云凭据。 |
| Kubernetes DNS 服务发现 | `dns_services.results` | `full` 模式查询常见 Kubernetes service DNS 记录。 |
| Service/Ingress 暴露 | `service-ingress-exposure-review` | 基于可见对象生成 Service、Ingress、Gateway、NodePort、LoadBalancer 复核命令。 |
| 管理面服务暴露 | `management-interface-review` | 复核 Dashboard、Argo CD、Rancher、Prometheus、Grafana、Kubeflow 等管理面入口。 |
| 横向网络路径 | `network-lateral-movement-review` | 复核 NetworkPolicy、服务发现、egress 到 API Server、metadata、kubelet、etcd、registry 等路径。 |
| kubelet API 可达性 | `kubelet-api-verify` | 生成 kubelet health/version 类只读探测命令。 |
| etcd endpoint 可达性 | `etcd-access-verify` | 生成 etcd endpoint status 类只读命令，mTLS 材料需授权提供。 |
| registry auth 验证 | `registry-auth-verify` | 生成 registry manifest/auth 非变更检查命令。 |
| Pod/Job 创建验证 | `pod-create-job` | `full` 模板，会创建短生命周期 Job/Pod，需清理。 |
| hostPath Pod 验证 | `pod-hostpath` | `full` 模板，用只读 hostPath Pod 验证 Admission 和挂载风险。 |
| privileged Pod 验证 | `pod-privileged` | `full` 模板，创建短生命周期 privileged Pod。 |
| hostPID Pod 验证 | `pod-hostpid` | `full` 模板，创建 hostPID Pod 验证策略边界。 |
| hostNetwork Pod 验证 | `pod-hostnetwork` | `full` 模板，创建 hostNetwork Pod 验证策略边界。 |
| ServiceAccount/RBAC 权限维持 | `serviceaccount-rbac-persistence` | `full` 模板，生成 SA、Role/ClusterRole、Binding 和可选长效 token Secret。 |
| CSR client cert 权限维持 | `csr-client-cert-persistence` | `dangerous` 模板，生成 CSR、证书和 kubeconfig；可能签发长期访问材料。 |
| sidecar patch 权限维持 | `workload-patch-sidecar-persistence` | `dangerous` 模板，patch Deployment/DaemonSet/StatefulSet template 并触发 rollout。 |
| imagePullSecret 注入 | `pull-secret-injection` | `full` 模板，创建 dockerconfigjson Secret 并 patch ServiceAccount。 |
| Admission 持久化面复核 | `admission-persistence-review` | 只读复核 webhook、CEL admission policy 和 namespace selector。 |
| static pod 持久化面复核 | `static-pod-node-persistence-review`、`static-pod-manifest-review` | 需要授权 node shell 或 hostPath 视角，只做静态 Pod manifest 路径复核。 |
| 镜像供应链复核 | `image-supply-chain-review` | 复核镜像来源、mutable tag、imagePullSecret、registry 和签名策略，不做漏洞库扫描。 |
| 观测与防御绕过 | `observability-evasion-review` | 复核 audit、events、logs、runtime security agents、kubelet/etcd 绕过影响。 |
| 资源滥用/DoS 面 | `resource-hijack-dos-review` | 复核 ResourceQuota、LimitRange、Job/CronJob/DaemonSet、GPU/CPU 资源滥用路径。 |
| Windows/HostProcess 容器复核 | `windows-container-review` | server 本地 collector 以 Linux 为主；Windows 侧由 Agent 生成只读复核命令。 |

## Special Thanks

- Kubernetes `client-go` 和 API machinery。
- Wails、Vue 和 Element Plus。
- [quarkslab/kdigger](https://github.com/quarkslab/kdigger)
- [madhuakula/kubernetes-goat](https://github.com/madhuakula/kubernetes-goat)

## 许可证

MIT License

### Follow the trail
