# KubeTrail EXP Forge 中文场景手册

本文说明 KubeTrail EXP 模块在授权 Kubernetes 红队评估、攻防演练和防御验证中的使用方式。EXP Forge 的职责是把 KubeTrail 事实、Finding 和模板参数渲染成可审计 bundle；它不替代人工授权判断，也不在 Agent shell 中直接执行副作用操作。

## 使用原则

- 先证据后验证：每个 EXP 计划都应绑定 `findingIds`、`factIds` 和必要的 `sensitiveRefs`。
- 先 `safe` 后 `full`：优先选择只读验证，只有在授权范围允许且需要证明可利用性时才使用会创建、 patch 或执行工作负载的模板。
- 分清三道门：RBAC 证明“能提交请求”，Admission 证明“请求会被接收”，Runtime/Network 证明“落地后能产生影响”。
- 不泄露原始敏感材料：报告和计划默认只引用 `sensitive://` 元数据；原文 materialize 必须由操作者显式开启。
- 横向移动只描述经证据支持的路径：没有网络、凭据或权限证据时，只能标注为假设或待补采。

## 入口命令

列出 CLI 暴露的模板：

```bash
npm run exp -- list
```

渲染指定模板：

```bash
npm run exp -- render --template <templateId> --set key=value
```

通过 Agent 生成计划时，必须先调用 `kubetrail_list_exp_templates`，并只使用运行时返回的模板 ID。当前代码中 `catalog.ts` 可能包含比 MCP 工具公开列表更多的模板；CLI `render` 按 catalog 查找模板，Agent 的 `kubetrail_generate_exp_plan` 按 MCP schema 限制模板 ID。

## 模式和副作用

| 模式 | 适用动作 | 操作边界 |
| --- | --- | --- |
| `safe` | API 只读查询、本地文件 stat、非破坏性连通性检查、身份只读确认 | 可作为默认验证路径，但仍应记录请求目标和授权上下文 |
| `full` | 创建短生命周期 Pod/Job、添加 ephemeral container、生成 hostPath/privileged/hostPID/hostNetwork 验证对象 | 必须有命名空间、对象名、清理命令和回滚说明 |
| `dangerous` | 外部 CVE PoC、本地提权、可能改变目标状态的二进制 | 仅限明确授权的靶场、快照 VM 或红队目标；执行前人工复核 manifest |

## 场景一：RBAC 到 Kubernetes API 横向

适用证据：

- SSRR/SSAR 显示 `secrets get/list/watch`、`pods/create`、`pods/exec`、`pods/ephemeralcontainers patch/update`、`serviceaccounts/token create`。
- `roles/rolebindings/clusterroles/clusterrolebindings` 的 `bind`、`escalate`、`create`、`patch`。
- `impersonate` 用户、组、ServiceAccount 或 node。
- `nodes/proxy`、`nodes/log`、`nodes/exec` 等 node 子资源。

优先模板：

- `secret-list-get-verify`
- `serviceaccount-token-api-verify`
- `pods-exec-verify`
- `pod-create-job`
- `ephemeralcontainers-patch`
- `impersonate-verify`
- `rbac-bind-escalate-verify`
- `nodes-proxy-verify`

利用和横向路径：

1. 如果当前 ServiceAccount token 可用，先用 `serviceaccount-token-api-verify` 确认 API Server 只读连通性和身份上下文。
2. 如果有 Secret 读取权限，用 `secret-list-get-verify` 只列元数据或目标 Secret 的非数据字段；横向重点是找到其他 namespace 的 SA token、registry auth、cloud credential 或应用密钥引用。
3. 如果有 `pods/exec`，用 `pods-exec-verify` 对已授权目标容器执行低影响身份检查；横向重点是从高价值 Pod 内部获取其网络位置、挂载凭据和内部服务可达性。
4. 如果有 workload 创建权限，先结合 Admission 结果判断是否能创建普通 Job；再用 `pod-create-job` 验证最小执行能力。能创建工作负载不等于能逃逸，后续要接 PodSpec、NetworkPolicy 和 ServiceAccount 权限。
5. 如果有 impersonation，优先用 `impersonate-verify` 做 `kubectl auth can-i` 类只读授权确认；横向结论必须说明可 impersonate 的具体 subject 和目标权限。
6. 如果有 RBAC bind/escalate，先用 `rbac-bind-escalate-verify` 做 preflight，不直接创建绑定；只有在 full 授权中才考虑实际绑定对象，并准备回滚。

降级条件：

- 只有 RoleBinding 指向 `cluster-admin` 不代表集群级管理员，必须区分 namespace scope 和 cluster scope。
- `can-i` 结果只能证明授权决策，不能证明 Admission、网络、镜像拉取或运行时行为。
- `nodes/proxy` 即便是 `get` 也应视为高风险，但验证应先选健康检查或版本类低影响路径。

## 场景二：Secret、ServiceAccount 和敏感材料

适用证据：

- `sensitive://` refs、挂载 token、legacy `kubernetes.io/service-account-token` Secret。
- Secret volume、secret-backed env、kubeconfig、client cert/key、Docker config JSON、imagePullSecret。
- 云凭据文件、`.env`、`.netrc`、Git credential、SSH key。

优先模板：

- `secret-material-review`
- `secret-list-get-verify`
- `serviceaccount-token-api-verify`
- `registry-auth-verify`
- `cloud-identity-verify`

利用和横向路径：

1. 先列出敏感 ref 元数据，不打印原文：kind、来源、大小、sha256、是否 materializable。
2. 对 Kubernetes token，先确认 token audience、有效期和绑定对象；再用 `serviceaccount-token-api-verify` 验证能否访问 API discovery。
3. 对 kubeconfig 或 client cert/key，横向重点是它代表的用户/集群/namespace，而不是文件名本身。
4. 对 imagePullSecret 或 Docker config，用 `registry-auth-verify` 做非写入 registry 读取验证；横向重点是是否能拉取私有镜像、读取镜像层中的配置或影响供应链。
5. 对云凭据，交给 `cloud-identity-verify` 做只读 caller identity；不要只凭文件名声称云账号失陷。

降级条件：

- Secret 引用或环境变量名只证明“可能存在材料”，没有 ref 或 API 读取权限时不能证明可用。
- 投影 token 通常是短期、可轮换、可能绑定 audience；legacy SA token 风险更高。

## 场景三：Pod Escape 和节点落点

适用证据：

- privileged、危险 Linux capabilities、hostPID、hostIPC、hostNetwork。
- hostPath 到 `/`、`/var/run`、`/run`、`/var/lib/kubelet`、`/etc`、`/proc`、`/sys`。
- Docker/containerd/CRI-O socket、kubelet socket、CNI socket、设备节点。
- seccomp/AppArmor/SELinux 缺失或弱化，`NoNewPrivs=false`。

优先模板：

- `runtime-socket-verify`
- `pod-privileged`
- `pod-hostpath`
- `pod-hostpid`
- `pod-hostnetwork`

利用和横向路径：

1. 对已运行 Pod，先用事实判断是否已经挂载主机路径或 runtime socket；`runtime-socket-verify` 只做 stat 或非变更 dial。
2. 如果当前身份能创建 Pod，必须先通过 RBAC 和 Admission 确认，再选择 `pod-hostpath`、`pod-privileged`、`pod-hostpid` 或 `pod-hostnetwork` 做 full 验证。
3. 节点落点后的横向重点是 kubelet client cert、bootstrap kubeconfig、容器运行时控制面、CNI 配置、主机网络和云节点身份。
4. hostNetwork 可以把验证视角切换到节点网络，但不自动证明能访问所有节点服务；仍需 NetworkPolicy、node firewall 和服务监听证据。

降级条件：

- 单个危险 capability 不等于逃逸成功，必须有匹配的 mount、device、kernel 或运行时条件。
- runtime socket 只读可见不等于可写控制，需要权限位、连接结果或后续只读 API 证据。

## 场景四：kubelet、runtime、etcd 和 API Server 绕过

适用证据：

- `nodes/proxy`、`nodes/exec`、`nodes/log`、`nodes/stats` 授权。
- kubelet HTTPS 端点可达、匿名访问、webhook auth 缺失、read-only port。
- etcd endpoint、2379/2380、client cert/key、API Server etcd client material。
- static pod manifest 路径可读或可写。

优先模板：

- `nodes-proxy-verify`
- `kubelet-api-verify`
- `runtime-socket-verify`
- `etcd-access-verify`
- `static-pod-manifest-review`

利用和横向路径：

1. `nodes/proxy` 先验证健康、版本或 metrics 类低影响路径；它可能绕过常规 Admission 和部分 Kubernetes API 审计边界。
2. 直连 kubelet 时，先确认认证和授权方式；只读验证用于判断端点是否暴露敏感节点/Pod 信息。
3. etcd 验证只做 endpoint status 或只读身份确认；如果有有效 client material，横向影响可能上升到集群状态读取或控制平面级别。
4. static pod manifest 若可写，是持久化和控制平面影响路径；默认只做 review，full 验证需要非常明确的授权和回滚方案。

降级条件：

- kubelet 端口可达不等于具备 exec/log 权限。
- etcd endpoint 可达但没有 mTLS/client material 时，只能标为暴露或待验证。

## 场景五：外部暴露、RCE 入口和管理界面

适用证据：

- Service `LoadBalancer`、NodePort、ExternalIP、hostPort、Ingress、Gateway、公共 DNS/IP。
- Dashboard、Argo CD、Rancher、Kubeflow、Grafana、Prometheus、Airflow、Jupyter、Jenkins、Harbor 等管理面。
- 暴露 workload 的镜像、版本、进程、env、ServiceAccount、网络可达性。

优先模板：

- `service-ingress-exposure-review`
- `management-interface-review`
- `workload-rce-posture-review`
- `secret-list-get-verify`
- `network-lateral-movement-review`

利用和横向路径：

1. 用 `service-ingress-exposure-review` 明确“谁能访问什么入口，以及后端 workload 是谁”。
2. 如果后端是管理面，用 `management-interface-review` 关联其 ServiceAccount、RBAC、认证模式和是否能创建 workload 或读取 Secret。
3. 如果后端是普通应用，用 `workload-rce-posture-review` 评估“假设 RCE 后”的 blast radius：token、env、文件、API、metadata、内部服务、数据库、registry。
4. 横向移动常见路径是：外部入口 -> workload RCE -> mounted token/env secret -> API/metadata/internal service -> 新 namespace 或云账号。

降级条件：

- 暴露端口不等于存在 CVE；必须有产品、版本或配置证据。
- 内部 Service 暴露不等于公网暴露；需要区分 internet、VPC、cluster 内部和当前 Pod 可达。

## 场景六：云元数据和工作负载身份

适用证据：

- `169.254.169.254`、AWS IMDSv1/IMDSv2、GCP metadata server、Azure IMDS。
- AWS IRSA、EKS Pod Identity、GKE Workload Identity Federation、AKS Workload Identity。
- projected token、provider env、federated token file、role/service account 标识。

优先模板：

- `cloud-metadata-verify`
- `cloud-identity-verify`
- `network-lateral-movement-review`

利用和横向路径：

1. 先用 `cloud-metadata-verify` 判断从目标 Pod 网络命名空间是否能访问 metadata 或工作负载身份端点。
2. 如果拿到身份标识或临时凭据 ref，再用 `cloud-identity-verify` 在授权操作员环境做只读 caller identity。
3. 横向重点从 Kubernetes 转到云 IAM：对象存储、镜像仓库、Secret Manager、KMS、数据库、消息队列、跨账号 assume role。
4. 对 IRSA/GKE/AKS Workload Identity，要区分 Kubernetes ServiceAccount、云 IAM subject 和最终云权限三层证据。

降级条件：

- metadata reachability 只证明网络路径，不证明凭据可取。
- 工作负载身份 env 只证明配置痕迹，不证明 token exchange 成功。

## 场景七：网络横向移动

适用证据：

- NetworkPolicy 缺失、无 default deny、CNI 不执行网络策略。
- Pod 到 API Server、metadata、kubelet、etcd、数据库、registry、service mesh、互联网的 egress。
- DNS 解析、headless service、跨 namespace endpoint、内部敏感服务。

优先模板：

- `network-lateral-movement-review`
- `cloud-metadata-verify`
- `kubelet-api-verify`
- `service-ingress-exposure-review`

利用和横向路径：

1. 先分清 ingress、egress 和 east-west；不要把“服务存在”误写成“当前 Pod 可达”。
2. 若 egress 到 API Server 且有 token，进入 RBAC 场景。
3. 若 egress 到 metadata，进入云身份场景。
4. 若 egress 到 kubelet/etcd/runtime API，进入组件绕过场景。
5. 若 egress 到数据库、队列、缓存或内部管理面，结合 Secret/env/config 证据判断是否具备应用层认证材料。

降级条件：

- NetworkPolicy 缺失通常是姿态风险；没有敏感 endpoint 或凭据时不应判高。
- service mesh mTLS 存在时，网络可达不等于应用可访问。

## 场景八：Admission、控制器持久化和 CRD 间接提权

适用证据：

- Pod Security Admission namespace labels：`enforce`、`audit`、`warn` 和 privileged/baseline/restricted。
- Validating/MutatingWebhookConfiguration、Gatekeeper、Kyverno、image policy、quota、LimitRange。
- Deployment、DaemonSet、Job、CronJob、static pod、sidecar/init container 注入。
- CRD、Operator、controller ServiceAccount、ownerReferences、跨 namespace 引用。

优先模板：

- `admission-policy-review`
- `controller-persistence-review`
- `operator-crd-abuse-review`
- `pod-create-job`
- `pod-privileged`
- `pod-hostpath`

利用和横向路径：

1. 对 workload 创建权限，先用 `admission-policy-review` 判断危险 PodSpec 是否会被拦截。
2. 如果 Admission 放行，再用最小副作用模板证明普通 Job 或特定安全上下文可创建。
3. 对持久化，优先 review DaemonSet/CronJob/Deployment 的覆盖范围、namespace、SA、image 和 cleanup，而不是直接创建长驻对象。
4. 对 CRD/Operator，横向链是“低权限 actor -> 可写 CR -> 高权限 controller -> 创建/读取/修改目标资源”。必须证明 controller 消费相关字段。

降级条件：

- webhook `failurePolicy: Ignore` 是绕过风险，但没有目标请求和 namespace selector 证据时不应直接判为可绕过。
- Operator RBAC 很高但用户不能写它监听的 CR 时，只能标为潜在风险。

## 场景九：镜像、Registry 和供应链

适用证据：

- 未 pin digest、`latest`、高权限 workload 使用不可信 registry 或可疑镜像名。
- imagePullSecret、Docker config、registry token、CI/CD runner 凭据。
- SBOM/scanner 缺失、签名策略缺失、镜像漏洞或恶意行为证据。

优先模板：

- `image-supply-chain-review`
- `registry-auth-verify`
- `admission-policy-review`
- `secret-material-review`

利用和横向路径：

1. 用 `image-supply-chain-review` 建立镜像、namespace、workload 权限和运行安全上下文的关系。
2. 用 `registry-auth-verify` 做只读 manifest/auth 检查，确认凭据能访问哪些 registry/repo。
3. 横向路径可能是 registry 凭据 -> 私有镜像层/配置泄露 -> CI/CD 凭据 -> 新镜像发布 -> 高权限 workload 拉取。
4. 如果能推送镜像，还必须结合 Admission、imagePullPolicy、tag 策略和控制器滚动更新证据。

降级条件：

- `latest` 是供应链卫生问题，不单独证明 compromise。
- 有 pull 权限不等于有 push 权限。

## 场景十：观测绕过、防御验证和资源滥用

适用证据：

- audit policy、日志转发、Event delete、pods/log、runtime sensor、Falco/Tetragon/Tracee/Hubble/云安全产品。
- 删除日志或事件权限、kubelet/etcd 绕过路径、可疑清理行为。
- ResourceQuota/LimitRange 缺失、GPU/CPU workload、autoscaler、Job/CronJob/DaemonSet 权限。

优先模板：

- `observability-evasion-review`
- `resource-hijack-dos-review`
- `controller-persistence-review`
- `pod-create-job`

利用和横向路径：

1. 防御绕过必须绑定具体攻击路径，例如 `nodes/proxy` 绕过 Admission 审计、runtime socket 绕过 API Server、事件删除掩盖 Job 创建。
2. 资源滥用默认只做 review；不要用破坏性压力测试证明 DoS，除非授权范围明确要求 full 验证。
3. 横向影响通常不是数据窃取，而是成本、可用性和检测空窗：创建 Job/CronJob/DaemonSet、触发 autoscaler、占用 GPU 或拉取大镜像。

降级条件：

- 没观察到安全 Agent 不等于没有检测；collector 缺口应标为 unknown。
- quota 缺失但没有 workload 创建权限时，不应判为 confirmed high。

## 场景十一：Windows 容器和混合集群

适用证据：

- Windows node、Windows container、HostProcess Pod、Windows kubelet/runtime、Hyper-V isolation。
- Windows 工作负载暴露、node credential、kubeconfig、ServiceAccount token。

优先模板：

- `windows-container-review`
- `serviceaccount-token-api-verify`
- `kubelet-api-verify`

利用和横向路径：

1. 只有出现 Windows 证据时才启用该场景。
2. 横向重点是 Windows container 到 Windows node 的边界、HostProcess 权限、node credential 和混合集群调度路径。
3. Linux Pod escape 规则不能直接套用到 Windows；报告必须标明隔离模式和已知/未知条件。

## 场景十二：外部 CVE 和本地提权

适用证据：

- 目标 OS/arch、软件版本、补丁状态、PoC manifest、预编译二进制 hash。
- 容器内本地用户上下文、setuid 文件、宿主/容器边界、是否为靶场或快照环境。

优先模板：

- `cve-2021-4034-pwnkit`
- `external-cve-poc`

利用和横向路径：

1. `dangerous` 模板只用于明确授权的实验环境或红队目标，执行前必须复核 source、commit/tag、sha256、参数和副作用。
2. 本地提权的横向意义取决于运行位置：容器内 root 不等于宿主 root；宿主 root 才可能进入节点凭据、runtime、kubelet、CNI 和云节点身份路径。
3. 对容器内 CVE，必须确认是否受容器隔离、seccomp、AppArmor、SELinux、capability 和只读文件系统限制。

## 快速决策表

| 目标问题 | 首选模板 | 后续横向方向 |
| --- | --- | --- |
| 当前 token 能否用 API | `serviceaccount-token-api-verify` | RBAC、Secret、workload 创建 |
| 能否读 Secret | `secret-list-get-verify` | SA token、registry、cloud/app credential |
| 能否创建工作负载 | `pod-create-job` | Admission、Pod escape、持久化 |
| 能否创建危险 PodSpec | `admission-policy-review` 后接 `pod-privileged`/`pod-hostpath` | 节点落点、runtime、node credential |
| 能否经 kubelet/node 子资源绕过 API | `nodes-proxy-verify`、`kubelet-api-verify` | Pod/log/exec、节点信息、审计绕过 |
| metadata 是否可达 | `cloud-metadata-verify` | 云 IAM、Secret Manager、registry、跨账号 |
| 外部入口打进去后有什么影响 | `service-ingress-exposure-review`、`workload-rce-posture-review` | token/env/网络/metadata |
| 管理面暴露有什么影响 | `management-interface-review` | workload 创建、Secret 读取、CI/CD |
| Operator 是否可间接提权 | `operator-crd-abuse-review` | controller SA、跨 namespace、生成资源 |
| Registry 凭据有什么用 | `registry-auth-verify` | 私有镜像、CI/CD、供应链投递 |
| 是否能隐蔽或删除痕迹 | `observability-evasion-review` | 审计缺口、事件/日志权限、component bypass |
| 是否能造成资源滥用 | `resource-hijack-dos-review` | Job/CronJob/DaemonSet、autoscaler、GPU |

## 报告输出建议

每个 EXP 计划建议包含：

- `templateId`：运行时可用的模板 ID。
- `title`：验证目标，不写夸大结论。
- `findingIds` / `factIds`：证据来源。
- `parameters`：namespace、pod、node、image、path、provider 等最小参数。
- `sensitiveRefs`：只列 ref，不列原文。
- `preconditions`：授权、网络位置、身份上下文、Admission、镜像拉取、目标对象存在。
- `sideEffects`：API 请求、对象创建、patch、exec、二进制执行等。
- `cleanup`：删除 Job/Pod、撤销 patch、清理 bundle、恢复快照。
- `defensiveFix`：最小权限、default deny、Pod Security、Admission policy、禁用 kubelet read-only port、限制 metadata、集中审计。

## 参考资料

- Kubernetes RBAC Authorization: https://kubernetes.io/docs/reference/access-authn-authz/rbac/
- Kubernetes RBAC Good Practices: https://kubernetes.io/docs/concepts/security/rbac-good-practices/
- Kubernetes ServiceAccounts: https://kubernetes.io/docs/concepts/security/service-accounts/
- Kubernetes ServiceAccount token projection: https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/
- Kubernetes Secrets: https://kubernetes.io/docs/concepts/configuration/secret/
- Kubernetes Security Context: https://kubernetes.io/docs/tasks/configure-pod-container/security-context/
- Kubernetes Pod Security Admission: https://kubernetes.io/docs/concepts/security/pod-security-admission/
- Kubernetes Pod Security Standards: https://kubernetes.io/docs/concepts/security/pod-security-standards/
- Kubernetes NetworkPolicy: https://kubernetes.io/docs/concepts/services-networking/network-policies/
- Kubernetes Service: https://kubernetes.io/docs/concepts/services-networking/service/
- Kubernetes Ingress: https://kubernetes.io/docs/concepts/services-networking/ingress/
- Kubernetes Gateway API: https://kubernetes.io/docs/concepts/services-networking/gateway/
- Kubernetes kubelet authentication/authorization: https://kubernetes.io/docs/reference/access-authn-authz/kubelet-authn-authz/
- Kubernetes API Server Bypass Risks: https://kubernetes.io/docs/concepts/security/api-server-bypass-risks/
- Kubernetes Auditing: https://kubernetes.io/docs/tasks/debug/debug-cluster/audit/
- Kubernetes Dynamic Admission Control: https://kubernetes.io/docs/reference/access-authn-authz/extensible-admission-controllers/
- AWS EKS Pod Identity: https://docs.aws.amazon.com/eks/latest/userguide/pod-identities.html
- AWS EC2 Instance Metadata Service: https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html
- GKE Workload Identity Federation: https://docs.cloud.google.com/kubernetes-engine/docs/concepts/workload-identity
- GKE metadata protection: https://docs.cloud.google.com/kubernetes-engine/docs/how-to/protecting-cluster-metadata
- AKS Workload Identity: https://learn.microsoft.com/en-us/azure/aks/workload-identity-overview
- Azure Instance Metadata Service: https://learn.microsoft.com/en-us/azure/virtual-machines/instance-metadata-service
