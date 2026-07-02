/**
 * Persistence Catalog
 *
 * Static catalog of Kubernetes post-exploitation persistence techniques for
 * the desktop GUI. Each entry maps to a backend PersistenceTechnique.
 *
 * Follows the same pattern as lpeExpCatalog.ts.
 */

export interface PersistenceParam {
  key: string
  label: string
  type: 'string' | 'number' | 'boolean'
  defaultValue: string | number | boolean
  placeholder?: string
}

export interface PersistenceTechniqueCard {
  id: string
  technique: string
  label: string
  category: 'rbac' | 'workload' | 'credential'
  riskLevel: 'low' | 'medium' | 'high'
  description: string
  requiresConfirm: boolean
  permissions: string[]
  parameters: PersistenceParam[]
  riskNotes?: string[]
}

export const persistenceCatalog: PersistenceTechniqueCard[] = [
  {
    id: 'sa-cluster-admin',
    technique: 'serviceaccount',
    label: 'ServiceAccount + ClusterRoleBinding',
    category: 'rbac',
    riskLevel: 'low',
    description:
      '创建 ServiceAccount 并绑定 cluster-admin ClusterRole，仅留下 RBAC 产物，不对集群工作负载产生影响。创建后可使用 token 直接访问 API Server。',
    requiresConfirm: false,
    permissions: [
      'create serviceaccounts',
      'create secrets',
      'create clusterrolebindings (rbac.authorization.k8s.io)',
    ],
    parameters: [
      {
        key: 'name',
        label: 'SA 名称',
        type: 'string',
        defaultValue: 'kubetrail-admin',
        placeholder: 'kubetrail-admin',
      },
      {
        key: 'namespace',
        label: '命名空间',
        type: 'string',
        defaultValue: 'default',
        placeholder: 'default / kube-system',
      },
      {
        key: 'clusterAdmin',
        label: 'Cluster Admin',
        type: 'boolean',
        defaultValue: true,
      },
    ],
  },
  {
    id: 'shadow-kubeconfig',
    technique: 'shadow-kubeconfig',
    label: '影子 Kubeconfig',
    category: 'credential',
    riskLevel: 'low',
    description:
      '自动创建高权 SA + 拉取 token + 生成完整 kubeconfig YAML 文件。可直接保存到本地，使用 kubectl --kubeconfig 或 KUBECONFIG 环境变量使用。',
    requiresConfirm: false,
    permissions: [
      'create serviceaccounts',
      'create secrets',
      'create clusterrolebindings (rbac.authorization.k8s.io)',
    ],
    parameters: [
      {
        key: 'name',
        label: 'SA 名称',
        type: 'string',
        defaultValue: 'kubetrail-shadow',
        placeholder: 'kubetrail-shadow',
      },
      {
        key: 'namespace',
        label: '命名空间',
        type: 'string',
        defaultValue: 'default',
        placeholder: 'default',
      },
    ],
  },
  {
    id: 'token-request',
    technique: 'token-request',
    label: 'TokenRequest 令牌请求',
    category: 'credential',
    riskLevel: 'low',
    description:
      '对已有 ServiceAccount 调用 TokenRequest API 获取有时效的 token。不创建新资源，仅生成临时凭据。适合短期访问或需要时效控制的场景。',
    requiresConfirm: false,
    permissions: ['create serviceaccounts/token'],
    parameters: [
      {
        key: 'saName',
        label: 'SA 名称',
        type: 'string',
        defaultValue: 'default',
        placeholder: '已有 SA 名称',
      },
      {
        key: 'namespace',
        label: '命名空间',
        type: 'string',
        defaultValue: 'default',
        placeholder: 'default',
      },
      {
        key: 'durationSeconds',
        label: '有效期 (秒)',
        type: 'number',
        defaultValue: 3600,
        placeholder: '3600 = 1小时, 86400 = 24小时',
      },
    ],
    riskNotes: ['Token 过期后自动失效, 最长 7 天 (604800 秒)'],
  },
  {
    id: 'cronjob-beacon',
    technique: 'cronjob',
    label: 'CronJob 定时信标',
    category: 'workload',
    riskLevel: 'medium',
    description:
      '创建 CronJob 周期性执行命令或回调。带资源限制 (50m CPU / 32Mi Memory)，对节点压力可控。适用于定期心跳、信标回调等场景。',
    requiresConfirm: true,
    permissions: ['create cronjobs (batch/v1)', 'create jobs'],
    parameters: [
      {
        key: 'name',
        label: '名称',
        type: 'string',
        defaultValue: 'kubetrail-persist',
        placeholder: 'kubetrail-persist',
      },
      {
        key: 'namespace',
        label: '命名空间',
        type: 'string',
        defaultValue: 'default',
        placeholder: 'default',
      },
      {
        key: 'schedule',
        label: 'Cron 表达式',
        type: 'string',
        defaultValue: '*/30 * * * *',
        placeholder: '*/30 * * * *',
      },
      {
        key: 'image',
        label: '镜像',
        type: 'string',
        defaultValue: 'busybox:stable',
        placeholder: 'busybox:stable',
      },
      {
        key: 'command',
        label: '命令',
        type: 'string',
        defaultValue: '/bin/sh -c echo persistence-ok',
        placeholder: '执行的命令',
      },
    ],
    riskNotes: [
      '默认每 30 分钟执行一次，建议调整 schedule 避免高频调度',
      '资源限制: 50m CPU / 32Mi Memory，请根据实际需求调整',
      'CronJob 会被调度器和审计系统记录',
    ],
  },
  {
    id: 'deployment-backdoor',
    technique: 'deployment',
    label: 'Deployment 后门',
    category: 'workload',
    riskLevel: 'medium',
    description:
      '创建常驻 Deployment (1 副本)，带资源限制。Pod 维持运行状态，适用于需要持久 TCP 连接的反向 shell 或隧道场景。',
    requiresConfirm: true,
    permissions: ['create deployments (apps/v1)'],
    parameters: [
      {
        key: 'name',
        label: '名称',
        type: 'string',
        defaultValue: 'kubetrail-backdoor',
        placeholder: 'kubetrail-backdoor',
      },
      {
        key: 'namespace',
        label: '命名空间',
        type: 'string',
        defaultValue: 'default',
        placeholder: 'default',
      },
      {
        key: 'image',
        label: '镜像',
        type: 'string',
        defaultValue: 'busybox:stable',
        placeholder: 'busybox:stable',
      },
      {
        key: 'command',
        label: '命令',
        type: 'string',
        defaultValue: '/bin/sh -c while true; do sleep 3600; done',
        placeholder: '容器入口命令',
      },
    ],
    riskNotes: [
      '默认 1 副本，可按需增加但会增加节点资源消耗',
      '资源限制: 50m CPU / 32Mi Memory',
      'Pod 重启或节点驱逐后 Deployment 会自动重建',
    ],
  },
  {
    id: 'daemonset-backdoor',
    technique: 'daemonset',
    label: 'DaemonSet 全节点后门',
    category: 'workload',
    riskLevel: 'high',
    description:
      '在每个节点上运行一个 Pod。风险较高 — 会覆盖所有节点（包括后续新加入的节点），可能影响集群调度和资源分配。仅建议在受控实验环境中使用。',
    requiresConfirm: true,
    permissions: ['create daemonsets (apps/v1)'],
    parameters: [
      {
        key: 'name',
        label: '名称',
        type: 'string',
        defaultValue: 'kubetrail-node-agent',
        placeholder: 'kubetrail-node-agent',
      },
      {
        key: 'namespace',
        label: '命名空间',
        type: 'string',
        defaultValue: 'default',
        placeholder: 'default',
      },
      {
        key: 'image',
        label: '镜像',
        type: 'string',
        defaultValue: 'busybox:stable',
        placeholder: 'busybox:stable',
      },
      {
        key: 'command',
        label: '命令',
        type: 'string',
        defaultValue: '/bin/sh -c while true; do sleep 3600; done',
        placeholder: '容器入口命令',
      },
    ],
    riskNotes: [
      '⚠️ 高风险：会在所有节点（包括新节点）上创建 Pod',
      '⚠️ 请确保资源限制足够低 (30m CPU / 24Mi Memory) 避免影响节点',
      '⚠️ 在生产环境中可能触发告警和 PodSecurity 拦截',
      '⚠️ 仅在授权实验环境中使用',
    ],
  },
  {
    id: 'pull-secret-injection',
    technique: 'pull-secret',
    label: 'ImagePullSecret 注入',
    category: 'credential',
    riskLevel: 'medium',
    description:
      '创建 dockerconfigjson 类型 Secret，并挂到 default ServiceAccount 的 imagePullSecrets。适用于验证默认镜像拉取凭据、私有镜像供应链或后续工作负载继承风险。',
    requiresConfirm: true,
    permissions: ['create secrets', 'get serviceaccounts', 'patch serviceaccounts'],
    parameters: [
      {
        key: 'namespace',
        label: '命名空间',
        type: 'string',
        defaultValue: 'default',
        placeholder: 'default',
      },
    ],
    riskNotes: [
      '会修改 default ServiceAccount，后续未显式设置 imagePullSecrets 的 Pod 可能继承该配置',
      '当前后端创建占位 dockerconfigjson，不写入真实 registry 凭据',
      '删除该资源会同时移除 default ServiceAccount 上的引用',
    ],
  },
]

export function persistenceSearchText(card: PersistenceTechniqueCard): string {
  return [card.label, card.description, card.technique, card.category, card.riskLevel, ...card.permissions]
    .join(' ')
    .toLowerCase()
}

export function riskVariant(level: string): 'safe' | 'full' | 'dangerous' {
  if (level === 'low') return 'safe'
  if (level === 'high') return 'dangerous'
  return 'full'
}

export function riskLabel(level: string): string {
  if (level === 'low') return '低风险'
  if (level === 'medium') return '中风险'
  if (level === 'high') return '高风险'
  return level
}

export function categoryLabel(category: string): string {
  const labels: Record<string, string> = {
    rbac: 'RBAC',
    workload: '工作负载',
    credential: '凭据',
  }
  return labels[category] ?? category
}
