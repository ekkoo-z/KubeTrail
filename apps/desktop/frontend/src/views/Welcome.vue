<script setup lang="ts">
import { OpenExternalURL } from '../../wailsjs/go/main/App'

function openGitHub() {
  OpenExternalURL('https://github.com/ekkoo-z/KubeTrail')
}
</script>

<template>
  <el-main class="layout-main welcome-main">
    <div class="welcome-wrap">
      <div class="welcome-hero">
        <div class="welcome-eyebrow">KUBERNETES RED-TEAM CLIENT</div>
        <h1 class="welcome-title">
          KubeTrail
          <span class="welcome-accent">.</span>
        </h1>
        <p class="welcome-sub">
          集群连接、安全态势采集、AI Agent 攻击面分析与 EXP 生成，一体化授权红队工作台。
        </p>
        <div class="welcome-meta">
          <span>Author · ekkoo</span>
          <button class="welcome-link" @click="openGitHub">github.com/ekkoo-z/KubeTrail</button>
        </div>
        <div class="welcome-cta">
          <span class="welcome-kbd">←</span>
          <span>左侧栏点击 <b>+</b> 添加你的第一个集群</span>
        </div>
      </div>

      <div class="welcome-grid">
        <div class="welcome-card">
          <div class="welcome-card__icon">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6"
                 stroke-linecap="round" stroke-linejoin="round">
              <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/>
              <polyline points="14 2 14 8 20 8"/>
            </svg>
          </div>
          <div class="welcome-card__title">集群连接</div>
          <div class="welcome-card__body">kubeconfig 文件或 SA Token 两种接入。Pod exec、日志、文件、端口转发一站式。</div>
        </div>

        <div class="welcome-card">
          <div class="welcome-card__icon">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6"
                 stroke-linecap="round" stroke-linejoin="round">
              <circle cx="12" cy="12" r="10"/>
              <line x1="12" y1="8" x2="12" y2="12"/>
              <line x1="12" y1="16" x2="12.01" y2="16"/>
            </svg>
          </div>
          <div class="welcome-card__title">安全扫描</div>
          <div class="welcome-card__body">16 个采集器全面探测 Pod 逃逸面、RBAC 权限、SA 令牌、云元数据、凭证扫描。</div>
        </div>

        <div class="welcome-card">
          <div class="welcome-card__icon">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6"
                 stroke-linecap="round" stroke-linejoin="round">
              <path d="M21 15a2 2 0 01-2 2H7l-4 4V5a2 2 0 012-2h14a2 2 0 012 2z"/>
            </svg>
          </div>
          <div class="welcome-card__title">AI Agent 攻击</div>
          <div class="welcome-card__body">Claude Agent SDK + 17 个攻击面 Skill，流式对话分析横移路径和攻击链。</div>
        </div>

        <div class="welcome-card">
          <div class="welcome-card__icon">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6"
                 stroke-linecap="round" stroke-linejoin="round">
              <polygon points="12 2 22 8.5 22 15.5 12 22 2 15.5 2 8.5 12 2"/>
              <line x1="12" y1="22" x2="12" y2="15.5"/>
              <polyline points="22 8.5 12 15.5 2 8.5"/>
            </svg>
          </div>
          <div class="welcome-card__title">攻击面 + EXP</div>
          <div class="welcome-card__body">解析具体风险、证据与下一步行动，联动 EXP 模板生成可验证 bundle。</div>
        </div>
      </div>

      <div class="welcome-foot">
        所有 token / kubeconfig 经 AES-GCM 加密保存到
        <code>~/.kubetrail/clusters.json</code>，密钥落在系统 keychain。
        Agent API Key 单独加密存储在 <code>~/.kubetrail/agent-config.json</code>。
      </div>
    </div>
  </el-main>
</template>

<style scoped>
.welcome-main {
  background: var(--kg-bg);
}
.welcome-wrap {
  max-width: 880px;
  margin: 0 auto;
  padding: 56px 24px 40px;
}
.welcome-eyebrow {
  font-family: var(--kg-font-mono);
  font-size: 11px;
  font-weight: 600;
  letter-spacing: 2px;
  color: var(--kg-accent);
  margin-bottom: 14px;
}
.welcome-title {
  font-size: 38px;
  font-weight: 700;
  letter-spacing: -0.5px;
  line-height: 1.1;
  margin: 0 0 14px;
  color: var(--kg-text);
}
.welcome-accent {
  color: var(--kg-accent);
}
.welcome-sub {
  font-size: 15px;
  line-height: 1.6;
  color: var(--kg-text-muted);
  margin: 0 0 24px;
  max-width: 620px;
}
.welcome-meta {
  display: flex;
  align-items: center;
  gap: 10px;
  flex-wrap: wrap;
  margin: -8px 0 22px;
  font-size: 12px;
  color: var(--kg-text-dim);
  font-family: var(--kg-font-mono);
}
.welcome-meta a,
.welcome-meta .welcome-link {
  color: var(--kg-accent);
  text-decoration: none;
  background: transparent;
  border: none;
  font-family: inherit;
  font-size: inherit;
  padding: 0;
  cursor: pointer;
}
.welcome-meta a:hover,
.welcome-meta .welcome-link:hover { text-decoration: underline; }
.welcome-cta {
  display: inline-flex;
  align-items: center;
  gap: 10px;
  padding: 10px 14px;
  border: 1px solid var(--kg-border);
  border-radius: 8px;
  background: var(--kg-surface);
  color: var(--kg-text-muted);
  font-size: 13px;
}
.welcome-cta b { color: var(--kg-accent); font-family: var(--kg-font-mono); }
.welcome-kbd {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: 22px;
  height: 22px;
  border-radius: 4px;
  background: var(--kg-surface-2);
  border: 1px solid var(--kg-border);
  font-family: var(--kg-font-mono);
  font-size: 12px;
  color: var(--kg-text);
}

.welcome-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
  gap: 14px;
  margin-top: 40px;
}
.welcome-card {
  background: var(--kg-surface);
  border: 1px solid var(--kg-border-soft);
  border-radius: 10px;
  padding: 20px;
  transition: border-color .2s ease, transform .2s ease;
}
.welcome-card:hover {
  border-color: var(--kg-border);
}
.welcome-card__icon {
  width: 32px;
  height: 32px;
  display: flex;
  align-items: center;
  justify-content: center;
  border-radius: 6px;
  background: var(--kg-accent-soft);
  color: var(--kg-accent);
  margin-bottom: 14px;
}
.welcome-card__icon svg { width: 17px; height: 17px; }
.welcome-card__title {
  font-size: 14px;
  font-weight: 600;
  color: var(--kg-text);
  margin-bottom: 6px;
}
.welcome-card__body {
  font-size: 12.5px;
  line-height: 1.6;
  color: var(--kg-text-muted);
}

.welcome-foot {
  margin-top: 40px;
  padding-top: 20px;
  border-top: 1px solid var(--kg-border-soft);
  font-size: 12px;
  color: var(--kg-text-dim);
  line-height: 1.7;
}
.welcome-foot code {
  font-family: var(--kg-font-mono);
  font-size: 11.5px;
  color: var(--kg-text-muted);
  background: var(--kg-surface-2);
  border: 1px solid var(--kg-border-soft);
  border-radius: 3px;
  padding: 1px 5px;
}
</style>
