<script setup lang="ts">
import avatarUrl from '../assets/brand/kubetrail-avatar.png'
import { OpenExternalURL } from '../../wailsjs/go/main/App'

const repoUrl = 'https://github.com/ekkoo-z/KubeTrail'

function openRepo() {
  OpenExternalURL(repoUrl)
}
</script>

<template>
  <el-main class="layout-main about-main">
    <section class="about-wrap">
      <header class="about-hero">
        <div class="about-avatar" aria-hidden="true">
          <img :src="avatarUrl" alt="" />
        </div>
        <div class="about-title">
          <div class="about-eyebrow">ABOUT KUBETRAIL</div>
          <h1>KubeTrail</h1>
          <p>面向授权红队评估与防御验证的 Kubernetes 攻击面发现、分析与 EXP 工作台。</p>
        </div>
      </header>

      <div class="about-grid">
        <article class="about-card">
          <div class="about-card__label">Author</div>
          <div class="about-card__value">ekkoo</div>
          <p>项目由 ekkoo 维护，围绕 Kubernetes in-pod situational awareness、攻击面解析和客户端 Agent 分析构建。</p>
        </article>

        <article class="about-card">
          <div class="about-card__label">Repository</div>
          <button class="about-repo" @click="openRepo()">
            github.com/ekkoo-z/KubeTrail
          </button>
          <p>源码、更新与实验能力入口均以 GitHub 仓库为准。</p>
        </article>

        <article class="about-card">
          <div class="about-card__label">Scope</div>
          <div class="about-card__value">Authorized testing only</div>
          <p>服务端采集结构化事实，客户端负责攻击面排序、证据绑定、Agent 对话分析和 EXP bundle 生成。</p>
        </article>

        <article class="about-card">
          <div class="about-card__label">Local data</div>
          <div class="about-paths">
            <code>~/.kubetrail/clusters.json</code>
            <code>~/.kubetrail/agent-config.json</code>
          </div>
          <p>集群配置与 Agent 配置在本地保存，敏感配置通过系统 keychain 派生密钥加密。</p>
        </article>
      </div>

      <section class="about-band">
        <div>
          <div class="about-band__title">Client modules</div>
          <div class="about-band__text">Cluster operations · Server scan result import · Attack surface · Claude Agent skills · EXP Forge</div>
        </div>
        <button class="about-button" @click="openRepo()">打开 GitHub 仓库</button>
      </section>
    </section>
  </el-main>
</template>

<style scoped>
.about-main {
  background: var(--kg-bg);
}
.about-wrap {
  max-width: 960px;
  margin: 0 auto;
  padding: 42px 24px;
}
.about-hero {
  display: grid;
  grid-template-columns: 116px minmax(0, 1fr);
  gap: 22px;
  align-items: center;
  margin-bottom: 28px;
}
.about-avatar {
  width: 104px;
  height: 104px;
  border-radius: 22px;
  overflow: hidden;
  background: #030805;
  box-shadow: 0 0 0 1px color-mix(in srgb, var(--kg-accent) 48%, var(--kg-border)),
              0 18px 52px rgba(0, 0, 0, 0.38),
              0 0 36px rgba(16, 185, 129, 0.16);
}
.about-avatar img {
  width: 100%;
  height: 100%;
  object-fit: cover;
  display: block;
}
.about-eyebrow {
  color: var(--kg-accent);
  font-family: var(--kg-font-mono);
  font-size: 11px;
  font-weight: 700;
  letter-spacing: 1.8px;
  margin-bottom: 8px;
}
.about-title h1 {
  margin: 0 0 8px;
  color: var(--kg-text);
  font-size: 34px;
  line-height: 1.08;
}
.about-title p {
  max-width: 640px;
  margin: 0;
  color: var(--kg-text-muted);
  font-size: 14px;
  line-height: 1.7;
}
.about-grid {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 14px;
}
.about-card {
  min-height: 150px;
  padding: 18px;
  border: 1px solid var(--kg-border);
  border-radius: 8px;
  background: var(--kg-surface);
}
.about-card__label {
  color: var(--kg-text-dim);
  font-family: var(--kg-font-mono);
  font-size: 10px;
  font-weight: 800;
  letter-spacing: 1.2px;
  text-transform: uppercase;
  margin-bottom: 10px;
}
.about-card__value {
  color: var(--kg-text);
  font-size: 18px;
  font-weight: 700;
}
.about-card p {
  margin: 12px 0 0;
  color: var(--kg-text-muted);
  font-size: 12.5px;
  line-height: 1.65;
}
.about-repo {
  color: var(--kg-accent);
  font-family: var(--kg-font-mono);
  font-size: 14px;
  font-weight: 700;
  text-decoration: none;
  overflow-wrap: anywhere;
  background: transparent;
  border: none;
  padding: 0;
  cursor: pointer;
  text-align: left;
}
.about-repo:hover { text-decoration: underline; }
.about-paths {
  display: flex;
  flex-direction: column;
  gap: 6px;
}
.about-paths code {
  width: fit-content;
  max-width: 100%;
  padding: 4px 7px;
  border: 1px solid var(--kg-border);
  border-radius: 5px;
  background: var(--kg-bg);
  color: var(--kg-text);
  font-family: var(--kg-font-mono);
  font-size: 11px;
  overflow-wrap: anywhere;
}
.about-band {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 18px;
  margin-top: 16px;
  padding: 16px 18px;
  border: 1px solid color-mix(in srgb, var(--kg-accent) 36%, var(--kg-border));
  border-radius: 8px;
  background: color-mix(in srgb, var(--kg-accent-soft) 52%, var(--kg-surface));
}
.about-band__title {
  color: var(--kg-text);
  font-size: 13px;
  font-weight: 800;
  margin-bottom: 4px;
}
.about-band__text {
  color: var(--kg-text-muted);
  font-size: 12px;
  font-family: var(--kg-font-mono);
}
.about-button {
  flex: 0 0 auto;
  padding: 8px 12px;
  border-radius: 6px;
  background: var(--kg-accent);
  color: #052E1F;
  font-size: 12px;
  font-weight: 800;
  text-decoration: none;
  border: none;
  cursor: pointer;
}
.about-button:hover { background: #34D399; }
@media (max-width: 760px) {
  .about-hero { grid-template-columns: 1fr; }
  .about-grid { grid-template-columns: 1fr; }
  .about-band { align-items: flex-start; flex-direction: column; }
}
</style>
