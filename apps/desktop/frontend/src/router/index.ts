import { createRouter, createWebHashHistory } from 'vue-router'

const Welcome = () => import('../views/Welcome.vue')
const Cluster = () => import('../views/Cluster.vue')
const Cheatsheet = () => import('../views/Cheatsheet.vue')
const Settings = () => import('../views/Settings.vue')
const Analysis = () => import('../views/Analysis.vue')
const About = () => import('../views/About.vue')

const router = createRouter({
  history: createWebHashHistory(),
  routes: [
    { path: '/', name: 'welcome', component: Welcome },
    { path: '/cluster/:id', name: 'cluster', component: Cluster, props: true },
    { path: '/cheatsheet', name: 'cheatsheet', component: Cheatsheet },
    { path: '/settings', name: 'settings', component: Settings },
    { path: '/analysis', name: 'analysis', component: Analysis },
    { path: '/about', name: 'about', component: About },
  ],
})

export default router
