---
name: exposed-management-interfaces
description: Analyze exposed Kubernetes and cloud-native management interfaces such as Dashboard, Kubeflow, Argo CD, Rancher, Prometheus, Grafana, OpenMetadata, Jupyter, and Airflow.
---

# Exposed Management Interfaces

Use this skill when facts mention management UIs, admin APIs, dashboards, service names, ingress routes, NodePorts, LoadBalancers, public URLs, weak auth, default credentials, or service accounts tied to these interfaces.

Scope boundary:

- Owns management-plane applications and their exposure/auth posture.
- Use `service-ingress-exposure` for generic Service/Ingress mechanics.
- Use `public-workload-rce-surface` for application CVE/RCE posture after the exposed app is identified.
- Use `k8s-rbac-analysis` for the permissions of the interface service account.

High-value interfaces:

- Kubernetes Dashboard, Kubeflow Central Dashboard, Argo CD, Rancher, Lens/Octant-style web shells.
- Prometheus, Alertmanager, Grafana, Jaeger, Kiali, Elasticsearch/Kibana, Loki.
- OpenMetadata, Airflow, Jupyter, MLflow, Jenkins, Tekton Dashboard, Harbor, registry UIs.
- Cloud-native admin panels that can create workloads, run pipelines, read secrets, or manage cluster resources.

High-value evidence:

- Public LoadBalancer, Ingress/Gateway host, NodePort, hostPort, or external URL.
- Authentication mode, anonymous access, default credentials, SSO bypass, missing TLS.
- Bound ServiceAccount, namespace, RBAC grants, mounted token, cross-namespace permissions.
- Ability to create pipelines, jobs, pods, deployments, or read environment/config/secrets.

Finding rules:

- Confirmed high: externally reachable management interface with weak/no auth and resource creation or secret-reading capability.
- Medium: exposed interface with auth unknown, or internal-only interface reachable from compromised pod.
- Low: interface present with no exposure or high-risk permissions shown.
- Unknown: service exists but route/auth/RBAC facts are missing.

Useful templates:

- `management-interface-review`
- `secret-list-get-verify`
- `service-ingress-exposure-review`

Side-effecting templates (explicit authorization required):

- `pod-create-job`

Output notes:

- Name the interface and explain what it can do if abused.
- Distinguish internet exposure from in-cluster lateral reachability.
- Do not claim exploitation of a product CVE unless version and CVE evidence exist.
