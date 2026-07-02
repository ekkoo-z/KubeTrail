---
name: service-ingress-exposure
description: Analyze Kubernetes Service, Ingress, Gateway, NodePort, LoadBalancer, ExternalIP, hostPort, and public exposure risks.
---

# Service And Ingress Exposure

Use this skill when facts mention Services, Ingresses, Gateways, routes, NodePorts, LoadBalancers, ExternalIPs, hostPorts, public IPs, DNS names, or TLS exposure.

Scope boundary:

- Owns how traffic enters or is redirected by Kubernetes networking objects.
- Use `exposed-management-interfaces` when the exposed endpoint is a management/admin interface.
- Use `public-workload-rce-surface` when the exposed endpoint is an application with vulnerability or RCE posture.
- Use `network-lateral-movement` for internal movement after initial exposure.

High-value evidence:

- `type: LoadBalancer`, public external IP, NodePort on public node, hostPort, public Ingress/Gateway.
- `externalIPs`, `loadBalancerIP`, `externalName`, wildcard hosts, broad path routing.
- TLS disabled, weak backend protocol, annotation-driven proxy behavior, misrouted default backend.
- Service account and workload behind the exposed endpoint.
- Conditions for traffic interception such as ExternalIP/LoadBalancer control where policy allows it.

Finding rules:

- Confirmed high: public exposure of sensitive management/admin workload or traffic interception primitive.
- Medium: public exposure of unknown workload or NodePort/hostPort on sensitive namespace.
- Low: internal-only exposure with no sensitive backend.
- Unknown: route exists but public/private status or backend identity is missing.

Useful templates:

- `service-ingress-exposure-review`
- `management-interface-review`
- `workload-rce-posture-review`

Output notes:

- State exactly what is exposed, to whom, and which workload receives traffic.
- Avoid duplicating application exploitability; hand off to the workload or management-interface skill.
- Call out CVE-2020-8554-style ExternalIP/LoadBalancer risk only when the required Service permissions or object evidence exists.
