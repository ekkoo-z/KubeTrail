---
name: image-registry-supply-chain
description: Analyze container image provenance, registry credentials, mutable tags, typosquatting, untrusted registries, and CI/CD supply-chain exposure.
---

# Image Registry Supply Chain

Use this skill when facts mention images, registries, imagePullSecrets, tags, digests, signatures, SBOM/scanner output, CI/CD runners, GitHub Actions, build jobs, or suspicious image naming.

Scope boundary:

- Owns image and build/registry trust, not runtime escape from a running container.
- Use `serviceaccount-secret-material` for the raw registry credential material.
- Use `pod-escape-surface` for dangerous runtime securityContext or mounted sockets.
- Use `workload-controller-persistence` for malicious controller objects using an image.

High-value evidence:

- Images without digest pinning, `latest`, mutable tags, typosquatted names, public Docker Hub images in system namespaces.
- Unknown or untrusted registries, unexpected cross-cloud registries, private registry pull secrets in broad namespaces.
- Image pull policy, admission signature policy, SBOM/vulnerability facts, scan disabled or stale.
- CI/CD service account tokens, GitHub/GitLab runner env, Docker config, publishing credentials.
- Image names mimicking Kubernetes components such as kube-controller, pause, proxy, metrics, or system agents.

Finding rules:

- Confirmed high: suspicious image in privileged/system workload, malicious scanner/action evidence, or registry credential ref with broad push/pull impact.
- Medium: unpinned/mutable image in high-privilege workload or untrusted registry in sensitive namespace.
- Low: hygiene issue only, such as missing digest with low privilege and no sensitive access.
- Unknown: image list exists but registry/auth/provenance facts are missing.

Useful templates:

- `image-supply-chain-review`
- `registry-auth-verify`
- `admission-policy-review`

Output notes:

- Separate "vulnerable image" from "malicious/provenance risk".
- Highlight images that combine supply-chain risk with privileged PodSpec or high-RBAC ServiceAccount.
- Do not claim compromise from a bad tag alone.
