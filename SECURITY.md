# Security Policy

KubeTrail is intended only for authorized Kubernetes security assessment,
defensive validation, and research in environments where the operator has
explicit permission.

## Reporting Vulnerabilities

Please report vulnerabilities privately by opening a GitHub security advisory
for this repository, or by contacting the maintainers through the repository
owner profile.

Do not include live credentials, kubeconfigs, ServiceAccount tokens, cloud
tokens, production scan outputs, or customer data in public issues or pull
requests. If evidence is required, provide a minimal synthetic reproduction.

## Supported Versions

Until the project reaches a stable release, only the current `main` branch is
supported for security fixes.

## Sensitive Data Handling

KubeTrail can collect or process sensitive assessment material, including
Kubernetes tokens, kubeconfigs, pod environment variables, registry hints, and
cloud metadata signals. Treat all scan output as sensitive unless it was
generated from a synthetic lab.

Before sharing logs, screenshots, JSON results, or generated EXP bundles:

- remove bearer tokens, kubeconfigs, private keys, and cloud credentials;
- prefer `--sensitive metadata` or `--sensitive redact` for shareable output;
- avoid posting target hostnames, internal domains, cluster names, IP ranges,
  namespaces, and ServiceAccount names unless they are synthetic.

## Responsible Use

Do not use KubeTrail against systems you do not own or do not have explicit
authorization to test. Some features can create Kubernetes resources, validate
privileged workload admission, generate kubeconfigs, or render proof-of-concept
materials. Use those features only in authorized test scopes and clean up any
created resources.
