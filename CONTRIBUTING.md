# Contributing

Contributions are welcome when they improve authorized Kubernetes assessment,
defensive validation, documentation, or project reliability.

## Ground Rules

- Do not submit real credentials, kubeconfigs, tokens, scan outputs, customer
  data, private cluster names, or internal hostnames.
- Use synthetic fixtures for tests and examples.
- Keep exploit and persistence content framed around authorization, validation,
  cleanup, and evidence. Avoid adding destructive payloads or live third-party
  infrastructure callbacks.
- Preserve existing safety defaults. Side-effecting features should require
  explicit user action and clear cleanup guidance.

## Development Checks

Run these before opening a pull request:

```bash
go test ./...

cd apps/agent
npm ci
npm run build

cd ../desktop/frontend
npm ci
npm run build

cd ../../..
git diff --check
```

For dependency or release changes, also run:

```bash
npm audit --audit-level=moderate --registry=https://registry.npmjs.org
```

from each npm package directory.

## Pull Requests

Please include:

- a short summary of behavior changes;
- test/build commands that were run;
- any new side effects, permissions, network requests, or cleanup steps;
- third-party source URLs and licenses for any added public PoC, dataset, font,
  image, or generated asset.
