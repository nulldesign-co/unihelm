# Ferrum documentation

- **Operators**
  - [Installing](operator/install.md)
  - [Configuration safety](config-safety.md) — what happens when you edit a generated file
- **Developers**
  - [Architecture](architecture.md) — the two daemons, the operation registry, the config contract
  - [Contributing](../CONTRIBUTING.md) — the working agreement and the CI gates
  - [Releasing](releasing.md) — cutting a release, the minisign signing key, rotation
  - [Security policy](../SECURITY.md) — reporting, and the threat model in brief
- **API**
  - [Operations](operations.md) — every registered operation, its permission and its inputs
  - [Error codes](api/errors.md) — generated from the source
  - [API versioning](api-versioning.md) — what may change without a version bump, and what may not
- **Extending Ferrum**
  - [Webhooks](webhooks.md) — the signature scheme, the delivery guarantees and the event catalogue
  - [Plugins](plugins.md) — the sidecar contract: manifest, trust model and socket protocol

The full product specification lives at [`../FERRUM_SPEC_1.md`](../FERRUM_SPEC_1.md).
