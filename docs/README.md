# Ferrum documentation

- **Operators**
  - [Installing](operator/install.md)
  - [The `ferrum` command line](operator/cli.md) — every operation, `--json`, exit codes, completions
  - [Configuration safety](config-safety.md) — what happens when you edit a generated file
- **Developers**
  - [Architecture](architecture.md) — the two daemons, the operation registry, the config contract
  - [Contributing](../CONTRIBUTING.md) — the working agreement and the CI gates
  - [Releasing](releasing.md) — cutting a release, the minisign signing key, rotation
  - [Security policy](../SECURITY.md) — reporting, and the threat model in brief
- **API**
  - [Operations](operations.md) — every registered operation, its permission and its inputs
  - [Error codes](api/errors.md) — generated from the source

The full product specification lives at [`../FERRUM_SPEC_1.md`](../FERRUM_SPEC_1.md).
