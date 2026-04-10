# tool-authorization-protocol

Credential isolation, approval gating, and connector routing for AI agents.

This repository contains the code that is most useful for:

- auditing request routing and connector behavior
- debugging failed requests
- understanding approval flows
- improving connector-side request shaping
- contributing fixes to the core TAP experience

## Start Here

- `docs/request-cookbook.md` — exact request shapes for direct credentials, full-URL sidecars, and relative-path sidecars
- `docs/connector-matrix.md` — compact connector behavior table with code pointers
- `packages/toolauthz` — local setup and skill-install workflows
- `crates/agentsec-proxy/src/routing.rs` — how TAP resolves connector target shapes
- `scripts/telegram_sidecar.py` — an example of a custom sidecar-backed connector

## Included

- core proxy and storage crates
- Telegram approval bot
- OAuth signer
- CLI
- `@nnsk/tap` setup package
- connector-side bridge code needed to understand runtime behavior

## Not Included

- hosted dashboard code
- enclave deployment code
- production workflows and secret bootstrapping
- managed hosting operations glue

Hosted deployment and operational infrastructure are maintained separately from this repository.

## Contributing

See `CONTRIBUTING.md`.

## Testing

```bash
cargo test --workspace -- --test-threads=1
cd packages/toolauthz && npm test
```
