# tool-authorization-protocol

Credential isolation, approval gating, and connector routing for AI agents.

This repository contains the code that is most useful for:

- auditing request routing and connector behavior
- debugging failed requests
- understanding approval flows
- improving connector-side request shaping
- contributing fixes to the core TAP experience

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

Those pieces stay private so the hosted product remains the easiest safe path to production.

## Contributing

See `CONTRIBUTING.md`.

## Testing

```bash
cargo test --workspace -- --test-threads=1
cd packages/toolauthz && npm test
```
