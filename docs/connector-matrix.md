# Connector Matrix

Use this table before guessing request shape.

| Connector | Typical auth mode | Target shape | Known-good read | Known-good write | Approval behavior | Code pointer |
|---|---|---|---|---|---|---|
| `slack` | direct / auth header | full URL | `https://slack.com/api/auth.test` | Slack write endpoint | reads usually auto-approved, writes usually require approval | `crates/agentsec-proxy/src/routing.rs` |
| `mercury` | direct / auth header | full URL | Mercury accounts endpoint | Mercury write endpoint | reads auto-approved by policy, writes gated | `crates/agentsec-proxy/src/routing.rs` |
| `google-*` | oauth sidecar | full URL | Gmail profile endpoint | Gmail send or other Google write | reads often auto-approved, writes policy-dependent | `crates/agentsec-proxy/src/google_oauth.rs` |
| `twitter-*` | oauth sidecar / signer | full URL | `https://api.twitter.com/2/users/me` | `https://api.twitter.com/2/tweets` | writes usually require approval | `crates/agentsec-signer/src/main.rs` |
| `telegram` | oauth sidecar / bridge | relative path | `/me`, `/dialogs?limit=20` | `/send`, `/reply` | reads can auto-approve, writes usually require approval | `scripts/telegram_sidecar.py` |

## Notes

- `target_is_relative_path=true` means `X-TAP-Target` is a sidecar path, not a vendor URL.
- If a connector is custom or unusual, inspect its code before documenting or automating request shape.
- When in doubt, create or update a service-specific TAP skill and validate one real read request before trusting the connector.
