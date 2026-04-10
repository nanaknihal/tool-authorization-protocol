# Request Cookbook

This is the public source of truth for TAP request shape.

Use it when you need to answer:

- does this connector want a full URL or a relative path?
- does it use direct injection or a sidecar?
- what is one known-good read probe?
- what kind of write request should I expect to approve?

## Core Request Shape

Every TAP request goes to the proxy:

```bash
curl -X POST "$TAP_PROXY_URL/forward" \
  -H "X-TAP-Key: $TAP_AGENT_KEY" \
  -H "X-TAP-Credential: <service-name>" \
  -H "X-TAP-Target: <target>" \
  -H "X-TAP-Method: GET"
```

The most important variable is `X-TAP-Target`.

For some connectors it is:

- a full upstream URL

For others it is:

- a relative sidecar path like `/me`

Do not guess. Check the connector behavior table and the connector code.

## Connector Classes

### 1. Direct Credentials

Use a full upstream URL in `X-TAP-Target`.

Example:

```bash
curl -X POST "$TAP_PROXY_URL/forward" \
  -H "X-TAP-Key: $TAP_AGENT_KEY" \
  -H "X-TAP-Credential: slack" \
  -H "X-TAP-Target: https://slack.com/api/auth.test" \
  -H "X-TAP-Method: GET"
```

Typical examples:

- Slack
- Mercury
- other API-key or bearer-token services

### 2. Sidecars That Still Use Full URLs

Some connectors route through a signing or OAuth helper, but still expect a full upstream URL.

Example:

```bash
curl -X POST "$TAP_PROXY_URL/forward" \
  -H "X-TAP-Key: $TAP_AGENT_KEY" \
  -H "X-TAP-Credential: twitter-personal" \
  -H "X-TAP-Target: https://api.twitter.com/2/users/me" \
  -H "X-TAP-Method: GET"
```

Typical examples:

- Twitter / X OAuth sidecars
- Google OAuth sidecars

### 3. Sidecars With Relative Targets

These are the most likely to be misused. The target is a path on the sidecar, not a vendor API URL.

Telegram personal account is the canonical example.

Correct:

```bash
curl -X POST "$TAP_PROXY_URL/forward" \
  -H "X-TAP-Key: $TAP_AGENT_KEY" \
  -H "X-TAP-Credential: telegram" \
  -H "X-TAP-Target: /me" \
  -H "X-TAP-Method: GET"
```

Also correct:

```bash
curl -X POST "$TAP_PROXY_URL/forward" \
  -H "X-TAP-Key: $TAP_AGENT_KEY" \
  -H "X-TAP-Credential: telegram" \
  -H "X-TAP-Target: /dialogs?limit=20" \
  -H "X-TAP-Method: GET"
```

Wrong:

```bash
X-TAP-Target: getMe
X-TAP-Target: /getMe
X-TAP-Target: https://api.telegram.org/...
```

Those are Telegram Bot API shapes, not the Telethon bridge used here.

## Known-Good Patterns

### Slack Read Probe

```bash
curl -X POST "$TAP_PROXY_URL/forward" \
  -H "X-TAP-Key: $TAP_AGENT_KEY" \
  -H "X-TAP-Credential: slack" \
  -H "X-TAP-Target: https://slack.com/api/auth.test" \
  -H "X-TAP-Method: GET"
```

### Google Read Probe

```bash
curl -X POST "$TAP_PROXY_URL/forward" \
  -H "X-TAP-Key: $TAP_AGENT_KEY" \
  -H "X-TAP-Credential: google-personal" \
  -H "X-TAP-Target: https://gmail.googleapis.com/gmail/v1/users/me/profile" \
  -H "X-TAP-Method: GET"
```

### Twitter Read Probe

```bash
curl -X POST "$TAP_PROXY_URL/forward" \
  -H "X-TAP-Key: $TAP_AGENT_KEY" \
  -H "X-TAP-Credential: twitter-personal" \
  -H "X-TAP-Target: https://api.twitter.com/2/users/me" \
  -H "X-TAP-Method: GET"
```

### Telegram Read Probe

```bash
curl -X POST "$TAP_PROXY_URL/forward" \
  -H "X-TAP-Key: $TAP_AGENT_KEY" \
  -H "X-TAP-Credential: telegram" \
  -H "X-TAP-Target: /me" \
  -H "X-TAP-Method: GET"
```

### Telegram Write Probe

```bash
curl -X POST "$TAP_PROXY_URL/forward" \
  -H "X-TAP-Key: $TAP_AGENT_KEY" \
  -H "X-TAP-Credential: telegram" \
  -H "X-TAP-Target: /send" \
  -H "X-TAP-Method: POST" \
  -H "Content-Type: application/json" \
  -d '{"chat":"me","message":"test message"}'
```

This should normally require approval.

## Common Errors

### `Unknown endpoint`

Usually means:

- you reached a sidecar successfully
- but you used the wrong sidecar path

Most common case:

- Telegram used with `getMe` instead of `/me`

### `403`

Usually means one of:

- the agent is not allowed to use that credential
- approval was denied
- policy blocked the request

### `Failed to load credential value`

Usually means the credential exists in config, but no actual secret value has been stored yet.

### Timeout on a Write

Usually means one of:

- approval is still pending
- the approval callback path is unhealthy
- the upstream sidecar or upstream API is hanging after approval

## Code Pointers

- target-shape routing: `crates/agentsec-proxy/src/routing.rs`
- approval flow: `crates/agentsec-bot/src/telegram.rs`
- proxy wait behavior: `crates/agentsec-proxy/src/proxy.rs`
- telegram sidecar endpoints: `scripts/telegram_sidecar.py`
- twitter signer behavior: `crates/agentsec-signer/src/main.rs`
- google oauth refresh path: `crates/agentsec-proxy/src/google_oauth.rs`

## Request Flow

```text
Agent
  -> POST /forward
  -> TAP checks credential + policy
  -> routing decides full URL vs sidecar path
  -> approval may block writes
  -> request is forwarded
  -> response is sanitized
  -> result returns to agent
```
