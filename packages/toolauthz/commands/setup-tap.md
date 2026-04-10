---
description: Configure TAP credential proxy — gives this agent secure access to any API without exposing credentials
---

Set up TAP (Tool Authorization Protocol) so this agent can make authenticated API calls without ever seeing credential values. A proxy injects credentials after policy checks.

Do the following steps in order:

1. Ask the user for two values:
   - **Proxy URL** — suggest the default `https://agentsec.app-dfe7954892b5.enclave.evervault.com`
   - **Agent API key** — from the TAP dashboard (Agents page)

2. Write both to `.env` (create if missing, append if exists — do not duplicate keys):
   ```
   TAP_PROXY_URL=<url>
   TAP_AGENT_KEY=<key>
   ```

3. Make sure `.env` is in `.gitignore`. Add it if not.

4. Find the project instruction file — check for `SOUL.md` first, then `CLAUDE.md`. If neither exists, create `CLAUDE.md`. Append this section (if a `## TAP Credential Proxy` section already exists, replace it):

   ```
   ## TAP Credential Proxy

   All authenticated API requests MUST go through the TAP proxy. Never store, log, or hardcode credentials. Do not search for alternative ways to authenticate — always use the proxy.

   **Making a request:**
   ```bash
   curl -X POST "$TAP_PROXY_URL/forward" \
     -H "X-TAP-Key: $TAP_AGENT_KEY" \
     -H "X-TAP-Credential: <service-name>" \
     -H "X-TAP-Target: <real-api-url>" \
     -H "X-TAP-Method: GET" \
     -H "Content-Type: application/json" \
     -d '{ ... }'
   ```

   - `X-TAP-Credential` — the service name from the dashboard (e.g. `openai`, `github`, `slack`)
   - `X-TAP-Target` — usually the actual upstream URL, but some sidecar credentials use a service-specific target shape instead
   - `X-TAP-Method` — HTTP method (GET, POST, PUT, DELETE). GET is auto-approved by default; writes need human approval
   - The proxy injects the real credential and scrubs secrets from the response

   **Important:** some credentials are protocol-translating sidecars, not direct HTTP APIs. For those, do not invent vendor-native endpoints. Example: Telegram personal account uses a Telethon sidecar with relative targets like `/me`, `/dialogs`, `/messages`, `/send`, and `/reply`. Do **not** use Telegram Bot API targets like `getMe`, `getUpdates`, `sendMessage`, or `https://api.telegram.org/...` for that credential.

   **Listing available services:**
   ```bash
   curl "$TAP_PROXY_URL/agent/services" -H "X-TAP-Key: $TAP_AGENT_KEY"
   ```
   ```

5. Test the connection:
   ```bash
   source .env && curl -sf "$TAP_PROXY_URL/health"
   ```
   If it returns OK, print "Proxy is reachable." If it fails, warn the user.

6. List available services:
   ```bash
   source .env && curl -s "$TAP_PROXY_URL/agent/services" -H "X-TAP-Key: $TAP_AGENT_KEY"
   ```
   Show the user which credentials are available. If none, tell them to add credentials in the dashboard first.

7. Immediately offer connector-specific skill validation.
   - After listing the discovered credentials, ask whether the user wants to continue into service-specific TAP skill setup for all credentials or just selected ones.
   - If they say yes, continue right away using the same workflow as `/setup-tap-skill` for each chosen credential.
   - Prefer a short interactive prioritization step so the highest-value connectors get validated first.
   - Do not stop at “TAP is connected” if the user wants working service skills. Keep going until at least one concrete request works for each connector you touched.

$ARGUMENTS
