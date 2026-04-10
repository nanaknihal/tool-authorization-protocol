---
description: Create or refine a service-specific TAP skill by iterating until at least one real request works
---

Pick one TAP credential or connector and turn it into a concrete, local skill that future agents can actually use without guessing.

Do this workflow in order:

1. Start with a short interactive check-in.
   - If the user did not already name the service, list available services from `/agent/services` and ask which one should be turned into a tested skill first.
   - Ask what the user wants the agent to actually do with it first: read, write, or both.
   - Ask whether to stop after a working read probe or continue until a write flow is also proven.
   - Keep this interactive step short and concrete. Prefer 1 to 3 focused questions, not an open-ended interview.

2. Gather the exact runtime facts before writing guidance.
   - Check the service entry from `/agent/services` for `auth_mode`, `target_is_relative_path`, and approval behavior.
   - If a service-specific local skill already exists, read it first.
   - Inspect the real connector implementation or sidecar code if the credential is unusual.

3. Create or update a service-specific skill file in the local project/context.
   - The skill must contain the exact request shape the agent should use.
   - Include at least one known-good read example.
   - If writes are supported, include one write example and say whether approval is expected.
   - Include a short “Pitfalls” section with the concrete mistakes an agent is likely to make.

4. Validate the skill with a real request before considering it done.
   - Prefer a lightweight read endpoint.
   - If the first attempt fails, debug and update the skill.
   - Do not stop at a generic template if the request has not been proven to work.
   - If the user asked for write validation too, carry the flow through a real write request and its approval path where practical.

5. Only finish when the skill is effective.
   - Effective means at least one real request succeeded and the skill now reflects the working request shape.
   - If the service is currently broken server-side, say so explicitly and write the skill around the best-known working constraints instead of pretending the setup is complete.

Strong guidance:

- Do not rely on vendor intuition when the connector is custom.
- Do not assume full URLs are correct for sidecars; verify whether the target is relative.
- Do not assume Bot API / SDK / REST API conventions if the connector is actually a bridge.
- Prefer concrete examples over abstract descriptions.
- If you see an error like `Unknown endpoint`, determine whether it came from the proxy, the sidecar, or the upstream API before documenting the fix.

Deliverable:

- A tested skill for exactly one service, plus a short note to the user saying what was validated and what still is not proven.

$ARGUMENTS
