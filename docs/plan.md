# Slack agent interface implementation contract

## Outcome

Agents use one Rust Incurs CLI, HTTP surface, or MCP Code Mode interface to communicate with the owner in Slack workspace `TEXAMPLE`. Each agent has an internal pseudonymous identity; the dedicated Comms Slack app posts on its behalf. Agents do not create Slack user accounts.

## Architecture

```text
+-------------------+
| Agent CLI / MCP   |
+---------+---------+
          | scoped agent credential
          v
+-------------------+
| Comms Code Mode   |
+---------+---------+
          | schema, policy, composition
          v
+-------------------+
| Slack API runtime |
+---------+---------+
          | injected Slack grants
          v
+-------------------+
| Lance Ventures    |
| messages / reply  |
+-------------------+
```

- `comms-identity` defines owner enrollment, fresh agent identities, reusable named profiles, renewal, and revocation. Credentials use native Keychain or an injected external vault.
- `comms-slack-api` exposes bounded discovery and method schemas from pinned official docs, SDK types, and archived OpenAPI.
- `comms-slack-runtime` validates inputs, selects available supported credentials, preserves the owner's access, encodes provider calls, and records delivery claims.
- `comms-interactions` defines rich questions, signed owner replies, deadlines, cancellation, and durable resume signals.
- `comms-codemode` exposes five lifecycle tools, agent-scoped executions, and an explicit memory-only search mode.
- The Worker owns encrypted installation credentials and CONTROL records. Agent SQL and media remain separate in DATA and R2.

Owner email authentication authorizes enrollment through Cloudflare Access. Agents receive scoped Comms credentials; Slack installation credentials stay on the service. Email alone does not authorize agent enrollment.

## API and policy

Public Slack methods remain discoverable even when the workspace plan or an injected grant does not support them. Methods with incomplete schemas are marked docs-only. Channel creation, rich messages, reactions, emojis, app configuration, and supported admin operations use the same API runtime. Owner membership, roles, authentication, and recovery controls are protected.

Owner credentials are preferred for owner-visible history. Documented bot-readable methods can use the bot when the owner credential is unavailable. Search still requires its supported grant and the memory-only execution path. The memory-only execution path keeps provider search results out of its durable Code Mode journal, SQL, blobs, delivery records, and artifacts. It cannot prevent an agent from copying returned text into a separate durable call.

The existing Mancer Slack installation and credentials are preserved. Comms uses app `AEXAMPLE`.

## Acceptance

1. Fresh agent enrollments produce distinct identities; named profiles renew the same identity across processes without printing secrets.
2. Native CLI and MCP create a private Slack channel, include the owner, compose rich messages, and verify provider readback.
3. Delivery replay produces one provider message; owner-removal calls fail before provider invocation.
4. A real owner reply answers a Slack question and resumes its blocked Code Mode execution. Wrong team, author, signature, message, and stale controls are rejected.
5. Memory-only search returns a bounded projection with no matching bytes in durable SQLite or artifacts; durable search is refused.
6. Catalog metadata regenerates from the pinned official corpus, preserving stronger SDK argument schemas and explicit unresolved coverage.

## Provider gates

Local fixture acceptance, real Slack bot acceptance, production login, owner OAuth, and hosted reply/resume are separate gates. Production readiness requires a deployed exact version, real owner login, required Slack grants, and provider readback. Authentication is not weakened when provider configuration is unavailable.

## Recovery

Keep the previous Worker version for rollback. Revoke agent or enrollment credentials through CONTROL without exposing Slack installation credentials. Worker rollback does not undo Slack operations, DATA changes, or media writes.
