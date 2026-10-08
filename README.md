# comms

A Slack CLI and MCP interface for agent swarms, written in Rust. Agents enroll with their own reusable identity, choose a session name and icon, discover Slack APIs, compose rich messages, and wait for owner replies in Slack.

## Linear work management

Agents with an installed Linear app can use their own identity through the same CLI, MCP, and Code Mode catalog:

```sh
comms linear me --format json
comms linear query --query '{ viewer { id name } organization { urlKey } }' --format json
comms linear inbox --cursor 0 --limit 20 --format json
```

Queries accept GraphQL variables and caller-selected fields, including issue parents and children. MCP and Code Mode expose `comms.linear_me`, `comms.linear_query`, and `comms.linear_inbox`. Each agent needs a distinct Linear OAuth application for a distinct assignable identity; minting extra tokens for one application does not create extra identities. See [Cloud setup](docs/cloud-setup.md) for app enrollment, hosted callbacks, webhook configuration, and transfer after credential renewal.

## Install

With a current stable Rust toolchain:

```sh
cargo install --git https://github.com/douglance/comms --tag v0.1.1 --locked comms-cli
comms --help
```

Linux x86_64 binaries and checksums are published on the [releases page](https://github.com/douglance/comms/releases). Source installation also supports macOS and other Rust-supported hosts.

## Connect an agent

The CLI requires a reachable, separately configured Comms backend. Public source and binaries contain no workspace credentials. Set COMMS_URL to your deployment; the default example URL is a placeholder.

An owner authenticates through Cloudflare Access and creates a reusable swarm enrollment. Provision its secret through your secret manager as COMMS_ENROLLMENT_SECRET. Give concurrent agents distinct COMMS_PROFILE values. On macOS credentials persist in Keychain; on headless hosts configure COMMS_VAULT_EXECUTABLE as described below.

```sh
export COMMS_URL=https://your-comms.example.com
export COMMS_PROFILE=builder-01
# Inject COMMS_ENROLLMENT_SECRET and configure a vault without printing secrets.
comms profile join --profile "$COMMS_PROFILE" --label "$COMMS_PROFILE" --format json
comms agent whoami --format json
comms slack session start --session-id build-01 --name Builder --icon-emoji ":hammer:" --title "Build task" --format json
comms slack session send --session-id build-01 --text "Hi! Starting work." --idempotency-key hello --format json
```

A Comms identity is a pseudonym behind the shared Slack app, not a separate Slack user account. Agents share the app's channel access. A named profile renews an existing identity; distinct session IDs support separate tasks with chosen names and icons. Do not distribute owner credentials or Slack bot tokens to agents.

## Collaborate and check Slack

```sh
comms slack search --query "channel history" --limit 5 --max-bytes 4096 --format json
comms slack inspect --method conversations.history --format json
comms slack invoke --method conversations.history --params '{"channel":"CHANNEL_ID","limit":10,"oldest":"LAST_SEEN_TS"}' --format json
comms slack session send --session-id build-01 --channel CHANNEL_ID --text "Ready for review." --idempotency-key ready --format json
comms slack session send --session-id build-01 --channel CHANNEL_ID --thread-ts MESSAGE_TS --text "Reviewed." --idempotency-key review --format json
```

Agent runtimes should check Slack at the start of every existing heartbeat, read a bounded set of new messages, and persist a last-seen cursor after processing. Reply or act when needed. Greet once during onboarding. The CLI does not create heartbeat timers or autonomously schedule agents.

Omit --channel to send to the owner's session thread. Supply --channel for a channel message, and --thread-ts for a reply. Saved session names and icons apply to all three. Delivery keys are agent-scoped; changing input with the same key conflicts.

## Rich questions and Code Mode

```sh
comms question create --text "Ship this build?" --choices '[{"id":"yes","text":"Ship","value":"yes"},{"id":"no","text":"Hold","value":"no"}]' --idempotency-key ship-01 --blocking --format json
comms question wait --id QUESTION_ID --format json
comms code search --query "human.ask" --format json
comms --mcp
```

MCP exposes codemode_search, codemode_execute, codemode_execution, codemode_decide, and codemode_cancel. Search for tools, then compose calls in JavaScript. Signed owner replies and Slack controls can resume durable questions. Memory-only search uses COMMS_CODEMODE_RETENTION=memory or --zero-retention; it cannot suspend for owner input.

The registry covers Web API, Legal Holds, SCIM, Audit Logs, and Slack Status. A listed method is not an OAuth grant: plan, token class, scope, and provider restrictions still apply. Owner-protection checks precede transport.

## Headless credential vault

Set COMMS_VAULT_EXECUTABLE to a vault bridge that reads a JSON request from stdin:

```json
{"op":"load","service":"comms.slack.agent","account":"BASE_URL:PROFILE:KIND","kind":"agent"}
```

Operations are load, save, and delete. Save includes secret; load returns {"secret":"..."} or null. Nonzero exit fails the operation. Secrets never enter child arguments. The bridge manages authentication and encryption. There is no plaintext credential-file fallback. COMMS_TOKEN supports externally managed ephemeral credentials.

The included [Python bridge](scripts/comms_vault.py) uses AES-256-GCM and requires Python 3 with the `cryptography` package. Install that dependency in your managed Python environment, make the bridge executable, and set COMMS_VAULT_EXECUTABLE to its absolute path. Provision COMMS_VAULT_KEY as a base64url-encoded random 32-byte key through an external secret manager. Keep the key separate from the encrypted files. COMMS_VAULT_DIR optionally selects the vault directory; the default is ~/.local/share/comms/vault. Processes sharing a vault must use the same key and distinct profiles. The key grants access to every profile in that vault.

Every new shell or process must supply its COMMS_PROFILE, COMMS_URL, and COMMS_VAULT_EXECUTABLE. Unset inherited COMMS_TOKEN and COMMS_OWNER_TOKEN when using saved profiles, since those environment credentials override the profile.

## Architecture

```text
+----------------------+
| Agent CLI / MCP      |
+----------+-----------+
           | authenticated calls
           v
+----------------------+
| Comms backend        |
| Identity + Code Mode |
+----------+-----------+
           | policy-checked API
           v
+----------------------+
| Shared Slack app     |
+----------+-----------+
           | messages and replies
           v
+----------------------+
| Owner and agent peers|
+----------------------+
```

| Crate | Responsibility |
| --- | --- |
| comms-cli | CLI, HTTP client, profiles, secure vault adapter |
| comms-core | Shared SQL and media contracts |
| comms-identity | Enrollment and agent credentials |
| comms-slack-api | Schemas and bounded documentation discovery |
| comms-slack-runtime | Validation, transport, owner protection |
| comms-interactions | Questions, Slack signatures, answers |
| comms-codemode | JavaScript composition and MCP |
| comms-worker | Cloudflare backend and durable state |

## Develop

```sh
cargo test --workspace --locked
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo check -p comms-worker --target wasm32-unknown-unknown --locked
```

See [Cloud setup](docs/cloud-setup.md), [verification](docs/verification.md), and [Slack schema provenance](docs/slack/README.md). Wrangler configurations contain example identities and resource IDs. Live Slack tests are opt-in mutations. Local emulator tests do not prove production authentication or Slack grants.

## License

MIT. Vendored dependencies retain their own licenses. Downloaded Slack documentation and schemas retain their upstream terms and attribution; the project license does not relicense them.
