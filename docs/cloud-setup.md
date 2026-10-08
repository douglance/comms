# Cloud setup

Configure your own Cloudflare account, D1 DATA and CONTROL databases, private R2 MEDIA bucket, and Slack OAuth app. The Wrangler files contain example IDs, not provisioned resources. Replace account and database IDs before deployment.

Set OWNER_EMAIL, OWNER_SLACK_ID, SLACK_TEAM_ID, SLACK_CLIENT_ID, ACCESS_TEAM_DOMAIN, and ACCESS_AUD for your deployment. Store Slack tokens, signing secret, client secret, and credential encryption keys with Wrangler secrets; never commit them. Cloudflare Access must restrict the owner browser flow to your owner email.

Build the Worker with worker-build and apply migrations/control to CONTROL. Set COMMS_URL on clients to the deployed HTTPS origin. Local fixtures use example identities and loopback-only authentication.

## Linear applications

Set `COMMS_PUBLIC_URL` to your Worker's stable HTTPS origin, without a path, query, or fragment. Apply all CONTROL migrations, including `0006_linear.sql` and `0007_linear_transfer.sql`. Store `LINEAR_SEAL_KEY` as a Wrangler secret containing an unpadded base64url encoding of 32 random bytes. Keep a protected backup of this key; changing it without re-encrypting stored credentials makes those credentials unreadable.

Create a private Linear OAuth application for each agent identity. Set its name to the agent's exact role title, enable client credentials, and register `https://your-comms.example.com/linear/oauth/callback` using your real origin. Application creation happens in Linear separately from Comms enrollment. The broker requests `read,write,app:assignable,app:mentionable`; it does not grant workspace administration rights.

Using owner authorization, submit `POST /owner/linear/apps` with `agent_id`, `role`, `workspace_slug`, `client_id`, `client_secret`, and optional `webhook_secret`. Transmit credentials directly over HTTPS from a protected credential store. Do not place secrets in command arguments, checked-in files, or logs. Comms verifies the provider's actual app-user name and workspace before binding the app to the active agent profile. App credentials are encrypted with agent-specific authenticated data; agents receive query results, not app secrets. `GET /owner/linear/apps` returns nonsecret binding metadata.

For an owner authorization flow, visit authenticated `/owner/linear/install?agent_id=AGENT_ID`. Comms uses a single-use, expiring state and the hosted callback. Agents do not need localhost callback servers. Temporary provider access tokens are revoked after each provider operation, including failed operations. If cleanup fails after a successful operation, the result includes `extensions.comms_token_cleanup`; do not replay a completed mutation to retry token cleanup.

Configure each application's webhook in Linear using its returned `webhook_url` and supply its signing secret during enrollment. The endpoint verifies the signature, timestamp, organization, and duplicate event before storage. Live event delivery requires this separate provider configuration. Read events with `comms linear inbox`, persist the returned cursor, and request only the needed page. Missing app bindings fail rather than falling back to another agent's identity.

## Transfer after agent credential renewal

Renewing a Comms profile can replace its agent ID. An owner can move an existing Linear binding with `POST /owner/linear/apps/transfer`, supplying `from_agent_id` and `to_agent_id`. The destination must be active, use the same profile name, and have no existing Linear binding. This operation re-encrypts app credentials for the replacement agent, preserves the Linear app-user identity and event cursor history, and discards pending OAuth states. Other profiles, expired or revoked destinations, and missing destinations are rejected.

After transfer, use the returned metadata to update the application's webhook URL because it contains the agent ID. Verify `comms linear me` using the replacement credential before resuming work. The previous agent ID no longer has the binding. Transfer is an owner operation and does not create a new Linear application.
