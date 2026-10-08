# Slack API corpus

Pinned official Slack docs and SDK sources were retrieved on 2026-10-06. Archived OpenAPI is retained as a fallback and identified by its source receipt.

| Coverage | Count |
| --- | ---: |
| Web API methods | 350 |
| SCIM v1/v2 operations | 32 |
| Audit Logs operations | 3 |
| Legal Holds methods | 9 |
| Slack Status endpoints | 2 |
| Combined registry operations | 396 |
| SDK argument schemas | 280 |
| OpenAPI fallback schemas | 12 |
| Schema-backed methods total | 292 |
| Web API docs-only methods | 58 |
| Supplemental operations with documentation-derived schemas | 46 |
| Documentation index entries | 9,456 |
| Pinned SDK TypeScript files | 56 |

`source-manifest.json` records source URLs, retrieval times, revisions, and digests. The public corpus includes the searchable documentation index, sitemap, archived OpenAPI schemas, and SDK source files. The full upstream prose archive, `raw/llms-full.txt`, is retained locally and excluded from public Git snapshots because vendor examples can contain credential-shaped strings. Executable API catalogs and schemas remain included. Current method facts supply token types, scopes, encoding, and rate metadata; SDK argument schemas replace archived string encodings with typed arrays and objects. The supplementary request-source receipt is `raw/sdk/sdk-request-supplement.json`.

The SDK parser handles argument inheritance, object fields, arrays, unions, Partial, and Pick. Shared Block Kit and view objects remain open objects to bound expansion; unresolved types are marked in each schema. This is partial TypeScript conversion, not complete JSON Schema or Slack payload validation. Slack validates the full payload.

Docs-only methods remain inspectable and accept generic JSON through the same policy layer. Missing schemas and provider grants are explicit limitations.

Run `cargo test -p comms-slack-api` to validate the shipped catalog. Source-regeneration checks (`python3 scripts/slack_sources.py --catalog-check` and `python3 tests/slack_catalog_generation.py`) require the ignored local `raw/llms-full.txt` archive from the source receipt; they do not run against the public snapshot alone. `--catalog-ops` emits griz operations and regenerates pinned method facts without writing source files.

## REST families

The registry also includes all 32 operations from the [SCIM v1/v2 reference](https://docs.slack.dev/reference/scim-api/) and the three [Audit Logs endpoints](https://docs.slack.dev/reference/audit-logs-api/methods-actions-reference/). These references were inspected on 2026-10-06. They have separate canonical REST origins, HTTP verbs, and credential classes; they are not Web API method aliases.

SCIM names use `scim.v1` or `scim.v2`, followed by `users`, `groups`, `schemas`, `config`, or `resource_types`. User/group operations are `list`, `get`, `create`, `update` (PATCH), `replace` (PUT), and `delete`. Item calls take `id`; writes take a JSON `body`, which is sent without the invocation envelope. Audit operations are `audit.actions.list`, `audit.schemas.list`, and `audit.logs.list`.

Inject `SLACK_SCIM_TOKEN` and `SLACK_AUDIT_TOKEN` for authenticated calls. Audit actions and schemas omit authorization and do not require an Audit Logs credential. Owner-account SCIM writes are denied before transport. Resource IDs cannot alter the route. JSON `body` envelopes are partial schemas; Slack validates the complete attributes and patch operations.

## Legal Holds and Slack Status

The registry adds nine `admin.legalHold.*` methods from the [Legal Holds reference](https://docs.slack.dev/reference/legal-holds-api-reference/), inspected on 2026-10-06. The singular `legalHold` spelling follows the documented method URLs. They use an Admin credential and form-encoded POST bodies, with custodian arrays encoded as JSON field values. The argument schemas follow the documented tables; they are marked documentation-only rather than attributed to the SDK or archived OpenAPI.

`status.current` and `status.history` use the unauthenticated [Slack Status v2 endpoints](https://docs.slack.dev/reference/slack-status-api/). Their canonical origin is `https://slack-status.com`, and neither sends an Authorization header. The history response is an array.

Legacy catalog coverage value `schema` denotes the archived OpenAPI, while `sdk-schema` denotes the current SDK snapshot. Tests independently count the loaded records for each source category and compare them with the coverage report.

## Before publication

Run `python3 scripts/check_publication.py --self-test` and `python3 scripts/check_publication.py` before creating a public snapshot or pushing it. The check rejects the raw prose archive and Slack token or webhook credential shapes in tracked files and nonignored new files. It reports only paths, line numbers, and pattern categories. Keep raw downloads local; publishing them requires sanitization and a fresh check. Upstream retrieval digests in `source-manifest.json` describe the original downloaded sources, not sanitized public example text.
