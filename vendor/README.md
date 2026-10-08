# Vendored Incurs snapshot

This directory vendors the minimal Incurs crates needed by `comms` so the checkout builds without a sibling `../comms-incurs-media` path.

Source snapshot:

- Upstream checkout: `the upstream Incurs checkout`
- Base SHA: `4c9eb9b26f3c802b5d5318df7e14e279c9002b7a`
- Local patch provenance: includes the working-tree audio/resource changes in `crates/incurs/src/command.rs` and `crates/incurs/src/mcp/shared.rs` from that checkout.
- License: MIT, copied from upstream into `vendor/incurs/LICENSE`.

Included crates:

- `incurs`
- `incurs-macros`
- `incurs-mcp-protocol`

The vendored snapshot keeps source files, manifests, protocol schema JSON, README, and license material. Tests and examples are omitted; the vendored `incurs` manifest removes the upstream example declarations so normal dependency builds do not require omitted example files.
