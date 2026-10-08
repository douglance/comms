# Verification

Run cargo test --workspace --locked, cargo fmt --all --check, cargo clippy --workspace --all-targets --all-features --locked -- -D warnings, and cargo check -p comms-worker --target wasm32-unknown-unknown --locked.

The Python integration tests use a local Worker and Slack emulator. Live Slack tests are opt-in mutations and require separately provisioned credentials. Local success does not establish a production OAuth grant or deployment.
