# Security notes

Do not commit enrollment secrets, bearer credentials, Slack tokens, signing secrets, private keys, or local Slack and Wrangler state. Public configuration files contain example resource IDs and identities. Configure your deployment separately.

## Dependency audit, 2026-10-07

Cargo audit reports RUSTSEC-2023-0071 for rsa 0.9.10. The CLI dependency graph contains no rsa dependency. The Worker imports RsaPublicKey and pkcs1v15::VerifyingKey exclusively for verifying Cloudflare Access signatures. It performs no RSA private-key decryption or signing, which are the operations implicated by the private-key recovery advisory. No patch is currently listed in the advisory database. This is a documented reachability exception, not a claim that cargo audit has no findings.

Run cargo audit --ignore RUSTSEC-2023-0071 to check for additional findings. Reassess the exception by 2026-11-07 or before adding any RSA private-key operation. See https://rustsec.org/advisories/RUSTSEC-2023-0071.html.

The secret scanner excludes only official Slack example material in docs/slack/raw/llms-full.txt and crates/comms-slack-api/data/docs_index.json. Application code, configuration, and other files remain scanned.
