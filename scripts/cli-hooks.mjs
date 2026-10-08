import { readFileSync } from 'node:fs';
const full = process.env.COMMS_SLACK_FULL_MANIFEST === '1';
const hooks = {"runtime":"node","hooks":{"get-hooks":"node scripts/cli-hooks.mjs","get-manifest":"node scripts/cli-hooks.mjs manifest","start":"python3 scripts/slack_runtime_hook.py"},"config":{"sdk-managed-connection-enabled":true}};
const output = process.argv[2] === 'manifest'
  ? JSON.parse(readFileSync(full ? 'slack-app-manifest.json' : 'slack-app-bootstrap-manifest.json', 'utf8'))
  : hooks;
process.stdout.write(JSON.stringify(output));
