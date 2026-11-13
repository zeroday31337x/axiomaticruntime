import { enumeratePaths } from './decision-tree-compiler.mjs';
import { writeFileSync } from 'node:fs';

// Generates deterministic policy fixtures for regression testing.
// Final host actions are NOT interchangeable with JEV ALLOW/DENY/FLAG labels.
const rows = enumeratePaths().map((p, i) => ({
  schemaVersion: '1',
  source: 'deterministic-policy-matrix-v1',
  policyVersion: 'decision-tree-v1',
  scenarioGroup: 'policy-' + i,
  inputs: { host: p.host, jev: p.jev, authenticated: p.authenticated,
    routeAllowed: p.routeAllowed, rateLimited: p.rateLimited },
  expectedHostAction: p.final,
}));
const data = rows.map(row => JSON.stringify(row)).join('\n') + '\n';
if (process.argv[2]) writeFileSync(process.argv[2], data, { flag: 'wx', mode: 0o600 });
else process.stdout.write(data);
