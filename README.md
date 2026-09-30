# ZeroDriveX Axiomatic Runtime

Standalone deterministic pre-execution control for agentic systems. Candidate actions are classified as **RETAIN**, **GATE**, or **PRUNE** before integrated side effects execute.

## Profiles
The runtime ships with a **ZDX Validated** baseline. Customers may create **Customer Modified** profiles using the same versioned schema intended for Axiomatic Universe Lite/Full import/export. Profiles are validated and SHA-256 identified before activation.

Profile customization does not change the runtime invariants: trusted execution context remains host-owned, invalid profiles fail closed, and only RETAIN may proceed to the host executor.

## Integration boundary
The host must call the runtime immediately before each consequential side effect. GATE and PRUNE are non-executable outcomes. Paths that bypass the runtime are outside its control boundary.

## Run
```
npm test
npm run validate:profile
node src/server.mjs
```

HTTP: `GET /health`, `POST /v1/evaluate`.
