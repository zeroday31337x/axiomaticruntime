# ZeroDriveX Axiomatic Runtime

Standalone deterministic pre-execution control for agentic systems. Candidate actions are classified as **RETAIN**, **GATE**, or **PRUNE** before integrated side effects execute.

## Profiles
The runtime ships with a **ZDX Validated** baseline. Customers may create **Customer Modified** profiles using the same versioned schema intended for Axiomatic Universe Lite/Full import/export. Profiles are validated and SHA-256 identified before activation.

Profile customization does not change the runtime invariants: trusted execution context remains host-owned, invalid profiles fail closed, and only RETAIN may proceed to the host executor.

## Trust boundary
The profile is loaded by the runtime host, never accepted from an evaluation request. POST evaluation also requires a host-managed bearer token of at least 32 bytes. Keep this token outside model prompts and model-accessible tools. The authenticated host may assert `explicitAction`; model output must not control that field.

The host must call the runtime immediately before each consequential side effect. GATE and PRUNE are non-executable outcomes. Paths that bypass the runtime are outside its control boundary.

## Run
Set `AXIOMATIC_RUNTIME_TOKEN` to a random secret of at least 32 bytes, then:

```
npm test
npm run validate:profile
AXIOMATIC_RUNTIME_TOKEN='<secret>' node src/server.mjs
```

HTTP: unauthenticated `GET /health`; authenticated `POST /v1/evaluate`.
