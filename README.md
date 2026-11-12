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


## Runtime hardening (development branch)

- Every proposal must declare its kind: reply, command, or tool. Unknown or
  malformed proposals are PRUNE, and bad profiles fail closed at startup and
  at the library evaluation boundary.
- The runtime checks canonical allowlists, bounds, suspicious shell syntax, and
  requires host-owned explicit authorization for mutating tools and commands.
- The API caps JSON request bodies at 1 MiB and enforces request and header
  timeouts. Only the host supplies the active policy; request input cannot
  replace it.
- A RETAIN decision is not a substitute for per-tool argument validation,
  host identity/entitlement checks, command-argument separation, and
  authorization immediately before every consequential side effect.
- No simulation gravity/truth-field metric is used for authorization.
- The validated baseline profile and versioned profile schema identity
  remain unchanged. Untrusted/custom profiles must be independently validated.

Run npm test and npm run validate:profile.
