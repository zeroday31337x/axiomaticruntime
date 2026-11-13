# JEV decision adapter — experimental

The adapter in `src/jev-adapter.mjs` combines the existing host-owned Axiomatic Runtime decision with an optional JEV classification. It does not invoke a model or change the production server.

| Host decision | JEV ALLOW | JEV DENY | JEV FLAG / missing |
| --- | --- | --- | --- |
| RETAIN | RETAIN | PRUNE | GATE |
| GATE | GATE | GATE | GATE |
| PRUNE | PRUNE | PRUNE | PRUNE |

The host must authenticate and authorize requests and execute the deterministic profile evaluation first. Model output cannot set explicitAction or change policy. GATE and PRUNE never execute. For the future gateway/router, use the same three-way model classification but separate authentication, policy, rate limits, and execution enforcement. Invalid model output or timeout must not grant access.

Initial deployment target: CPU-only 100–250M-parameter classifier, 2 vCPU and 1 GB RAM, subject to measured performance and memory usage. Potential optimization target: 1 vCPU and 512 MB.

Next: versioned inference interface, strict schema validation, request sanitization, bounded timeouts, audit metadata, container build, benchmark suite, and opt-in integration behind a feature flag. No production deployment until reviewed and tested.
