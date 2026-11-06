# JEV decision matrix, trees, and distillation

## Security authority
The deterministic Axiomatic Runtime host policy remains authoritative. The JEV three-class prediction is advisory. A model must never elevate host GATE or PRUNE to RETAIN. An unavailable, invalid, or uncertain model prediction gates a host RETAIN decision. Unknown host decisions are rejected by the runtime adapter.

## Executable matrix
`decision-matrix.mjs` enumerates the complete finite 3 x 4 host/prediction state space (12 paths). `test/decision-matrix.test.mjs` checks all paths, monotonicity, and agreement with the existing adapter. The matrix is the reference specification, not a second enforcement implementation.

## Decision trees
Build domain-specific trees for authentication, route policy, resource ownership, rate limits, and malformed inputs. Every node must specify its input domain, missing-value behavior, and fail-closed branch. Exhaustive enumeration is possible only for bounded categorical state spaces. Continuous values, arbitrary paths, and combinations of unbounded request fields require equivalence partitions, boundary tests, fuzzing, and property-based testing.

## Distillation data
Derive deterministic labels from the policy engine, but retain provenance and policy version on each record. Generate adversarial and ambiguous examples separately. Use a larger teacher model for soft targets and candidate examples, not for ground-truth policy authority. Human-reviewed independent holdouts must remain excluded from teacher prompts and training. Split by scenario family to avoid leakage.

## Promotion gates
Keep the current experimental model in checksum-pinned shadow mode. Require independent validation of false ALLOW on DENY cases, false DENY on ALLOW cases, per-class recall, calibration, latency, peak RSS, and behavior under model outages before considering enforcement. Synthetic smoke tests and the 12-path matrix do not establish real-world model accuracy.
