# JEV distillation data contract

The current dataset generator enumerates 96 finite security-policy combinations and produces `task: host_action` records labeled RETAIN, GATE, or PRUNE. It is for deterministic regression, policy-student experiments, and consistency checks; it is **not** valid input to the current three-class JEV trainer, which expects ALLOW/DENY/FLAG.

The records contain scenario IDs, provenance, policy version, and a stable train/holdout partition. Because the 96 cases share one small finite policy, this holdout checks implementation consistency only; it does not estimate generalization to unseen security traffic.

Teacher model suggestions must be stored as `task: jev_classification`, `labelSource: teacher_candidate`, `approvalStatus: unreviewed`, and a scenario-family group. The candidate validator intentionally rejects teacher examples marked approved: approval requires a separate review process, not a field flip. Teacher-generated soft targets and rationales are not ground truth.

Before training JEV, create a reviewed, independently labeled ALLOW/DENY/FLAG corpus with policy-consistent definitions, scenario-family split isolation, adversarial and malformed inputs, and an untouched evaluation set. Do not distill from confidential request payloads or secrets. Enforce the host policy independently at runtime.

To generate the policy corpus from Node:
```sh
node --input-type=module -e "import { generatePolicyDataset, exportJsonl } from './jev-service/distillation-dataset.mjs'; process.stdout.write(exportJsonl(generatePolicyDataset()))" > policy-fixtures.jsonl
```
