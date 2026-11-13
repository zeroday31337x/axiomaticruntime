# JEV offline training and validation

The first experimental trainer is a small three-class linear model, **not** a 100–250M-parameter neural network. It is useful for testing data contracts, model loading and validation, but cannot establish a secure gateway classifier from a handful of examples.

Input: JSONL records with independently reviewed `context.route`, `context.method`, `label` (ALLOW, DENY, FLAG), and a stable `group` representing one scenario family. Do not include bearer tokens, secrets, user data, or raw request bodies.

Run: `python3 jev-service/train.py --data /private/jev-labeled.jsonl --out /private/jev-experimental.json`.

The trainer uses deterministic group-wise holdout and reports a confusion matrix, accuracy, and false-ALLOW count/rate. Training never approves the model automatically. For security review, require independent adversarial evaluation, class-specific false-ALLOW analysis, calibration, distribution-shift tests, provenance and integrity of model artifacts, and manual approval before deployment.

The Node service still defaults to a conservative rules-only placeholder. Experimental weights are **not** loaded automatically. No production JEV inference should be enabled from this script alone.
