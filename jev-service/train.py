#!/usr/bin/env python3
"""Offline experimental 3-class linear classifier trainer (stdlib only).
Input JSONL records: {"context":{"route":"/...","method":"GET"},
"label":"ALLOW|DENY|FLAG","group":"independent-case-id"}.
Labels must be independently reviewed; never derive ground truth from host decisions.
This does not produce a production-approved security model.
"""
import argparse
import hashlib
import json
import math
from pathlib import Path

CLASSES = ["ALLOW", "DENY", "FLAG"]
FEATURES = ["bias", "method_get", "method_write", "route_health", "route_admin",
            "route_auth", "route_unknown", "route_suspicious"]

def vector(context):
    route, method = context.get("route"), context.get("method")
    if not isinstance(route, str) or not route.startswith("/") or len(route) > 2048:
        raise ValueError("invalid route")
    if method not in ("GET", "POST", "PUT", "PATCH", "DELETE"):
        raise ValueError("invalid method")
    import re
    suspicious = bool(re.search(r"[\\\x00-\x1f]|\.\.|%2f|%5c|%00", route, re.I))
    return [1, int(method == "GET"), int(method != "GET"),
            int(route in ("/health", "/v1/health")), int(route.startswith("/admin")),
            int(route.startswith("/auth")),
            int(route not in ("/health", "/v1/health") and not route.startswith(("/admin", "/auth"))),
            int(suspicious)]

def softmax(values):
    m = max(values)
    z = [math.exp(v - m) for v in values]
    return [v / sum(z) for v in z]

def evaluate(weights, records):
    matrix = {label: {pred: 0 for pred in CLASSES} for label in CLASSES}
    for x, y in records:
        scores = [sum(a * b for a, b in zip(row, x)) for row in weights]
        pred = CLASSES[max(range(3), key=lambda i: scores[i])]
        matrix[CLASSES[y]][pred] += 1
    n = len(records)
    correct = sum(matrix[c][c] for c in CLASSES)
    false_allow = sum(matrix[c]["ALLOW"] for c in ("DENY", "FLAG"))
    return {"samples": n, "accuracy": correct / n if n else None,
            "falseAllowCount": false_allow, "falseAllowRate": false_allow / n if n else None,
            "confusion": matrix}

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--data", required=True)
    p.add_argument("--out", required=True)
    p.add_argument("--epochs", type=int, default=200)
    p.add_argument("--learning-rate", type=float, default=0.05)
    a = p.parse_args()
    if not (1 <= a.epochs <= 10000 and 0 < a.learning_rate <= 1):
        p.error("invalid training hyperparameters")
    rows = []
    for line in Path(a.data).read_text().splitlines():
        if not line.strip():
            continue
        obj = json.loads(line)
        if obj.get("label") not in CLASSES or not isinstance(obj.get("group"), str) or not obj["group"]:
            raise ValueError("each record requires valid label and group")
        rows.append((vector(obj["context"]), CLASSES.index(obj["label"]), obj["group"]))
    if len(rows) < 20 or len(set(r[2] for r in rows)) < 10:
        raise ValueError("at least 20 examples across 10 independent groups required")
    # Stable group-wise split prevents same-case leakage into train and validation.
    train, valid = [], []
    for x, y, group in rows:
        bucket = int(hashlib.sha256(group.encode()).hexdigest()[:8], 16) % 5
        (valid if bucket == 0 else train).append((x, y))
    if not train or not valid or set(y for _, y in train) != {0, 1, 2}:
        raise ValueError("insufficient class coverage or validation data")
    weights = [[0.0] * len(FEATURES) for _ in CLASSES]
    for _ in range(a.epochs):
        for x, y in train:
            probs = softmax([sum(w * v for w, v in zip(row, x)) for row in weights])
            for c in range(3):
                error = (1 if c == y else 0) - probs[c]
                for j, v in enumerate(x):
                    weights[c][j] += a.learning_rate * error * v
    artifact = {"schemaVersion": "1", "classes": CLASSES, "featureNames": FEATURES,
                "weights": weights, "trained": True, "approvalStatus": "experimental"}
    Path(a.out).write_text(json.dumps(artifact, indent=2) + "\n")
    print(json.dumps({"train": evaluate(weights, train), "validation": evaluate(weights, valid),
                      "approvalStatus": "experimental"}, indent=2))

if __name__ == "__main__":
    main()
