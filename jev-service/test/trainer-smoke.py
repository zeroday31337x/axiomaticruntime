#!/usr/bin/env python3
"""Synthetic smoke test only; does not measure production model quality."""
import json
import subprocess
import sys
import tempfile
from pathlib import Path

root = Path(__file__).resolve().parents[1]
with tempfile.TemporaryDirectory() as tmp:
    data = Path(tmp) / "synthetic.jsonl"
    output = Path(tmp) / "model.json"
    records = []
    # Distinct scenario families and labels exercise splitting and artifact export.
    for i in range(90):
        kind = i % 3
        route = ("/health" if kind == 0 else "/admin/settings" if kind == 1 else "/v1/unknown")
        method = ("GET" if kind == 0 else "DELETE" if kind == 1 else "POST")
        label = ("ALLOW" if kind == 0 else "DENY" if kind == 1 else "FLAG")
        records.append({"context": {"route": route, "method": method},
                        "label": label, "group": f"scenario-{i}"})
    data.write_text("\n".join(json.dumps(x) for x in records) + "\n")
    result = subprocess.run([sys.executable, str(root / "train.py"), "--data", str(data),
                             "--out", str(output)], capture_output=True, text=True, check=True)
    report = json.loads(result.stdout)
    model = json.loads(output.read_text())
    assert report["validation"]["samples"] > 0
    assert report["train"]["samples"] > 0
    assert model["approvalStatus"] == "experimental"
    assert len(model["weights"]) == 3
    assert all(len(row) == len(model["featureNames"]) for row in model["weights"])
    print(json.dumps({"smoke": "pass", "validationSamples": report["validation"]["samples"],
                      "warning": "synthetic examples only; not a security quality benchmark"}))
