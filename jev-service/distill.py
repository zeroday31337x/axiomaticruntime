#!/usr/bin/env python3
"""Offline experimental JEV student distillation. No production authorization."""
import argparse
import json
import math
from pathlib import Path
from train import CLASSES, FEATURES, vector, softmax, evaluate

def load(path):
    rows = []
    for line in Path(path).read_text().splitlines():
        if not line.strip():
            continue
        r = json.loads(line)
        if r.get("task") != "jev_classification" or r.get("approvalStatus") != "reviewed" or r.get("reviewed") is not True:
            raise ValueError("only independently reviewed classification labels accepted")
        if r.get("labelSource") != "independent_review" or r.get("label") not in CLASSES:
            raise ValueError("missing independent ground truth")
        if not isinstance(r.get("scenarioGroup"), str) or not r["scenarioGroup"]:
            raise ValueError("missing scenario family")
        teacher = r.get("teacher", {}).get("probabilities")
        if not isinstance(teacher, dict) or set(teacher) != set(CLASSES):
            raise ValueError("missing teacher distribution")
        p = [teacher[c] for c in CLASSES]
        if any(not isinstance(v, (int,float)) or isinstance(v,bool) or not math.isfinite(v) or v < 0 or v > 1 for v in p) or abs(sum(p)-1)>1e-6:
            raise ValueError("invalid teacher probabilities")
        rows.append((vector(r["context"]), CLASSES.index(r["label"]), r["scenarioGroup"], p))
    return rows

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--data", required=True)
    p.add_argument("--out", required=True)
    p.add_argument("--epochs", type=int, default=100)
    p.add_argument("--learning-rate", type=float, default=0.03)
    p.add_argument("--teacher-weight", type=float, default=0.25)
    p.add_argument("--temperature", type=float, default=2)
    a = p.parse_args()
    if not (1 <= a.epochs <= 10000 and 0 < a.learning_rate <= 1 and
            0 <= a.teacher_weight <= 0.5 and 0 < a.temperature <= 100):
        p.error("invalid hyperparameters")
    rows = load(a.data)
    if len(rows) < 20 or len(set(r[2] for r in rows)) < 10:
        raise ValueError("insufficient reviewed examples or independent groups")
    import hashlib
    train, valid = [], []
    for r in rows:
        bucket = int(hashlib.sha256(r[2].encode()).hexdigest()[:8],16)%5
        (valid if bucket == 0 else train).append(r)
    if not train or not valid or set(y for _,y,_,_ in train) != {0,1,2}:
        raise ValueError("insufficient class coverage or holdout")
    weights = [[0.0]*len(FEATURES) for _ in CLASSES]
    for _ in range(a.epochs):
        for x,y,_,teacher in train:
            scores = [sum(w*v for w,v in zip(row,x)) for row in weights]
            hard = softmax(scores)
            student_soft = softmax([s/a.temperature for s in scores])
            t = [max(v,1e-12)**(1/a.temperature) for v in teacher]
            t = [v/sum(t) for v in t]
            for c in range(3):
                gradient = (1-a.teacher_weight)*((1 if c==y else 0)-hard[c])
                gradient += a.teacher_weight*a.temperature*(t[c]-student_soft[c])
                for j,v in enumerate(x):
                    weights[c][j] += a.learning_rate*gradient*v
    artifact = {"schemaVersion":"1","classes":CLASSES,"featureNames":FEATURES,
                "weights":weights,"trained":True,"approvalStatus":"experimental",
                "trainingMethod":"reviewed-label-and-teacher-distillation"}
    Path(a.out).write_text(json.dumps(artifact,indent=2)+"\n")
    metrics = {"train":evaluate(weights,[(x,y) for x,y,_,_ in train]),
               "validation":evaluate(weights,[(x,y) for x,y,_,_ in valid]),
               "teacherWeight":a.teacher_weight,"temperature":a.temperature,
               "warning":"holdout is not an independent external evaluation"}
    print(json.dumps(metrics,indent=2))

if __name__ == "__main__":
    main()
