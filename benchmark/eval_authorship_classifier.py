"""Validate the AI-authorship heuristic as a classifier (reviewer #9).

Uses the SecurityEval dataset, which provides a genuine labeled set:
  - AI-authored positives: Testcases_Copilot + Testcases_InCoder (model-generated)
  - human-authored negatives: Testcases_Insecure_Code (written by the dataset
    authors), comparable in size/domain to the AI samples.

Runs the deterministic 7-signal heuristic on each file (treated as an all-added
diff) and reports precision / recall / F1 at the 0.5 threshold plus ROC-AUC
(threshold-free). No LLM / API.

    python benchmark/eval_authorship_classifier.py --securityeval /tmp/SecurityEval
"""
from __future__ import annotations

import argparse
from pathlib import Path

from autopsy.detection.heuristics import analyze_diff


def _as_added_diff(code: str) -> str:
    return "\n".join("+" + ln for ln in code.splitlines())


def _scores(files: list[Path]) -> list[float]:
    out = []
    for f in files:
        try:
            code = f.read_text(errors="replace")
        except OSError:
            continue
        if len(code.splitlines()) < 3:
            continue
        out.append(analyze_diff(_as_added_diff(code)).confidence)
    return out


def _auc(pos: list[float], neg: list[float]) -> float:
    """ROC-AUC = P(score(AI) > score(human)), ties = 0.5."""
    if not pos or not neg:
        return 0.0
    wins = 0.0
    for p in pos:
        for q in neg:
            wins += 1.0 if p > q else 0.5 if p == q else 0.0
    return wins / (len(pos) * len(neg))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--securityeval", type=Path, default=Path("/tmp/SecurityEval"))
    ap.add_argument("--threshold", type=float, default=0.5)
    args = ap.parse_args()

    se = args.securityeval
    ai_files = sorted((se / "Testcases_Copilot").rglob("*.py")) + \
        sorted((se / "Testcases_InCoder").rglob("*.py"))
    human_files = sorted((se / "Testcases_Insecure_Code").rglob("*.py"))

    ai = _scores(ai_files)
    hu = _scores(human_files)
    print(f"AI-authored samples (Copilot+InCoder): {len(ai)}")
    print(f"Human-authored samples (Insecure_Code): {len(hu)}")

    t = args.threshold
    tp = sum(1 for s in ai if s >= t)
    fn = len(ai) - tp
    fp = sum(1 for s in hu if s >= t)
    tn = len(hu) - fp
    prec = tp / (tp + fp) if (tp + fp) else 0.0
    rec = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    auc = _auc(ai, hu)

    print(f"\nAuthorship classifier @ threshold {t} (likely_ai):")
    print(f"  Precision {round(prec*100)}%  Recall {round(rec*100)}%  F1 {round(f1*100)}%")
    print(f"  FPR (human flagged as AI) {round(fpr*100)}%")
    print(f"  ROC-AUC {auc:.2f}")
    print(f"  mean confidence: AI={sum(ai)/len(ai):.2f}, human={sum(hu)/len(hu):.2f}")


if __name__ == "__main__":
    main()
