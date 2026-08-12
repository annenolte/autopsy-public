"""Phase 2 (Aug 2026 replication) driver — run_phaseA.py with a NEW ledger file.

The replication addendum forbids modifying any existing artifact under
benchmark/results/. run_phaseA.py appends to `results/phaseA/ledger.jsonl`, which
is a published artifact, so this shim redirects the ledger to
`results/phaseA/ledger_aug2026.jsonl` and changes nothing else.

Everything that touches the experiment — arms, prompts, models, windowing, dedupe,
matcher, ground truth, cost accounting, the per-arm aggregate writer — is
run_phaseA's own code, called unmodified. The per-arm aggregate outputs are already
timestamped (`eval_{label}_{YYYYmmdd_HHMMSS}.json`), so they land in new files.

Usage is identical to run_phaseA.py, e.g.:
  python benchmark/run_phaseA_aug2026.py --arm autopsy \
     --target /tmp/pygoat/introduction \
     --ground-truth benchmark/pygoat/ground_truth_pygoat.json \
     --baseline-mode whole-file --chunked --repeat 3 --cap 9.00 --est-unit 1.15
"""
from __future__ import annotations

import sys
from pathlib import Path

_BENCH = Path(__file__).resolve().parent
_ROOT = _BENCH.parent
for p in (str(_BENCH), str(_ROOT)):
    if p not in sys.path:
        sys.path.insert(0, p)

import run_phaseA as P  # noqa: E402

# The ONLY change. cumulative() and append_ledger() resolve LEDGER as a module
# global at call time, so rebinding it here redirects both reads and writes.
P.LEDGER = P.PHASE_DIR / "ledger_aug2026.jsonl"

if __name__ == "__main__":
    assert P.LEDGER.name == "ledger_aug2026.jsonl"
    print(f"[shim] ledger -> {P.LEDGER}")
    P.main()
