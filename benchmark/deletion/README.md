# Deletion / zero-footprint benchmark (reviewer issue #6)

The paper claims deletion-based ("zero-footprint activation") vulnerabilities as
a core novelty, but the main benchmark (`demo_project/`) is entirely
addition-based, so the feature was untested. This directory backs that novelty
with an actual experiment.

`before/` and `after/` differ **only by a deletion**. An addition-only scanner
sees nothing dangerous; the deletion-aware detectors must catch it.

| id | file | what the deletion does | detector |
|----|------|------------------------|----------|
| deletion-comment-activation | activation.py | removes a docstring opener (`"""`), uncommenting a dormant `/admin/shell` route that runs `os.popen` on user input | `detect_comment_boundary_deletions` |
| deletion-security-control | auth_layer.py | removes `authorize_request` (a staff-only auth gate), leaving `handle_admin_action` unprotected | `diff_graphs().security_critical_deletions` |

## Result (deterministic, no LLM)

```
python benchmark/eval_deletions.py
→ deletion-detector recall: 2/2 = 100%
```

Both planted deletion vulns are recovered by the appropriate detector.

## Honest limitation (surfaced, not hidden)

The comment-boundary detector fired a **second, spurious** time on
`auth_layer.py`. Cause: it flags *any* deleted line beginning with `"""`, so
removing a normal function that has a one-line docstring trips it even though no
code was activated. It is a precise *recall* signal for genuine activations but
an **imprecise** one — it cannot distinguish an opener-that-activates-code from a
benign docstring deletion. This is a real precision weakness of the heuristic and
should be reported as such (and is locked in `tests/test_deletion_benchmark.py`);
refining it (e.g., only flag a delimiter whose removal actually changes which
lines parse as code) is future work.
