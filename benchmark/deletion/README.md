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

## Precision fix (Part 1C — was a known limitation)

The comment-boundary detector previously fired a **second, spurious** time on
`auth_layer.py`, because it flagged *any* deleted line beginning with `"""` —
including a normal function whose one-line docstring was removed, even though no
code was activated. That over-fire is now **fixed**: the detector gates on the
*revealed* block (the lines that follow the deleted opener, up to the matching
closer) and only fires when that block parses to executable definitions or
contains a sink (the sink patterns are reused from
`autopsy/detection/static_rules.py`). Two guards do the work:

1. a **self-closing** single-line block (`"""text"""`, `/* ... */`) reveals
   nothing on deletion and is skipped; and
2. a revealed block that is **comment-/docstring-/prose-only** is suppressed.

So `auth_layer.py` is no longer flagged by the comment-boundary detector (it is
still caught by the security-control-deletion detector), while the genuine
`activation.py` case — where deleting the opener reveals a live `/admin/shell`
route calling `os.popen` — still fires. Locked in
`tests/test_deletion_benchmark.py::test_comment_detector_suppresses_benign_docstring`.
