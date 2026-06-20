# Held-out generality check (NOT part of the scored benchmark)

This tiny "orders" project exists only to test whether the deterministic
detectors (`autopsy/detection/ignored_returns.py`,
`autopsy/detection/static_rules.py`) **generalize** — i.e. fire on code they
were *not* written against, with different names, a different domain, and a
different DB-wrapper. It is deliberately separate from `demo_project/` and
`ground_truth.json` so it cannot contaminate the frozen benchmark.

- `vulnerable/` contains three planted bugs in different shapes:
  - an ignored cross-file authorization gate (`cancel_order` → `verify_owner`),
  - a parameter interpolated into a SQL string reaching a sink (`run_sql`),
  - MD5 hashing.
- `safe/` is the same project with all three fixed (return checked, bound
  parameters, PBKDF2). The detectors must produce **zero** findings here.

Run `python benchmark/validate_heldout.py` to check both expectations.
