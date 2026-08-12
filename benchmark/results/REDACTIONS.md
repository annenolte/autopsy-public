# Redactions applied to published run artifacts

Dated 2026-08-12. Append-only; supersedes nothing.

## What was redacted

Ten demo_project run artifacts published for the v1.3 paper revision had absolute
developer paths in their `config.demo` and `config.baseline` fields. Two distinct string
values were substituted, everywhere they occurred:

| original | published as | occurrences |
|---|---|---|
| `/Users/annenolte/autopsytest copy/benchmark/baseline` | `<repo>/benchmark/baseline` | 7 |
| `/Users/annenolte/autopsytest copy/demo_project` | `<repo>/demo_project` | 7 |

Affected files (occurrences substituted):

- `eval_autopsy_20260619_233900.json` (2)
- `eval_sonnet-only_20260619_233900.json` (2)
- `eval_raw_20260619_233900.json` (2)
- `eval_autopsy_20260619_123412.json` (1)
- `eval_raw_20260619_123412.json` (1)
- `eval_autopsy_20260618_161028.json` (2)
- `eval_autopsy_20260618_210426.json` (2)
- `eval_autopsy_20260618_212208.json` (2)
- `phaseA/eval_autopsy-demo_20260622_150627.json` (0 — published byte-identical)
- `phaseA/eval_chunked-nograph-demo_20260622_151446.json` (0 — published byte-identical)

## What was NOT changed

The substitution is a pure literal string replacement on two path prefixes. **No measured
value, metric, count, finding, token count, timestamp, or config flag was altered.** The
`runs`, `metrics`, `counts`, and `aggregate` blocks are byte-identical to the local
originals. Anyone can verify by reversing the two substitutions above and comparing
hashes against the author's working copy.

## Screening performed

All ten files were screened for: Anthropic API keys (`sk-ant-…`), `ANTHROPIC_API_KEY`
assignments, GitHub tokens (`ghp_`/`gho_`/`ghu_`/`ghs_`/`ghr_`), AWS access key IDs,
PEM private-key headers, and bearer tokens. **Zero hits in all categories.**

An email-pattern scan returned 196 matches, all verified false positives: 173 are
`\n@app.route` (the pattern matching across an escaped newline in Flask decorator text
inside finding bodies) and the remainder are synthetic examples authored in the scan
output (`attacker@evil.com`, `attacker@example.com`, `admin@example.com`). No real
address is present.

## Known inconsistency with v1.2-paper

Three files published at the `v1.2-paper` tag contain the same class of absolute
developer path and were **not** redacted at that time:

- `benchmark/results/phaseA/eval_raw_20260622_145235.json` (1 occurrence)
- `results/codeql/codeql_version.json` (2 occurrences)
- `results/codeql/resolved_packs.json` (141 occurrences)

These are left untouched: the v1.2-paper file set is immutable by project rule, and
rewriting it would invalidate the archived v1.2 DOI. The redaction standard therefore
applies from v1.3 onward, and the inconsistency is recorded here rather than silently
resolved. Note also that the developer path segment is the same string as the public
GitHub account name, so it discloses nothing not already implied by the repository URL.
