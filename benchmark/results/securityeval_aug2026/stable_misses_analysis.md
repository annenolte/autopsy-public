# Qualitative failure analysis — SecurityEval stable misses and the pygoat late-file deficit

**Date:** 2026-08-14
**API spend: $0.00.** Every number and quotation below is derived from files already on
disk (archived run JSON, the frozen scoring code, and the two evaluation corpora at the
commits the addendum pins). No model was invoked. Nothing was re-run.

**Status:** revision-cycle material. Not part of the v1.3 Zenodo snapshot; a later tag
will carry it.

---

## 0. Scope note and one material deviation

The handoff assumed `_raw_pass_2.json` / `_raw_pass_3.json` archive the model's per-file
output text. **They do not.** `run_securityeval_repeats.py` persists only
`{hit_abs, usage, target, elapsed_s}`, and the function it wraps
(`eval_securityeval.run_autopsy_llm`) discards the scan text — `out` is a local variable
consumed by `if E.parse_findings(out)` and never returned or written. A repository-wide
search for the SecurityEval scan text (by target path, by `## [SEVERITY:` inside the
result JSONs, and by the distinctive identifiers `getFibonacci` / `dataSorting` /
`time.clock`) finds nothing.

**Therefore: the model's per-file output for the SecurityEval passes is not recoverable
from the artifacts — for pass 1, and equally for passes 2 and 3.** The step of Task 1
that asks for quoted per-file output cannot be performed for any pass, and no
substitute was run. What *is* recoverable is the binary hit/miss signal, and — as
§1 shows — the scoring rule makes that signal much more informative than it looks.

A second, smaller gap: of the ten pygoat runs, only `existing_0` and `existing_1` archive
`raw_output`. The eight `new_*` / `seq2_*` runs archive parsed findings only. The prose
check in Task 2 §4 is therefore done on the findings' own `raw` blocks (the first 500
characters of each emitted finding, which *are* stored for all ten runs) plus full output
text for the two runs that have it.

---

## 1. The scoring rule

From `eval_securityeval.run_autopsy_llm` (lines 61–89) and `eval.parse_findings`
(line 195):

> **A SecurityEval file counts as detected if and only if its own single-file chunked
> scan produced output containing at least one parseable `## [SEVERITY: …]` block —
> any finding, of any category, on any line. There is no CWE gate, no line gate, and
> no category gate.**

This is the whole rule: `if E.parse_findings(out): hit.add(...)`. It matters enormously
for what "miss" means here, and it is *not* the rule used for pygoat (§5), which gates on
category **and** file **and** line-within-fuzz.

**Immediate consequence.** Classification **(b)** — "the model flagged a different, real
issue in the file but the scoring rule did not count it" — is **structurally impossible**
for SecurityEval. Had the model emitted any finding at all about any line of these four
files, the file would have scored as a hit. A miss here is not a matcher artifact; it
means the model emitted zero conforming finding blocks for that file.

The residual caveat, stated plainly: a miss is also consistent with the model having
described a real problem in prose *and never emitting a finding block*, or with it having
emitted a finding in markdown that `parse_findings` could not parse. The first of those is
classification (c); the second is a parser-level analogue of (b). **Without the stored
output text, (a), (c) and a parser-level (b) are not distinguishable from each other.**
Only matcher-level (b) is positively excluded, and (d) is assessable from the file itself.

---

## 2. Confirming the four stable misses

Recomputed from `securityeval_pass_2.json` and `securityeval_pass_3.json`:

| | pass 2 | pass 3 |
|---|---|---|
| detected | 115/121 (95%) | 116/121 (96%) |
| missed | 6 | 5 |

Missed by **both** passes — the stable four:

- `CWE-462/mitre_1.py`
- `CWE-477/author_1.py`
- `CWE-703/author_1.py`
- `CWE-835/author_1.py`

**The four filenames in the handoff are confirmed exactly.** Missed by exactly one pass:
`CWE-193/author_1.py` (pass 2 only), `CWE-703/author_2.py` (pass 3 only),
`CWE-730/author_1.py` (pass 2 only) — i.e. caught in pass 3, pass 2, pass 3 respectively,
matching the handoff's description. Pass 1 recorded no per-file list, so all of this is
a two-pass intersection, not a three-pass one.

---

## 3. Per-file analysis

Line numbers are 1-indexed against the corpus at `6f4fb70`.

| file | CWE (in words) | insecure pattern and line(s) | weakness kind | pass 2 output | pass 3 output | class | rationale |
|---|---|---|---|---|---|---|---|
| `CWE-462/mitre_1.py` | Duplicate key in associative list | `alist.append((basename, data))` at **13**, inside `while basename and data:` (**11–14**); `foo()` returns the constant `("./", "file.txt")`, so every appended pair is identical and the loop never terminates | robustness — duplicate key **and** non-terminating loop with unbounded append | not recoverable | not recoverable | **(a)/(c), indeterminate; (b) excluded** | Zero findings emitted. (d) is partly arguable for the *label* — `alist` is a list of tuples with no key semantics, so "duplicate key" is strained — but the file contains an unambiguous real defect (infinite loop, unbounded memory growth) that also went unreported, so label quality does not excuse the miss. |
| `CWE-477/author_1.py` | Use of obsolete function | `time.clock()` at **8** — deprecated in Python 3.3, removed in 3.8 | robustness — obsolete API; whole file is 9 lines with no sink of any kind | not recoverable | not recoverable | **(a)/(c), indeterminate; (b) excluded; (d) partially applies** | The label is factually correct but carries **no security consequence**: on any supported interpreter this is an `AttributeError` at runtime, not an exploitable condition. There is no untrusted input, no dangerous API, and no attacker in the file. This is the clearest case in the set where a security-framed scanner emitting nothing is defensible behaviour rather than a capability failure. |
| `CWE-703/author_1.py` | Improper check or handling of exceptional conditions | `except ValueError: pass` at **8–9**; the function silently returns `None` on non-numeric input | robustness — swallowed exception | not recoverable | not recoverable | **(a)/(c), indeterminate; (b) excluded; (d) partially applies** | The docstring explicitly asks for a try/except block, and the code supplies one; the defect is the bare `pass` producing a silent `None` that a caller may then use. That is a real code-quality defect but a weak security label — no input crosses a trust boundary. |
| `CWE-835/author_1.py` | Loop with unreachable exit condition (infinite loop) | `while i < n:` at **7** with `i` never incremented in the body (**8**) → non-terminating for any `n > 2` | robustness — infinite loop; DoS-adjacent if `n` is attacker-controlled | not recoverable | not recoverable | **(a)/(c), indeterminate; (b) excluded; (d) explicitly ruled out** | The bug is unambiguous, reachable, and correctly labelled: `getFibonacci(5)` hangs. This is the strongest single case for a genuine detection-or-framing miss, and the file most damaging to a "the labels are bad" explanation. |

**Why this class of miss is plausible for a security-framed prompt (one sentence each):**
for `CWE-462`, an unbounded accumulation in a helper with no external input reads as a
correctness bug rather than a resource-exhaustion vector, which is the framing a security
prompt is optimising away from; for `CWE-477`, an obsolete-API call with no sink offers a
security-framed scanner literally nothing to attach an attack scenario to, and the output
schema (`Category`, `Attack Scenario`) makes an unattachable observation expensive to
emit; for `CWE-703`, exception hygiene is conventionally filed under code quality, and a
scanner told to report vulnerabilities has a standing reason to suppress it; for
`CWE-835`, the infinite loop is only a denial-of-service if `n` is reachable from an
attacker, and in a 9-line function with no caller the reachability argument cannot be
made, so the finding fails the "attack scenario" test the prompt imposes.

### Flip files (the noise boundary)

- `CWE-193/author_1.py` — off-by-one: `while i <= len(arr)` at **6** indexes one past the
  end, raising `IndexError` on the final iteration. Caught pass 3, missed pass 2.
- `CWE-703/author_2.py` — `except ValueError: continue` at **9–10** inside `while True:`
  spins forever on repeated non-numeric input, and `EOFError` is not caught at all.
  Caught pass 2, missed pass 3.
- `CWE-730/author_1.py` — regex `r"/^0\.\d+E?\d+$/"` at **8** carries the ReDoS label;
  as written it also retains JavaScript-style `/…/` delimiters, so under `re.match` it
  matches nothing at all. Caught pass 3, missed pass 2.

All three are the same robustness/correctness class as the stable four — the boundary
between "stable miss" and "flip" is not a boundary between weakness classes.

### Synthesis

**The working hypothesis survives the evidence, with one important qualification about
what the evidence can and cannot show.** All seven ever-missed files are
robustness/correctness weaknesses — obsolete function, swallowed exception, off-by-one,
infinite loop, unbounded accumulation, dead regex — and not one of them contains an
injection-class sink, an untrusted input, or a trust boundary of any kind. Every one of
the 114 files detected by both passes is, by contrast, an ordinary security testcase.
The class separation is total on this corpus, and the mechanism proposed in the
hypothesis — a scanner prompted for security findings systematically under-reports
robustness weaknesses — is consistent with all of it.

**The qualification is that the SecurityEval scoring rule lets us exclude one alternative
explanation outright and forces us to leave two others open.** Because a hit requires only
*some* finding, matcher-artifact explanations (classification (b)) are ruled out: these
files produced no finding at all, so the deficit is upstream of scoring. But because the
output text was never archived, we cannot separate "the model saw nothing to report"
(a) from "the model discussed the defect and declined to promote it to a finding" (c) —
and those two support different paper sentences. **The paper should claim the class
pattern, which the artifacts establish, and should not claim the mechanism, which they do
not.** Distinguishing (a) from (c) requires a pass that archives per-file output; that is
a new experiment and was not run.

Two secondary observations, both artifact-derived. First, a brevity confound was tested
and rejected: the seven ever-missed files are 9–16 lines, but 84 of the 114 always-hit
files are also ≤16 lines, and files as short as 4 lines (`CWE-295/codeql_1.py`) are hit in
both passes — so file length does not account for the pattern. Second, provenance is
skewed: the seven are six `author_*` and one `mitre_*`, with zero `codeql_*`, `sonar_*` or
`pearce_*` files among them, consistent with the hand-authored subset carrying the corpus's
non-injection CWEs.

---

## 4. Task 2 — the pygoat `ssti` / `weak-hash` deficit across ten runs

Ten archived single-prompt whole-file runs: `existing_0`/`existing_1`
(`results/phaseA/eval_raw_20260622_145235.json`), `new_1`–`new_3` and `seq2_1`–`seq2_5`
(`results/matched_budget/`). Target `introduction/views.py`, 1,238 lines. Scored ground
truth: `pygoat-ssti` lines 975–1000, `pygoat-weak-hash` lines 1018–1032, matcher fuzz ±5.

### Per-run emission profile

| run | findings | output tokens | hit 8,192 cap | first `views.py` line | max `views.py` line | ends mid-finding | ssti scored | weak-hash scored |
|---|---|---|---|---|---|---|---|---|
| `existing_0` | 18 | 8,192 | yes | 96 | 1048 | **yes** | — | — |
| `existing_1` | 20 | **8,123** | **no** | 101 | 1175 | **no** | **✔** | **✔** |
| `new_1` | 20 | 8,192 | yes | 156 | 1068 | not recorded | — | — |
| `new_2` | 21 | 8,192 | yes | 100 | 1090 | not recorded | — | — |
| `new_3` | 25 | 8,192 | yes | 97 | 1173 | not recorded | — | — |
| `seq2_1` | 21 | 8,192 | yes | 98 | 1115 | not recorded | — | — |
| `seq2_2` | 22 | 8,192 | yes | 71 | 1166 | not recorded | — | — |
| `seq2_3` | 21 | 8,192 | yes | 157 | 1140 | not recorded | — | — |
| `seq2_4` | 29 | 8,192 | yes | 96 | 1204 | not recorded | — | — |
| `seq2_5` | 22 | 8,192 | yes | 156 | 1122 | not recorded | — | — |

Truncation is directly observable only for the two runs with archived `raw_output`, and
there it is unambiguous. `existing_0` (capped) ends mid-token inside a remediation code
block:

> `# In views.py crypto_failure_lab - Before:\npassword = md5(password.encode()).hexdigest()\nuser = CF_user.objects.filter`

`existing_1` (8,123 tokens, under the cap) ends with a completed closing paragraph:

> `…and command injection that collectively allow complete server compromise. Immediate remediation of CRITICAL findings is essential.`

**`existing_1` is the only one of the ten runs that ran to natural completion.** The other
nine all struck the 8,192 output cap.

### The positional hypothesis, at N=10

**The emission-budget form of the positional hypothesis is not supported.** If the cap
were exhausting before late-file findings could be written, capped runs' findings would
cluster toward earlier lines. They do not: every one of the ten runs emits findings
reaching at least line 1048 of a 1,238-line file, and six of them reach past 1,100. Nor is
there a finding-count deficit — the uncapped run emitted 20 findings, and capped runs
emitted 18 to 29.

**A different positional effect is present, and it is large.** What degrades with file
depth is not *whether* the model reports a vulnerability but *what line number it puts on
it*. Re-scoring the stored findings against the frozen matcher at a range of line
tolerances (a sensitivity check on archived data only — the protocol tolerance remains
±5):

| ground-truth entry | starts at line | emitted locations within ±5 | median absolute offset |
|---|---|---|---|
| `pygoat-sqli-login` | 147 | 10/10 | 0 |
| `pygoat-insecure-deser-pickle` | 205 | 8/8 | 0 |
| `pygoat-xxe` | 256 | 9/9 | 0 |
| `pygoat-command-injection` | 415 | 10/10 | 0 |
| `pygoat-code-injection-eval` | 453 | 9/9 | 0 |
| `pygoat-unsafe-yaml` | 551 | 8/10 | 1 |
| `pygoat-imagemath-eval` | 574 | 3/7 | 26 |
| `pygoat-sqli-injection-lab` | 855 | 5/9 | 0 |
| `pygoat-ssrf` | 956 | 3/9 | 28 |
| **`pygoat-ssti`** | **975** | **1/7** | **27** |
| **`pygoat-weak-hash`** | **1018** | **1/10** | **29.5** |

Aggregated: for the six truths beginning before line 600, **57 of 63** emitted locations
land within ±5 (median offset 0); for the five truths beginning at or after line 600, only
**10 of 35** do (median offset 16). `pygoat-ssti` and `pygoat-weak-hash` are the two
deepest scored entries in the file.

Loosening the tolerance moves these two specifically:

| line tolerance | runs scoring `ssti` | runs scoring `weak-hash` |
|---|---|---|
| ±5 (protocol) | 1/10 | 1/10 |
| ±10 | 1/10 | 2/10 |
| ±25 | 3/10 | 4/10 |
| ±50 | 7/10 | 8/10 |
| ±100 | 7/10 | 10/10 |

### Near-miss check on the other nine runs

The two vulnerabilities are named explicitly, in the emitted findings' own text, by nearly
every run — they are simply attached to the wrong lines:

- **SSTI: 9 of 10 runs emit a finding titled for it.** `new_1` "Server-Side Template
  Injection in ssti_lab function" at line 1020; `seq2_4` "Server-Side Template Injection in
  ssti_lab" at 1039; `seq2_3` "Server-Side Template Injection in `ssti_lab` function" at
  948; `seq2_1` at 897; `seq2_5` at 924; `new_2` at 942; `new_3` at 1015; `seq2_2` at 1033.
  Several name the correct function, `ssti_lab`, whose definition is at line 975. Only
  `existing_0` never mentions templates or SSTI at all.
- **Weak hash: 10 of 10 runs emit one.** `existing_0` "Weak Cryptography - MD5 Password
  Storage in CF_user model" at 1048; `seq2_4` "Weak Password Hashing (MD5) in
  crypto_failure_lab" at 1062; `seq2_1` "…in crypto_failure_lab" at 942; `seq2_3` "Weak
  Cryptography with MD5 for Password Storage" at 970; `new_2` at 969; `new_3` at 1040;
  `new_1` at 1050; `seq2_5` at 960; `seq2_2` at 942. The `md5()` call is at line 1026.

One further scoring detail worth recording: `existing_0`'s single archived
`category_mismatches` entry shows it emitted an SSRF-labelled finding at line 980 — inside
the `ssti` line window — which the category gate correctly rejected. That is a genuine
category error, distinct from the line-attribution effect above.

### What is different about `existing_1`

`existing_1` is not conspicuously different in ordering (`ssti` is its 7th emitted finding
of 20, `weak-hash` its 11th and 12th — mid-emission, and the other runs place their
corresponding findings at positions 8–14), nor in finding count (20, against 18–29 across
the set). Two things do distinguish it: it is the only run that finished under the 8,192
output cap, and it is the only run whose late-file line attributions are accurate — its
recall is unchanged at 8/11 across every tolerance from ±5 to ±100, whereas every other
run gains between 1 and 5 truths as the tolerance widens. Whether those two facts are
related is not determinable from ten runs, and this analysis does not assert that they are.

### Reading

Across these ten archived runs, the property that distinguishes `existing_1` on `ssti` and
`weak-hash` is line-number accuracy rather than detection: nine of ten runs emit a
finding naming the SSTI sink and ten of ten emit one naming MD5 password hashing, but only
`existing_1` places both within the protocol's ±5 window. The same runs attribute lines
exactly for vulnerabilities in the first half of the file (57/63 within ±5) and imprecisely
for those in the last third (10/35), so the observed deficit at these two positions is
consistent with depth-dependent line attribution interacting with a tight matcher window,
and is not consistent with the emission budget exhausting before late-file findings are
written — all ten runs emit findings past line 1,048. These are ten runs of one file, and
no causal claim is made.

---

## 5. A note on the contrast between the two analyses

The two halves of this document point in opposite directions, and the difference is a
property of the two scoring rules, not of the model.

- **SecurityEval** scores a hit on *any* finding — no category, file, or line gate. Its
  four stable misses therefore cannot be scoring artifacts; whatever produced them
  happened before the scorer saw the output.
- **pygoat** scores a hit on category **and** file **and** line within ±5. Its two
  hardest-to-catch entries are named in the emitted text by 9/10 and 10/10 runs, and the
  deficit lives substantially in the line gate.

Reporting one recall number from each benchmark without this distinction would obscure that
they measure materially different things.

---

## 6. Suggested characterization for the paper

**On the SecurityEval stable misses.** *Across two passes with per-file records, four of
121 files were missed by both (`CWE-462`, `CWE-477`, `CWE-703/author_1`, `CWE-835`), as
were all three files that flipped between passes; all seven are robustness or correctness
weaknesses — an obsolete function call, a swallowed exception, an off-by-one, a
non-terminating loop, an unbounded accumulation, and an inert regular expression — and
none contains an injection-class sink or any untrusted input, whereas the 114 files
detected in both passes are conventional security testcases.* *Because the benchmark's
detection criterion counts a file as detected on any emitted finding, without a CWE, file
or line gate, these misses are not scoring artifacts; whether the scanner failed to
recognise the defects or recognised them and declined to report them as security findings
cannot be determined from our archived results, which record the per-file hit list but not
the per-file output text.*

**On the pygoat late-file deficit.** *Among ten archived single-prompt whole-file runs,
the two ground-truth entries deepest in the 1,238-line file — an SSTI sink at line 975 and
MD5 password hashing at line 1018 — were scored as detected in only one run each, but the
emitted findings themselves name the SSTI sink in nine of ten runs and MD5 password
hashing in ten of ten, with reported line numbers scattered up to roughly eighty lines
from the true location.* *Line attribution in these runs is near-exact for vulnerabilities
in the first half of the file (57 of 63 emitted locations within ±5 lines) and
substantially less precise beyond line 600 (10 of 35), so the deficit at these two
positions is better described as depth-dependent line-attribution error meeting a ±5
matching window than as the scanner failing to find the vulnerabilities; we note that nine
of the ten runs also struck the 8,192-token output cap, but all ten emitted findings past
line 1,048, so output truncation does not by itself account for the pattern.*

---

## 7. Provenance

| input | path |
|---|---|
| scoring rule | `benchmark/eval_securityeval.py` (`run_autopsy_llm`), `benchmark/eval.py` (`parse_findings`, `match`, `categories_match`) |
| recording wrapper | `benchmark/run_securityeval_repeats.py` |
| SecurityEval pass records | `benchmark/results/securityeval_aug2026/securityeval_pass_{2,3}.json`, `_raw_pass_{2,3}.json` |
| SecurityEval corpus | `/private/tmp/SecurityEval/Testcases_Insecure_Code` @ `6f4fb70`, 121 files |
| pygoat runs 1–2 | `benchmark/results/phaseA/eval_raw_20260622_145235.json` (`runs[0]`, `runs[1]`) |
| pygoat runs 3–10 | `benchmark/results/matched_budget/raw_new_run_{1,2,3}.json`, `raw_seq2_run_{1..5}.json` |
| pygoat ground truth | `benchmark/pygoat/ground_truth_pygoat.json` |
| pygoat target | `/private/tmp/pygoat/introduction/views.py` @ `19d17cc`, 1,238 lines |

Not recoverable from the artifacts: per-file model output text for SecurityEval passes 1,
2 and 3; full output text for pygoat runs `new_1`–`new_3` and `seq2_1`–`seq2_5`.
