# Change-review measurements

## Version 2

The frozen successor contains 80 synthetic changes, including the original 48, ordinary argument and role controls, method-specific guard and version repairs, manifest-only cases, name similarities and mixed labels. It assigns 63 changes to the held-out split. Cases carry source bytes or inert placeholders, family, class labels, split, rationale, allowed test and repair eligibility. The independent human-review field remains pending. [Manifest](manifest-v2.json) · [Digest](manifest-v2.sha256)

| System | Raw observations | Independent audit |
| --- | --- | --- |
| A | Frozen in-process pattern predicates, with matching locations | No proposals |
| B | One stateless call returns all predicted classes/locations, claimed properties, rationales and a candidate. The redacted response is captured before auditing. | Same fixture eligibility, edit validator and property runner as split |
| Split | Stateless detection sees the redacted change and class policy. Verification sees candidates, immutable evidence references and eligible test IDs. After an observed original failure, fixing receives only its property evidence and edit scope. | The runner executes the chosen owned suite and audits the returned bytes |
| Template | CLI deterministic detectors plus owned fix templates | The same independent audit reruns the proposed bytes |

```sh
python Research/evaluate.py --out /tmp/laundromat-offline.json
python Research/evaluate.py --arm template --group query/direct --out /tmp/query.json
python Research/evaluate.py --live --out /tmp/laundromat-live.json
```

The live arms require a configured provider and model. Each runs three repetitions. Requests have no tools or shared conversation, use provider-default sampling, and disable storage. B gets a 9,000-character input and 1,200-token output ceiling. The split roles share those ceilings as 4,000/2,200/2,800 characters and 500/200/500 output tokens. Each call records input digest, prompt version, model, latency, usage or error. Runtime execution and final authorization stay with the deterministic runner. Ordinary inputs measure named properties only. The dependency regression measures the resolved metadata and catalog behavior without loading lodash.

The scorer counts each held-out change against each of eight classes. An unexpected predicted class contributes a false positive. Detection denominators exclude incomplete detections. Workflow completion, failures, unverified proposals, abstentions, stage time and eligible denominators remain visible. The recall interval resamples entire held-out families with replacement 500 times using a fixed seed. Closely related variants and author labels limit generalization. Redaction distinguishes encoded and literal synthetic values for the model. This gives model arms format information and limits comparisons with raw-byte detectors.

The latest strict offline run measured the following outcomes. [Generated table](results-offline-v2.md) · [Per-case observations, grouped metrics and failure examples](results-offline-v2.json)

| Arm | Completed changes | TP | FP | FN | Recall | Verified repairs |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| A | 63/63 | 24 | 12 | 12 | 24/36 | 0 proposals |
| Template | 60/63 | 32 | 0 | 4 | 32/36 | 7/7 proposed, 7/7 eligible |
| B and split | Pending | — | — | — | — | Provider credentials and model were unavailable |

The four missed positive labels were the encoded-secret and cross-module query variants. Unknown route policy, an ambiguous dynamic import and missing dependency metadata produced three incomplete observations. Seven confirmed fixes give 7/36 recall after requiring a verified repair. No provider tokens were consumed in the offline run. The offline arms cannot estimate the effect of splitting model roles.

The strict template run accumulated 91.08 seconds of case processing and 9.63 seconds in the separate audit. Validation jobs ran concurrently on this machine. Its grouped 95% bootstrap recall interval was 0.692–1.000. All 36 distinct retained container receipts reported removal. Re-running the archived v1 software reproduced the original 12 true positives, four misses and two verified repairs.

## Frozen version 1

The following figures describe the original corpus and software. The v1 runner checks the digest of its archived implementation before running it in a temporary directory. Original results and historical rehearsal measurements are retained separately.

### Detection and verified repairs on the original change set

On 32 held-out changes, the regex baseline found 14 of 16 labeled positives and raised 10 false positives. The deterministic template pipeline found 12 positives and raised zero false positives. It proposed two template repairs. Both passed the fixed parameter-binding verifier, preserved the expected SQLite IDs and cleared the Semgrep finding. These measurements compare complete systems with different detectors. They cannot establish the causal effect of separating stages or the benefit of a model-generated fix.

## Reproduce

From the [configured checkout](../README.md), run the offline comparison. The JSON contains each case outcome, elapsed time, versions, model settings and aggregate counts. The command generates the Markdown table from those results.

```sh
source .venv/bin/activate
python Research/evaluate_v1.py
cat Research/results-offline.md
```

For live systems B and C, provide `OPENAI_API_KEY` and a pinned `LAUNDROMAT_MODEL` in the environment, then run:

```sh
python Research/evaluate_v1.py --live --out Research/results-live.json
```

B gets one model pass per held-out change. C uses the static detectors and requests a model candidate only for a supported search finding. Both use the configured Responses model, the same redacted fixture context, a shared 4,000-character total prompt budget, a 700-token output limit and the same final verifier. The manifest labels, rationales and expected outputs stay outside the prompts. The live command records the model version returned by the service, usage, per-repetition metrics and the observed min/max across three repetitions. A failed model proposal retains the static finding. The live evaluation disables the template fallback for C.

The authenticated Codex wrapper was exercised separately. Its [captured edit](live-capture.json) provides task-boundary evidence. The Responses comparison requires its own configured API key and model. Live B/C measurements, token use and between-repetition spread are pending. A recorded parser response exercises the candidate path in tests and contributes no live observations.

## Dataset and scoring

The [versioned manifest](manifest-v1.json) contains 48 cases, 12 per class. Each two-case family belongs to a single split. There are 16 development cases and 32 held-out cases, eight per class. The manifest includes the fixture text, author label, rationale, eligible-repair flag and review status. A deterministic materializer generates inert credential values at runtime. The scorer checks the [frozen SHA-256](manifest-v1.sha256) before every run. Independent human label review is pending.

The unit is one change evaluated against its nominated class. A static match counts as a detection. Exact labels for all classes and the two eligible search fixes were frozen before the new detectors were tuned. Close variants within families and the small sample limit generalization. An initial run exposed a duplicate argument in guard evidence serialization. That run marked four checks incomplete. The final run uses the corrected serializer with the original manifest and rules.

| System | TP | FP | TN | FN | Precision | Recall | False-positive rate | Verified fixes |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| A · regex | 14 | 10 | 6 | 2 | 14/24 | 14/16 | 10/16 | Inapplicable |
| Offline deterministic template | 12 | 0 | 16 | 4 | 12/12 | 12/16 | 0/16 | 2/2 proposed, 2/2 eligible |
| B · one model pass | — | — | — | — | — | — | — | Pending |
| C · split with model | — | — | — | — | — | — | — | Pending |

Precision uses TP/(TP+FP), recall uses TP/(TP+FN), and false-positive rate uses FP/(FP+TN). Incomplete detections have their own count and are excluded from the confusion matrix. Proposed and eligible denominators remain visible even when verification fails. A zero denominator is `null` in JSON and a dash in the generated table. The two verified candidates had zero observed SQLite regressions. On the six positive **query** cases, detection recall was 4/6 before requiring verification and 2/6 afterward. The two detected concatenation cases had no supported repair. [Per-class table](results-offline.md) · [Per-case records](results-offline.json)

## Timing

The evaluator measures elapsed time from availability of a prepared input to its verdict and, where applicable, its verified candidate. Live task timing starts when the bounded coding task finishes. Push latency spans the actual `git push` process, including the hook and local transport. The rehearsal record also contains time spent inside the gate. [Five rehearsal traces](rehearsals.json)

| Measurement | Observed |
| --- | --- |
| 32 held-out inputs, summed processing time | Regex 0.119 ms · offline pipeline 28.18 s |
| Authenticated Codex task completion to verdict | 3.079 s |
| Prepared task completion to verified patch and verdict, five runs | 3.256–3.370 s for each endpoint at millisecond resolution |
| Real intermediate-secret push, five runs | 872–877 ms, all blocked |
| Real clean follow-up push, five runs | 604–608 ms, all allowed |
| Clean-branch interruptions | 0 of 10 initial and follow-up clean pushes |
| Extended rehearsal wall time | 9.967, 9.814, 9.811, 9.945 and 9.972 s |

The offline systems made zero provider calls. Their token fields are null. The timing comparison includes scanner startup and fixture verification in the offline pipeline. The regex baseline runs in-process.

## Failure analysis

| Held-out family | Expected label | Offline outcome | Consequence |
| --- | --- | --- | --- |
| `secret/encoded` | Positive | Two misses | The pinned Gitleaks rule inspects literal synthetic values. Encoded fixture values remain undetected. |
| `query/cross-file` | Positive | Two misses | The scoped Semgrep rules do not trace values across modules. No repair was proposed. |
| `query/composed` | Positive | Two static findings, zero proposals | The signal is visible for manual repair. The deterministic template supports only the original interpolation expression. |
| `query/business` | Negative for parameter binding | Two clean query checks | The bound arguments satisfy this property. Incorrect result ordering is a separate business-rule defect outside this evaluation. |
| `dependency/build-script` | Negative for the advisory | Two correct negatives and recorded install-script changes | A legitimate native build earns a metadata notice. No upgrade test was exercised. |

A clean scan covers the named tools, paths, fixture policy and pinned advisory. Expanding the corpus or detector coverage changes the research question and requires a new manifest version.
