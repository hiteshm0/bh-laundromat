# Finish Laundromat after Phase 1

You are implementing the rest of Laundromat in the team’s existing `bh-laundromat` checkout. Deliver a working local developer tool, a reproducible research comparison, and a four-minute final demo. Make the changes, run the software through its public entry points, fix failures, and document the commands and observed results. Work through the milestones in order without waiting for approval between routine implementation decisions.

## 1. Start from the actual checkout

Read `README.md`, `Docs/review-1.md`, `Backend/pyproject.toml`, `Backend/laundromat/`, `Backend/tests/test_phase1.py`, and `demo/`. Inspect Git status and preserve existing work. The reviewed project plan, if available, is background. This brief settles the implementation choices for the final build.

The current checkout has a Python/Typer CLI, a Semgrep rule, a Node/SQLite search fixture, and a template repair with a verification suite. FastAPI and React are new work in this checkout. Reuse the existing implementation if the branch has advanced since this brief was written.

Activate the project environment, install the editable package if needed, and run `python -m unittest discover -s Backend/tests -v`. Use disposable copies for rehearsals. Preserve the following Phase 1 contracts.

- `laundromat setup`, `reset`, `demo [--json]`, `apply RECEIPT`, and `undo RECEIPT` keep working. The demo exits 0 for verified, 1 for unverified, and 2 for incomplete. Existing schema-v1 receipts remain readable and usable under their original integrity checks.
- With ordinary search terms, the original fails the binding check, the candidate passes it, and the safe control stays clean. SQLite returns IDs `[101, 109]` for amber, `[104]` for indigo, and `[]` for jade on both versions. Keep those expectations independent of the code under test.
- The verified property is **parameter binding**. Use that wording in the CLI, UI, and research report. A static finding, a policy mismatch, an advisory match, and a verified repair each carry different evidence.
- Phase 1 reset replaces the marked `.laundromat/` tree. Store durable project history outside that reset boundary, or migrate it with an explicit compatibility test. Resetting a demo must preserve prior project scans.

## 2. Capture one finished task and persist its evidence

Build one bounded wrapper for a supported coding-agent CLI. Pick one the team can actually run and document its invocation. Launch it locally with an argument vector and a timeout. From a specified local repository, capture a before snapshot, run one explicitly requested coding task, capture the after snapshot, and scan the changed scope. Record repository identity, revision where available, file hashes, additions, modifications, deletions, task exit status, and time from task completion to verdict. Account for relevant untracked files and pre-existing dirty changes. Show the delta between those snapshots. If concurrent edits make authorship ambiguous, say so. An interrupted task must leave an honest partial record.

Provide a scan entry point independent of the wrapper so the team can inspect a local snapshot or replay a prepared fixture without an agent credential. Label captured edits, prepared snapshots, and replayed results at the point where users see them. A live wrapper run should support a benign edit such as correcting the existing search function. A prepared before snapshot can demonstrate the original finding.

Use FastAPI, Pydantic, SQLite, and one local worker. Keep the existing CLI and add the smallest shared application layer needed by the CLI, API, worker, and hook. SQLite should persist repositories, scans, findings, jobs, ordered events, and repair references. A scan identifies its trigger, exact scope and snapshot, tool/rule versions, coverage, elapsed time, and any incomplete checks. A finding records its source, category, location, severity, evidence, and a redacted explanation. A repair records its origin, diff hash, test-suite version, outcomes, and apply/undo state. Import Phase 1 evidence without rewriting the original receipt.

Implement `POST /scans`, `GET /scans/{id}`, and cursor-based `GET /events?after=…`. Add the listing endpoints the UI actually consumes. Submitting the same scan twice must return the same logical scan and create one job. Reject reuse of an idempotency key with different content. Persist results before making completion visible. A worker restart must identify interrupted work and support a retry without duplicating findings or decisions. Bind locally by default. The CLI and push gate must still work when the dashboard service is stopped.

**Acceptance.** Capture one edit that starts from a dirty fixture. Match the recorded diff and file hashes to that edit. Submit the scan twice, restart the service, and retrieve the same evidence and ordered timeline. Show how a scan produced while the service was offline becomes visible later.

## 3. Finish the four defensive checks and the repair path

| Check | Required behavior | Evidence to show |
| --- | --- | --- |
| Unsafe query | Reuse the scoped Semgrep rule. Run the same trusted adapter and SQLite behavior checks on the supported original and candidate. Keep other query styles visible as unsupported for repair. | Rule, file and line, before/after binding observations, expected and actual IDs, rescan outcome. |
| Synthetic secret | Use Gitleaks with pinned rules on the selected changes and outgoing Git history. Use nonfunctional synthetic values for tests. Redact before persistence, logging, rendering diffs, or sending context to a provider. | Rule, redacted location, commit, and policy decision. Validate locally. |
| Missing access guard | Define the team fixture’s route policy, then compare its declared guard requirements with the source using a scoped static rule. Cover one compliant case, one missing guard, and a deliberately public route. | Expected guard, observed source location, and `needs review`. State the route-level coverage. |
| Vulnerable dependency | Use OSV-Scanner or a clearly labeled offline adapter with pinned advisory data. Match ecosystem, exact resolved version, and affected range from a supported lockfile. Cover one affected and one fixed version. | Advisory identifier, resolved version, range, known fixed version, evidence source/date, and dependency path when available. Record upgrade-test status only if exercised. |

Keep scanner process status separate from its findings. Record required-tool failure, unreadable inputs, unavailable advisory data, and unsupported scope as incomplete or unknown with a specific reason. Make severity, evidence, repair status, and push decision distinct fields. Retain unverified findings and record why a check failed or did not run.

Implement Detect, Verify, and Fix as separate components with explicit inputs and outputs. The deterministic controller owns verdicts. Verify uses fixed, checked-in defensive checks on ordinary inputs. The supported repair is a parameterized replacement for the one existing search pattern. Add one configurable model provider for explanations and candidate fixes, with credentials supplied through the environment. A provider receives only the minimal redacted fixture context. Accept a narrowly scoped candidate edit, validate its shape and permitted file before running the fixed checks, and record its actual origin. Retain the existing labeled template fallback for offline use. A model failure must preserve the finding.

Extend apply/undo to the supported captured search change. Keep explicit apply as the default. Bind each operation to the exact repository, snapshot, touched path, patch, and validated candidate bytes. Save the original before replacement, refuse stale apply and conflicting undo, and preserve unrelated edits. Record applied and restored hashes. Keep Phase 1’s template-specific integrity checks for its receipts and use equivalent verification for new model receipts. Never execute commands proposed by a model or found in scanned source. Execute fixture checks only on the supported team-owned demo. Use a pinned no-network container when available, or identify the fallback as a disposable local copy.

**Acceptance.** Each class has a positive and a clean control. Demonstrate a scanner outage, an unsupported repair, and model unavailability. The supported search repair must pass its original behavioral gate, apply explicitly, and restore the original bytes. Verify that the synthetic secret value is absent from the terminal, database, JSON, dashboard, and model context.

## 4. Make one real Git push decision

Provide an explicit command to install the local pre-push hook in a chosen repository. Preserve an existing hook or custom hooks configuration and explain any conflict. Use temporary repositories and a local bare remote for automated tests and rehearsals.

Read all ref updates supplied by Git. Determine outgoing history from Git objects, including a new branch and multiple refs. Handle deletions, empty updates, and unavailable base objects deliberately. Scan the commits that would leave the repository, including a synthetic secret added in an intermediate commit and removed before the tip. Keep the decision local and deterministic. It must work with the API stopped and without model access.

Adopt this initial policy and document it. A strong secret in outgoing history blocks. An incomplete required history scan blocks with a specific reason. P2 warnings include a fixed-version dependency advisory and require acknowledgement scoped to the finding and snapshot. P3 review items and P4 informational items are reported. A clean result allows the push. Keep hook exit behavior simple and publish a separate exit-code table for scriptable CLI commands. Preserve the existing Phase 1 codes. Support machine-readable JSON for new noninteractive CLI operations.

**Acceptance.** Invoke actual `git push` commands to the bare remote. Prove the remote ref stays unchanged on a blocked push and moves to the expected object on a clean push. Also test the incomplete case, P2 acknowledgement, and a multi-ref push. Record redacted output and elapsed time. Describe the hook as local developer protection.

## 5. Build the dashboard and dependency-change view

Build a small React and TypeScript frontend under `Frontend/`. Use Vite for development and serve the production build with the API from one origin. Start with polling and a persisted event cursor. Implement these three views.

1. **Repository history.** Show scans over time with trigger, snapshot, coverage, status, and counts by class. Distinguish clean, incomplete, and never scanned.
2. **Scan detail.** Show the changed files, redacted finding locations, severity, evidence, plain-language explanation, and push decision with its reason.
3. **Repair evidence.** Show the redacted diff, candidate origin, original/candidate checks, normal search results, timing, and current apply/undo state. Display the matching CLI command for explicit actions.

Add the dependency-change warning using recorded package metadata. Show when an exact resolved package version gains an install-time script. If recorded parent-package source is available, show whether that parent references the new dependency. Mark missing data unknown. Include a legitimate install-script example and keep this signal separate from a known advisory. Use metadata only. Label recorded data throughout.

**Acceptance.** Run the production build, open the UI against the real API, inspect a real scan, refresh a deep link, and restart the backend. The same history and evidence should return in order. Check empty, loading, incomplete, and offline states. If browser verification is unavailable, report exactly which API and build checks ran.

## 6. Run a reproducible evaluation

On a held-out set of team-owned synthetic changes, does separating detection, verification, and repair improve detection precision and verified-fix rate? What does it cost in time and model usage?

- **Dataset.** Target 10–15 labeled cases per class, including safe look-alikes and difficult cases. Group close variants before making the development/held-out split. Freeze a versioned manifest and record a digest before tuning. Keep labels and expected results out of model input. Record each label’s rationale and review status. Identify any pending human review honestly.
- **Systems.** A is a simple static/regex baseline. B is one model pass that returns findings and a candidate repair where supported. C is the split pipeline with a model-generated repair. Use the same provider, model version, fixture context, total context budget, and final verifier for B and C. Keep deterministic fallback runs in their own row. Static-only A has no applicable fix rate. Record prompts, parameters, versions, and dataset digest.
- **Runs.** Supply one evaluation command with an offline mode and an opt-in live-provider mode. Run A and all locally available checks. With a configured provider, run B and C on the same held-out cases for at least three repetitions and report the spread. Without provider access, finish the adapter, scorer, offline tests, and runnable command. Mark the affected measurements pending. A recorded response may test the parser but cannot count as a live result.
- **Metrics.** Report sample size, TP, FP, TN, FN, precision, recall, and false-positive rate per class and overall. Define the unit of comparison. Show verified fixes over proposed repairs and over eligible cases, plus any behavioral regressions. Report detection recall before and after requiring verification, scoped to supported classes. Measure time from task finish to verdict and verified patch, push latency, clean-branch interruptions, and token usage when available. Keep incomplete observations and zero denominators visible.
- **Failure analysis.** Include fixtures or observations for an encoded synthetic secret, a cross-file flow outside the rule’s scope, a business-rule defect, an unsupported query style, and a benign dependency script. Show the expected label, actual outcome, and reason. Distinguish a missed finding from a detected finding without a supported repair.

Write machine-readable results and a short human-readable table generated from those results. Record the commands and environment needed to reproduce them. Report negative results and actual sample size. Include no estimated performance percentages.

## 7. Rehearse and hand off

Update the root README with a clean-checkout setup, tool versions, CLI entry points, server startup, and links to the runbook and evaluation. Keep `Docs/review-1.md` usable. Provide a final runbook that a teammate can follow in four minutes.

1. Show the exact captured change and its finding.
2. Compare the original and candidate evidence, apply the verified patch, and show the undo receipt.
3. Demonstrate the blocked intermediate-secret push and a clean push to the local remote.
4. Refresh the dashboard, then show the measured comparison and one failure with its consequence.

Run the original tests, new integration tests, frontend checks and production build, real push tests, and evaluation commands. Rehearse the core flow five times from disposable resets. Record the actual pass count and timings. Check fresh setup independently of any already-installed editable package. Keep generated secrets, databases, virtual environments, dependency trees, and raw provider logs out of Git. Include only compact, redacted evaluation and demo evidence intended for teammates.

Prioritize the working CLI-to-receipt path, real Git gate, persistent dashboard, and measured comparison. Second-laptop viewing, optional automatic apply, extra package-name heuristics, and dashboard polish come after these pass. If an external dependency is unavailable, finish all independent work and give the exact command that will complete the missing verification.

End with (1) what shipped, (2) commands to run the demo and evaluation, (3) test and rehearsal results you personally observed, and (4) remaining gaps with the affected claims. Hand back something a teammate can run from the README.
