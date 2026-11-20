# Review the release

A judge can review a local file read-only with `laundromat review /absolute/path/to/routes.js --format json`. For a change that has not been written, use `laundromat review --repo /path/to/preimage --diff proposal.diff`. Use `--class supply-chain` for new lifecycle declarations or `--class slopsquatting` for the offline name index. The report gives the searched parent paths, recognized uses, unknowns and class-specific observations. The working tree stays at its original hash during review.

Run `laundromat --demo --scenario injection` for the independent SQL, command and prompt fixtures. Inspect a wrapper proposal with `laundromat capture DIR annotate-search --proposal --prepared`, then use the reported ID with `show`, `accept` or `reject`. The default capture remains post-task. Install the pre-push hook only in the repository that should use it. Use `laundromat show ID --json` to inspect commit scope, policy, evidence, timestamps and restoration hashes. [Installation, data retention and external-code coverage](../README.md)

## Release validation

The wheel test took 119.3 seconds in a clean venv and unrelated directory. It verified setup, both receipt and ledger apply/undo, a real pre-push hook and local remote update, all six scenarios, repeated seed import and dashboard assets. The installed wheel contains 59 entries. The original and restored search both hashed to `2ff4c4305367223fe57bdc351cb27f7189dc2f44a637ad78e5fb452f4885a475`. [Wheel inventory and observations](../release/wheel-contents.json) · [Artifact checksums](../release/SHA256SUMS)

All 27 backend tests passed in 80.9 seconds. Type checking and the production frontend build passed. In an isolated Chrome profile, a prepared capture displayed its unknown scope, survived a reload, transitioned to its result on the same page, and displayed the completed result after another reload. Fault injection covered a missing scanner, wrong expected row IDs, a timed-out container and unconfirmed teardown. The affected checks denied application. The real non-root calibration observed both the install-stage marker and Node v22.21.0. In the packaged run its warm start took 272 ms and the container was removed.

The separate demo ledger holds 39 synthetic scans and 20 findings, including six property confirmations and an observed apply/restore pair. A second seed retained the same counts. All 106 previously recorded scan IDs and statuses in the real ledger matched their values before seeding. [Measured research results](../Research/results-offline-v2.md)

## Earlier four-minute final review

Complete the [clean-checkout setup](../README.md) before the presentation. Keep two terminals in the repository root with `source .venv/bin/activate` active.

| Time | What to show |
| --- | --- |
| 0:00–0:45 | In terminal one, run `python scripts/final_demo.py`. Show the captured one-line comment and the finding at `search.js:3`. The command labels the offline task as a prepared replay. The [recorded live capture](../Research/live-capture.json) contains the same edit from a real Codex run on a dirty repository, with its hashes and task exit. |
| 0:45–1:30 | Read the original and candidate parameter-binding results. The original passed zero arguments and used different SQL for amber and indigo. The candidate bound one argument to constant SQL. SQLite preserved `[101,109]`, `[104]` and `[]`. Compare the explicit apply and undo receipts. |
| 1:30–2:15 | Show the blocked push. An intermediate commit added a synthetic credential and its child removed it. The local remote kept its original object. The clean branch then advanced the same remote ref. The terminal prints both object IDs. |
| 2:15–3:10 | Run `laundromat scan demo/recorded --prepared` and `laundromat serve` in terminal two. Open [history](http://127.0.0.1:8731/), select the prepared task, and refresh its repair evidence link. Show the restored state. The recorded package scan also shows the advisory and a separate legitimate install script. |
| 3:10–4:00 | Run `cat Research/results-offline.md`. On 32 held-out cases, the template pipeline produced zero false positives and missed four positives. Two misses came from encoded synthetic values. A literal-only credential rule left those cases undetected. [Full comparison](../Research/README.md) |

To show a fresh **live** capture, run `python scripts/final_demo.py --live-agent`. It uses the existing Codex CLI login. To inspect or drive a single prepared snapshot by hand, use a new temporary directory.

```sh
review_dir=$(mktemp -d)
cp demo/fixture/*.js "$review_dir/"
laundromat scan "$review_dir" --prepared --json > "$review_dir.scan.json"
scan_id=$(python -c 'import json,sys; print(json.load(open(sys.argv[1]))["id"])' "$review_dir.scan.json")
laundromat show "$scan_id"
laundromat apply "$scan_id" --json
laundromat undo "$scan_id" --json
cmp demo/fixture/search.js "$review_dir/search.js"
```

## Local push policy

The gate reads every update on stdin and peels commit refs. It computes a union of outgoing commits with `git rev-list` and reads trees and blobs from the Git object database. For a local bare remote it also subtracts locally available commit tips already on that remote. For other transports it uses the bases supplied by Git. A new network branch can therefore conservatively include already published ancestry. Decisions use local objects and local tools. The hook provides developer protection on machines where it is installed.

Gitleaks scans the text blobs in each outgoing commit and commit messages using the pinned synthetic rule. It scans each distinct blob once and records the commit and path of its matches. Query, route and lockfile rules examine outgoing tips. Deletions and empty updates transfer no new commits. Missing specified bases, shallow history, unreadable data, binary blobs, submodules and files over 2 MB can make required coverage incomplete.

| Evidence | Decision |
| --- | --- |
| P1 strong synthetic credential in outgoing history | Block, even if the tip removed the value. |
| Incomplete required scan | Block and print the cause. |
| P2 affected npm release with a known fix | Require `laundromat acknowledge SCAN_ID FINDING_ID` and repeat the push. A changed snapshot requires a fresh acknowledgement. |
| P3 query or missing guard | Report for review. |
| P4 recorded install-script change | Report as package metadata. |
| Complete scan satisfying policy | Allow. |

Existing pre-push hooks and `core.hooksPath` configurations are preserved. The installer reports conflicts. An owner maintaining an existing hook can integrate `laundromat gate --repo . --remote "$2"` and forward the complete ref-update stream. Every participating check needs its own copy of stdin. The hook maps success to 0 and any refusal or error to 1.

## Script exit codes

| CLI operation | 0 | 1 | 2 |
| --- | --- | --- | --- |
| Phase 1 `demo [--json]` | Verified parameter binding | Unverified | Incomplete |
| `scan`, `capture`, `retry` | Completed, including static findings | — | Incomplete or invalid request |
| `gate` | Allow | Block or acknowledgement required | Invocation error |
| `apply`, `undo`, `acknowledge`, `install-hook`, `import-receipt`, `register`, `show` | Completed | — | Refusal or invalid request |

## Coverage and evidence boundaries

- The search verifier executes only the known team fixture and narrowly validated replacement bytes. It uses a cached official `node:22.21.0-alpine` image by immutable digest with `--network=none` when available. Otherwise it records `disposable local copy`. Other JavaScript receives static analysis. The template supports one search expression.
- The guard rule parses the fixture’s declarative `router.get` registrations in `routes.js`. `/orders` and `/orders/:id` require `requireUser` before the handler. `/health` and `/about` are explicitly public. Unsupported syntax or policy paths yield incomplete coverage. Each observed route has its line and middleware list.
- The offline advisory adapter covers exact three-part npm releases in package-lock v2/v3, using the pinned advisory for lodash. The finding includes the affected range, fixed version, package path, evidence date and upgrade-test status. Recorded package metadata is inspected without running installation scripts. Missing script inventories or parent source produce unknowns. [Pinned advisory source](https://github.com/advisories/GHSA-p6mc-m468-83gw)
- Static matches, route-policy mismatches and advisory matches retain their own evidence. The runtime verdict applies specifically to parameter binding. The Gitleaks configuration covers the team's nonfunctional test format. Detectors have the measured blind spots described in the evaluation.

## Recheck the rehearsal

```sh
python scripts/final_demo.py --extended --runs 5 --out /tmp/laundromat-rehearsals.json
```

The extended sequence adds a real blocked P2 push, the acknowledged retry, a required-tool outage and a two-ref push. Each run creates fresh repositories and verifies the remote objects, backup restoration, and redaction. [Recorded timings and ref evidence](../Research/rehearsals.json)

## Observed acceptance results

The clean setup used a separate checkout copy and virtual environment. Dependency checks, the production build, the Phase 1 demo and the final demo passed there. The full suite passed 14 tests, including abrupt worker termination, retry, receipt import across reset, stale file protection and real pushes.

Two identical HTTP submissions returned 202 with the same scan ID. Different content with the same key returned 409. After a process restart the scan still had one job attempt and the same ordered queued, running and findings events. The browser displayed the offline-created scan, recorded install-script change, empty repository state, loading indicator, incomplete history, cached evidence during an outage, and the restored repair after deep-link refresh.

The five timed rehearsals used the disposable local verifier. A separate run used the pinned Node 22.21.0 Alpine image with networking disabled. Parameter binding failed on the original and passed on the candidate. Both versions returned the expected IDs for all three terms. To repeat the container check, cache the image and scan with a fresh request key.

```sh
docker pull node@sha256:bd26af08779f746650d95a2e4d653b0fd3c8030c44284b6b98d701c9b5eb66b9
laundromat scan demo/fixture --prepared --key container-review --json
```

The repair's `sandbox` field records the runtime used. Live API-model measurements require the two environment variables documented in the [evaluation](../Research/README.md).
