# THE MAIN BRANCH WAS FOR DEVELOPING THE PROTOTYPE INCREMENTALLY, SWITCH TO "contains-vulnerable-site"  branch for the final repo containing the vulnerable site for the demo

## we are doing this to make sure we have a branch with clean pushed code that reviewers can check instead of getting distracted by our experimental main branch where everyone commited there things

### Laundromat

Laundromat reviews a proposed change, a local snapshot, or the outgoing objects in a Git push. The CLI and local dashboard distinguish static candidates, observed fixture properties, repair application, and push policy. The pre-push graph supports one runtime repair contract for a Node/SQLite inventory service. Snapshot reviews retain their existing fixture adapters.

## Install the Detect → Prove → Fix hook

From this source checkout, use Python 3.11+, Git, Go (for OPA), and Docker with Linux ARM64 support. Build and install the current source to get the graph and dashboard.

```sh
python3 -m venv .venv
source .venv/bin/activate
npm ci --prefix Frontend --ignore-scripts
npm run build --prefix Frontend
python -m pip install -e ./Backend
laundromat-install-gitleaks
GOBIN="$VIRTUAL_ENV/bin" go install github.com/open-policy-agent/opa@v1.8.0
docker load -i release/verifier-linux-arm64.tar.gz
```

**Add the API key to the ignored `.env.local` file in this checkout.** For Groq Studio, set `LAUNDROMAT_PROVIDER=groq` and add your key under `GROQ_API_KEY`. The example selects `openai/gpt-oss-20b` on Groq for all three roles. OpenAI remains the default when the provider setting is omitted and uses `OPENAI_API_KEY` with your OpenAI model ID. Load the file in the terminal that runs Git. The hook inherits that environment. A Git client launched independently needs the same exported variables in its launch environment.

```sh
cp -n .env.example .env.local
chmod 600 .env.local
${EDITOR:-vi} .env.local
source ./.env.local
```

Install the hook once in the repository to review. The mode commands work anywhere inside that repository. Only the mode is stored under `laundromat.mode` in local Git configuration.

```sh
laundromat install-hook /path/to/repo
cd /path/to/repo
laundromat switch developer
laundromat mode --json
git push
laundromat show SCAN_ID
laundromat approve SCAN_ID
git diff --cached
```

Developer is the default. Approval checks the reviewed branch, commit and affected bytes, then stages the verified hunk. To authorize automatic staging, run `laundromat switch vibe-coder`. A push with a verified repair stops in both modes. Review and commit the staged changes yourself, then push again. Overlapping edits and ambiguous ref assignments leave a proposal in the receipt. A credential in an intermediate outgoing commit still blocks after a later deletion.

### Reproduce the inventory review

From this checkout with the virtual environment active, select a run:

```sh
python scripts/push_demo.py --mode developer
python scripts/push_demo.py --mode vibe-coder
python scripts/push_demo.py --mode vibe-coder --mock-provider
python scripts/push_demo.py --mode developer --dashboard
```

Each invocation creates a disposable repository, bare remote and separate SQLite ledger. By default the demo uses your exported model credentials. `--mock-provider` uses labelled mock Responses and real scanners, Git and Docker. The terminal shows live review progress, the verified diff, and the next command for your mode. In developer mode, the fix is staged only when you run the printed approval command.

Add `--dashboard` to open the review in your browser from the same terminal. The demo starts a local dashboard on an available port and prints its URL and stop command. Use `laundromat show SCAN_ID --json` with the same `LAUNDROMAT_HOME` to read the full receipt.

The packaged Rego policy handles strong credential matches and dependency acknowledgements locally. Detect reviews new code-pattern candidates with a redacted excerpt and location. For the approved inventory service, Prove authors cases over ordinary aisle names and ordered SKU results. A trusted adapter freezes the test, observes statement text and bound arguments in Docker, and records the original result. An observed binding violation allows Fix to return a one-line replacement. Certification requires the candidate to pass the frozen test, the checked-in inventory regression and the detector recheck. Other services retain static findings. Each push has at most nine provider requests, 6,500 input characters and 700 output tokens per call, a 25-second call timeout, and a 150-second window to start model work. A required role or verifier failure blocks as incomplete.

## Install the earlier 0.2.0 release

Use Python 3.11 or later, Git, and Gitleaks 8.28.0 on macOS or Linux. The release was exercised with Python 3.13 and Node 22.21.0. The wheel includes the Semgrep and Gitleaks policies, fixture inputs, offline metadata, expected observations, and production dashboard. Pip installs the Python dependencies, including Semgrep. The supplied verifier image is Linux ARM64.

```sh
python3 -m venv .venv
source .venv/bin/activate
python -m pip install release/bh_laundromat-0.2.0-py3-none-any.whl
laundromat-install-gitleaks
docker load -i release/verifier-linux-arm64.tar.gz
laundromat doctor --strict --json
```

The image archive supports offline use on a Docker host capable of running Linux ARM64. Strict checks select the packaged image digest, use a fresh non-root container per test, mount a single validated input read-only, disable networking and capabilities, and bound CPU, memory, processes, and elapsed time. Each receipt includes the container identity, suite digest, observations, duration and removal status. A daemon or image outage produces incomplete verification. The legacy SQL fixture can explicitly use local Node with `LAUNDROMAT_RUNTIME=local`. The schema-v1 `demo` command selects this compatibility mode and requires local Node with SQLite.

For editable development, install the backend with `python -m pip install -e ./Backend`, install the pinned scanner with the installer above, and run `npm ci --prefix Frontend --ignore-scripts` followed by `npm run build --prefix Frontend`. The release smoke test rebuilds the UI, constructs a wheel from the source allowlist, installs its dependencies in a new venv, and exercises it from an unrelated directory. [Release inputs](release-source.txt) · [Wheel inventory and measured hashes](release/wheel-contents.json)

## Review a file or a proposal

```sh
laundromat review /path/to/my-file.js
laundromat review /path/to/repo --class injection --format json
laundromat review --repo /path/to/repo --diff changes.diff --mode proposal
git diff --no-ext-diff | laundromat review --repo /path/to/matching-preimage --diff -
laundromat --demo --scenario supply-chain --json
```

Review reads the selected files and leaves the working bytes intact. A patch needs its matching preimage on disk. Supported unified text hunks are evaluated in memory. Edits to a manifest use the remaining parent tree for import and local metadata coverage. Snapshot review compares parent declarations against local HEAD where available. Unknown prior declarations, missing metadata, unsupported lockfiles and ambiguous source coverage are reported explicitly. The six scenario names are `secret`, `injection`, `guard`, `dependency`, `supply-chain` and `slopsquatting`. The injection scenario includes independent SQL, argument-vector and prompt-role cases.

| External check | Measured scope |
| --- | --- |
| Literal credential formats | Pinned Gitleaks patterns for the synthetic key and selected GitHub, API key and AWS access-ID shapes. A match establishes the shape. Credentials are redacted and reviewed locally. An outgoing-history match requires owner remediation. |
| SQL, command arguments and message roles | Local Semgrep patterns for interpolated and concatenated query text, direct command construction and nonliteral instruction-role content. Runtime confirmation requires a matching team-owned adapter. |
| Route guards | Supported declarations in `routes.js` against the packaged method/path policy. Undeclared routes and unsupported syntax have incomplete coverage. |
| Dependencies | npm lockfile v2/v3 exact releases against the packaged advisory range. The owned regression exercises ordinary SQLite catalog results with the repaired lock metadata present. Third-party dependency behavior is outside that observation. |
| Install metadata | New dependency plus a declared install hook plus complete parent coverage with no recognized use. The checker parses JS/TS module references and supported commands/config. Recorded version changes, structural warnings and the independent Node calibration have separate evidence. |
| npm package names | Added names are compared with the versioned similarity index. Review also checks public npm registry availability for registry dependencies. A definitive HTTP 404 produces a P3 finding. A standalone manifest can be checked for existence without a Git baseline. The pre-push hook and synthetic replays use the offline checks. |

Encoded secrets, cross-module data flow and business logic are outside the measured properties. Positive and clean results carry these limits. The scoped tools do not install repository dependencies or run their scripts.

## Review an agent edit before writing

```sh
review_dir=$(mktemp -d)
cp demo/fixture/*.js "$review_dir/"
laundromat capture "$review_dir" annotate-search --proposal --prepared --json
laundromat show SCAN_ID
laundromat accept SCAN_ID
laundromat undo SCAN_ID
```

This is an opt-in wrapper approval boundary. Omit `--prepared` to request the bounded edit from an authenticated Codex CLI. The wrapper obtains a candidate from an empty temporary directory, compares the proposed and original snapshots, and records the hunk before touching the watched file. `reject SCAN_ID` leaves the file intact. Acceptance rechecks the working snapshot and revision, saves distinct working and proposed references, and atomically writes the accepted bytes. `--proposal --auto-apply` authorizes a verified repair for that invocation only. Ordinary `capture` records the post-task delta. The live capture saved under Research is an earlier post-task observation.

For snapshot repairs, use `laundromat apply SCAN_ID` and `laundromat undo SCAN_ID`. On scans with multiple repairs, select one with `--finding FINDING_ID`. The receipt records the diff, hashes, verification property, template/model origin and application actor. Legacy `setup`, `demo --json`, `apply RECEIPT`, `undo RECEIPT`, `reset` and `import-receipt RECEIPT` remain available.

Text reviews and demos stream finding and fixture-check progress. JSON output contains the receipt. For a quoted credential, review the redacted substitution diff, configure the indicated environment variable, and rotate the exposed credential. To apply a reviewed structural candidate, run `laundromat apply-candidate SCAN_ID FINDING_ID`. Its private backup contains the original bytes and supports `laundromat undo SCAN_ID --finding FINDING_ID`.

## Git, history and the dashboard

```sh
laundromat install-hook /path/to/repo
laundromat register /path/to/repo
laundromat serve
laundromat seed-demo-history --json
laundromat serve --demo-history --port 8732
```

`laundromat demo-serve` seeds a missing demo ledger and serves it. Use `--reseed` to refresh the fixture receipts. Once seeded, the replay dashboard can display the recorded repair and rollback with Docker offline.

Hook installation is explicit and preserves existing hooks and custom hook paths. Pushes scan commit messages, intermediate file contents and all supplied refs. Detection reads outgoing Git objects. Staging follows the approval mode described above. Strong credential matches and incomplete required scans block. A P2 acknowledgement applies to the finding, repository and outgoing snapshot. A new branch may include already-published history when an exact exclusion is unavailable. Limits are 256 outgoing commits, 64 updates, 4,096 paths or blobs, 2 MB per file and 32 MB of distinct content.

The service binds to loopback. Open the repository history or refresh a scan at `/review/SCAN_ID`. Registered repositories can submit jobs through `POST /scans`. Transitions and receipt updates are durable in SQLite, and interrupted ordinary jobs can be retried. An interrupted capture needs a fresh task window. An abandoned push needs fresh Git refs. For Vite development, set `LAUNDROMAT_API_URL` to the desired loopback backend. [Local dashboard](http://127.0.0.1:8731/)

`LAUNDROMAT_HOME` selects the data directory. Installed defaults use `$XDG_DATA_HOME/laundromat` or `~/.local/share/laundromat`. A marked existing editable checkout retains its original lab and ledger defaults. `reset` replaces only the marked Phase 1 lab. Receipts, redacted observations, exact hashes, owned-fixture backups and journals otherwise persist until the owner removes the selected data directory. The marked `demo-replay-v2` child ledger contains traceable synthetic imports. Fresh repository history starts empty.

## Validate and compare

```sh
python scripts/test_release.py
python -m unittest discover -s Backend/tests -v
npm run check --prefix Frontend
npm run build --prefix Frontend
python scripts/check_dashboard.py
python Research/evaluate.py --out /tmp/laundromat-offline.json
```

The browser check needs Chrome and uses an isolated profile. For the optional live model comparison, load your provider configuration and pass `--live`. Systems A, B, split and template can be selected individually with `--arm`. The recorded response in the tests exercises parsing. [Current measurements and limitations](Research/README.md) · [Review commands](Docs/final-review.md)
