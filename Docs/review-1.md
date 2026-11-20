# Review 1 · Verify a search repair

Run these commands from the repository root in Bash or Zsh on macOS or Linux. The setup below uses Python 3.13 and Node 22.21. The fixture uses Node’s built-in `node:sqlite`. Package installation needs network access. Subsequent runs use a local Semgrep rule and an in-memory database.

## One-time setup

```sh
python3.13 -m venv .venv
source .venv/bin/activate
python -m pip install -e ./Backend
laundromat setup
```

The editable install locates the fixture and rule in this checkout. Setup copies the two source files from `demo/fixture/` into `.laundromat/workspace/`. Repeating setup preserves the workspace. Reset discards edits, receipts, and backups inside the marked `.laundromat/` directory and restores the fixture.

## Two-minute demo

```sh
source .venv/bin/activate
laundromat reset
laundromat demo
```

Read the reported location, before/after table, and one-line diff. The workspace still contains the original search. After this fresh reset and single demo, the glob below selects that run’s receipt. When keeping several reviews, pass the exact receipt path printed by the chosen run.

```sh
laundromat apply .laundromat/runs/*/receipt.json
laundromat undo .laundromat/runs/*/receipt.json
```

Apply verifies the current search file against its scanned SHA-256, checks the candidate and diff, and saves the original bytes beside the receipt in `original.bin`. Undo checks the current file against the applied candidate’s SHA-256 before restoring those bytes. Both commands refuse a stale file and preserve edits to other files.

## Read the evidence

```sh
laundromat demo --json | python -m json.tool
```

Each run saves the same JSON it can print in `.laundromat/runs/<run-id>/receipt.json`. Its sibling `repair.diff` contains the unified diff. Finding paths are relative to the scanned fixture snapshot. The snapshot hash covers a sorted JSON manifest of the two source filenames and their SHA-256 hashes. The patch hash covers the exact diff bytes.

The adapter probe calls the exported search twice and records each SQL string passed to `prepare` and each argument list passed to that statement’s `all`. The original uses different SQL strings with empty argument lists. The template candidate uses the same SQL string with a single placeholder and binds `amber` or `indigo`. A separate Node process runs the identical search function against SQLite seeded from `demo/seed.sql`.

| Check | Original | Candidate |
| --- | --- | --- |
| `laundromat.interpolated-search` | 1 at `search.js:2` | 0 |
| `safe-search.js` findings | 0 | 0 |
| Constant SQL and separate bound argument | Fail | Pass |
| SQLite IDs for `amber` | `[101, 109]` | `[101, 109]` |
| SQLite IDs for `indigo` | `[104]` | `[104]` |
| SQLite IDs for `jade` | `[]` | `[]` |

`verified` requires the binding change from fail to pass, the single finding to clear, a clean scanned control in both phases, and exact ordered IDs for all three cases in both phases. A completed review that misses a condition returns `unverified` (exit 1). An unavailable check returns `incomplete` (exit 2) with its reason. A verified review exits 0.

## Repeat the acceptance checks

```sh
python -m unittest discover -s Backend/tests -v
```

The checks use temporary checkouts. They compare two fresh receipts, verify apply and undo byte-for-byte, and exercise stale files, missing Semgrep, and mismatched expected IDs.
