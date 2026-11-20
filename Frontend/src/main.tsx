import React, { useEffect, useState } from "react";
import { createRoot } from "react-dom/client";
import "./style.css";

type Fields = Record<string, unknown>;
type Summary = {
  id: string;
  created: number;
  status: string;
  trigger: string;
  snapshot: { repository: string; sha256: string };
  counts: Record<string, number>;
  coverage?: Fields;
  counts_summary?: { caught: number; confirmed: number; applied: number; adjudicated_false_positives: number; severity: Record<string, number> };
};
type Phase = {
  binding: { status: string; observations?: { term: string; statements: Fields[] }[] };
  sqlite: { status: string; results?: { term: string; actual: number[]; expected: number[] }[] };
  semgrep: { findings?: unknown[]; negative_control?: string };
};
type Repair = {
  test_id?: string;
  finding_id?: string;
  application_actor?: string;
  backup_reference?: string;
  original_sha256?: string;
  restored_sha256?: string;
  property: string;
  origin: string;
  state: string;
  verdict: string;
  diff: string;
  patch_sha256: string;
  suite: string;
  elapsed_ms?: number;
  before: Phase;
  after?: Phase;
  source_receipt?: string;
  model_issue?: string;
  model_explanation?: string;
};
type PushEvidence = {
  finding_id: string;
  state: string;
  reason?: string;
  change?: string;
  introducing_commit?: string;
  introducing_diff?: string;
  policy_route?: string;
  detect?: { reasoning: string; property: string; route: string };
  role_calls: { role: string; model?: string; outcome?: string }[];
  test?: Fields;
  test_sha256?: string;
  before?: { status: string };
  after?: { status: string };
  regression?: boolean;
  rescan?: Fields;
  property?: string;
  rationale?: string;
  patch?: string;
  staged_diff?: string;
  working_tree_issue?: string;
  committed_oid?: string;
};
type Detail = Summary & {
  mode?: string;
  updates?: { local: string; tip: string; remote: string; base: string }[];
  push_reviews?: PushEvidence[];
  staging_issue?: string;
  proposal_ready?: boolean;
  scope: string[] | null;
  recovery?: string;
  next_stage?: string;
  proposal_state?: string;
  scope_limits?: string[];
  transitions?: { id: number; finding: string | null; state: string; reason: string; actor: string; time: number }[];
  structural_observations?: Fields[];
  last_successful_observation?: { state: string; time: number; reason: string };
  last_observation?: { kind: string; time: number };
  verified_actions?: Fields[];
  changes?: { path: string; change: string; diff: string }[];
  findings: {
    id: string;
    path: string;
    line?: number;
    rule: string;
    severity: string;
    category: string;
    explanation: string;
    evidence: Fields;
    repair_status: string;
    state?: string;
    scope_limits?: string[];
    change?: string;
    property?: string;
  }[];
  repair: Repair | null;
  repairs?: Repair[];
  issues?: string[];
  task_status?: string;
  elapsed_ms?: number;
  task_to_verdict_ms?: number;
  push_decision?: { action: string; reason: string };
  dependency_changes?: {
    package: string;
    previous: string;
    resolved: string;
    gained: string[] | null;
    parent_references: boolean | null;
  }[];
};

const path = window.location.pathname.split("/");
const id = path[1] === "review" ? path[2] : null;
const repairView = path[3] === "repair";
const date = (n: number) => new Date(n * 1000).toLocaleString();
const tail = (p: string) => p.split("/").filter(Boolean).slice(-2).join("");

function coverageText(coverage: Fields = {}) {
  if (typeof coverage.outgoing_commits === "number")
    return coverage.outgoing_commits + " outgoing commits · " + coverage.history_blobs + " distinct blobs";
  return Object.entries(coverage)
    .flatMap(([name, check]) => {
      const status = (check as { status?: string })?.status;
      return status && status !== "outside scope" ? [name + " " + status] : [];
    })
    .join(" · ") || "Awaiting coverage";
}

function Badge({ value }: { value: string }) {
  return <span className={"badge " + value.split(" ")[0]}>{value}</span>;
}

async function read<T>(url: string): Promise<T> {
  const r = await fetch(url);
  if (!r.ok) throw Error(r.status === 404 ? "Scan not found" : "Local API unavailable");
  return r.json();
}

function Data({ value }: { value: unknown }) {
  return <pre>{JSON.stringify(value, null, 2)}</pre>;
}

function PushFinding({ item }: { item: PushEvidence }) {
  return <div>
    <p><Badge value={item.state} /> {item.reason || item.property}</p>
    {item.introducing_commit && <details><summary>Introducing change · {item.change}</summary>
      <code>{item.introducing_commit}</code>{item.introducing_diff && <pre>{item.introducing_diff}</pre>}
    </details>}
    {item.detect && <><h3>Detect</h3><p>{item.detect.reasoning}</p>
      <p>{item.detect.property} · {item.policy_route}</p></>}
    {item.test && <><h3>Prove</h3><details><summary>Frozen test specification</summary>
      <code>{item.test_sha256}</code><Data value={item.test} /></details>
      <p>Original · {item.before?.status || "pending"}<br/>Candidate · {item.after?.status || "pending"}</p>
      <details><summary>Test observations</summary><Data value={{ original: item.before, candidate: item.after, regression: item.regression, rescan: item.rescan }} /></details></>}
    {item.patch && <><h3>Fix · proposed diff</h3><p>{item.rationale}</p><pre>{item.patch}</pre></>}
    {item.staged_diff && <><h3>Staged diff</h3><pre>{item.staged_diff}</pre></>}
    {item.working_tree_issue && <p>{item.working_tree_issue}</p>}
    {item.committed_oid && <p>Committed in <code>{item.committed_oid}</code></p>}
    {!!item.role_calls.length && <details><summary>Model calls</summary><Data value={item.role_calls} /></details>}
  </div>;
}

function Evidence({ r, id, authorized, proposal }: { r: Repair; id: string; authorized: boolean; proposal: boolean }) {
  const phases = [r.before, r.after];
  return (
    <>
      <section>
        <h2>{r.property}</h2>
        <Badge value={r.verdict} />
        <p>{r.origin} candidate · {r.suite} · {r.elapsed_ms ?? "—"} ms · {r.state}</p>
        {r.model_issue && <p>{r.model_issue}</p>}
        {r.model_explanation && <p>Model explanation · {r.model_explanation}</p>}
        {r.test_id ? <Data value={{ original: r.before, candidate: r.after }} /> : (
          <>
            <table>
              <thead>
                <tr>
                  <th>Check</th>
                  <th>Original</th>
                  <th>Candidate</th>
                </tr>
              </thead>
              <tbody>
                {[
                  "Parameter binding",
                  "Semgrep findings",
                  "Safe control",
                  "amber",
                  "indigo",
                  "jade",
                ].map((k, i) => (
                  <tr key={k}>
                    <td>{k}</td>
                    {phases.map((p, j) => (
                      <td key={j}>
                        {!p ? "unknown" : i === 0 ? p.binding.status : i === 1 ? (p.semgrep.findings?.length ?? "unknown") : i === 2 ? (p.semgrep.negative_control ?? "unknown") : (JSON.stringify(p.sqlite.results?.find((row) => row.term === k)?.actual) ?? "unknown")}
                      </td>
                    ))}
                  </tr>
                ))}
              </tbody>
            </table>
            <details>
              <summary>Observed SQL, arguments and expected IDs</summary>
              <Data value={phases.map((p) => ({ adapter: p?.binding.observations, sqlite: p?.sqlite.results }))} />
            </details>
          </>
        )}
      </section>
      <section>
        <h2>Candidate diff</h2>
        <pre>{r.diff}</pre>
        <small>SHA-256 · {r.patch_sha256}</small>
      </section>
      <section>
        <h2>Explicit actions</h2>
        <p>{r.application_actor && "Applied by " + r.application_actor}</p>
        {r.backup_reference && <p>Backup · {r.backup_reference}</p>}
        <Data value={{ original: r.original_sha256, restored: r.restored_sha256 }} />
        <pre>
          {(r.state === "applied" ? ["undo"] : authorized && r.verdict === "verified" ? [proposal ? "accept" : "apply"] : [])
            .map((cmd) => "laundromat " + cmd + " " + (r.source_receipt || id) + ((!proposal && r.finding_id) ? " --finding " + r.finding_id : ""))
            .join("\n")}
        </pre>
      </section>
    </>
  );
}

class ReviewBoundary extends React.Component<React.PropsWithChildren, { failed: boolean }> {
  state = { failed: false };
  static getDerivedStateFromError() { return { failed: true }; }
  render() {
    if (this.state.failed) return <main role="alert"><h1>Review could not be displayed</h1>
      <button onClick={() => location.reload()}>Reload this review</button> <a href="/">Repository history</a></main>;
    return this.props.children;
  }
}

function WashingMachine() {
  return (
    <div className="wm-scene" aria-hidden="true">
      <div className="wm">
        <div className="wm-top"><div className="wm-lid" /></div>
        <div className="wm-front">
          <div className="wm-drum">
            <span className="wm-cloth c1" />
            <span className="wm-cloth c2" />
            <span className="wm-cloth c3" />
          </div>
          <div className="wm-glass" />
        </div>
        <div className="wm-water" />
        <div className="wm-bubble b1" />
        <div className="wm-bubble b2" />
        <div className="wm-bubble b3" />
        <div className="wm-glow" />
      </div>
    </div>
  );
}

function Landing() {
  const scenarios = [
    ["secret", "Secrets", "Credential-shaped text, keys and tokens detected before they leave the repo."],
    ["injection", "Injection", "SQL, argument-vector and prompt-role injection patterns blocked."],
    ["guard", "Guard", "Route and authorization guard coverage validated."],
    ["dependency", "Dependency", "Lockfile integrity and advisory checks."],
    ["supply-chain", "Supply chain", "Phantom dependencies and tampered installs surfaced."],
    ["slopsquatting", "Slopsquatting", "Similar-name squatting warnings for risky packages."],
  ];
  return (
    <main className="landing">
      <aside className="side">
        <div className="side-brand">
          <span className="side-logo" />
          <span>Laundromat</span>
          <em>v0.2.0</em>
        </div>
        <div className="side-search">
          <span>Search docs</span>
          <kbd>⌘K</kbd>
        </div>
        <nav className="side-nav">
          <p>Getting Started</p>
          <a href="#docs">Overview</a>
          <a href="#install">Installation</a>
          <a href="#quickstart">Quick Start</a>
          <p>Security Checks</p>
          <a href="#checks">Inspect</a>
          <a href="#checks">Clean</a>
          <a href="#checks">Protect</a>
          <p>Reference</p>
          <a href="#cli">CLI</a>
          <a href="#troubleshoot">Troubleshooting</a>
        </nav>
      </aside>
      <div className="landing-main">
      <section className="hero">
        <div className="hero-copy">
          <p className="eyebrow">local vulnerability review · repair · gate</p>
          <h1>
            Dirty code goes in.
            <br />
            Clean code comes out.
          </h1>
          <p className="lede">
            Laundromat runs your repository through a laundering pipeline:
            dirty code in, detection, verification, repair — clean code out.
          </p>
          <div className="cta">
            <a className="btn primary" href="/dashboard">Open Live Dashboard</a>
            <a className="btn ghost" href="#docs">Read the Docs</a>
          </div>
          <div className="terminal">
            <div className="terminal-bar">
              <span className="terminal-dot" />
              <span className="terminal-dot r" />
              <span className="terminal-dot y" />
              <span className="terminal-dot g" />
              <span className="terminal-title">laundromat · scan</span>
            </div>
            <pre>
              <span className="cursor">▊</span> scanning dirty code…
              {"\n"}✓ secret scan ........ clean
              {"\n"}✓ injection guard ... clean
              {"\n"}✓ dependency lock .. clean
              {"\n"}→ code clean · ready to ship
            </pre>
          </div>
        </div>
      </section>

      <section className="pipeline" aria-label="review pipeline">
        <div className="pipe-step">
          <span className="pipe-dot in">dirty</span>
          <span className="pipe-label">Dirty input</span>
        </div>
        <div className="pipe-arrow">→</div>
        <div className="pipe-step">
          <span className="pipe-dot detect">detect</span>
          <span className="pipe-label">Detect faults</span>
        </div>
        <div className="pipe-arrow">→</div>
        <div className="pipe-step">
          <span className="pipe-dot repair">repair</span>
          <span className="pipe-label">Verify &amp; repair</span>
        </div>
        <div className="pipe-arrow">→</div>
        <div className="pipe-step">
          <span className="pipe-dot clean">clean</span>
          <span className="pipe-label">Clean output</span>
        </div>
      </section>

      <section className="features" id="features">
        <h2>What it catches</h2>
        <div className="grid">
          {scenarios.map(([key, title, body]) => (
            <article className="card" key={key}>
              <h3>{title}</h3>
              <p>{body}</p>
              <code>laundromat --demo --scenario {key}</code>
            </article>
          ))}
        </div>
      </section>

      <section className="docs" id="docs">
        <h2>Documentation</h2>
        <div className="doc-grid">
          <div className="doc-card">
            <h3>Install</h3>
            <pre>{`python -m venv .venv
source .venv/bin/activate
python -m pip install -e ./Backend
laundromat-install-gitleaks
laundromat doctor`}</pre>
          </div>
          <div className="doc-card">
            <h3>Quick start</h3>
            <pre>{`laundromat setup
laundromat --demo
laundromat review .
laundromat serve --port 8731`}</pre>
          </div>
          <div className="doc-card">
            <h3>Scan a repo</h3>
            <pre>{`laundromat scan /path/to/repo
laundromat review /path/to/repo
laundromat gate --repo .`}</pre>
          </div>
        </div>
      </section>

      <section className="cta-final">
        <h2>Ready to clean the build?</h2>
        <p>Watch laundromat turn dirty code into verified, clean code.</p>
        <a className="btn primary" href="/dashboard">Open Live Dashboard</a>
      </section>
      </div>
    </main>
  );
}

function App() {
  const segments = window.location.pathname.split("/").filter(Boolean);
  const isReview = segments[0] === "review";
  const isDashboard = segments[0] === "dashboard";
  if (!isReview && !isDashboard) {
    return <Landing />;
  }
  const [scans, setScans] = useState<Summary[]>([]);
  const [repos, setRepos] = useState<string[]>([]);
  const [detail, setDetail] = useState<Detail | null>(null);
  const [loaded, setLoaded] = useState(false);
  const [error, setError] = useState("");
  const [filter, setFilter] = useState("");
  useEffect(() => {
    let active = true;
    let timer: ReturnType<typeof setTimeout>;
    let cursor = Number(localStorage.getItem("laundromat.events")) || 0;
    let lastRefresh = 0;
    async function poll() {
      try {
        const events = await read<{ id: number }[]>("/events?after=" + cursor);
        if (!id && !events.length && Date.now() - lastRefresh < 30000) return;
        const [history, registered, current] = await Promise.all([
          read<Summary[]>("/scans"),
          read<string[]>("/repositories"),
          id ? read<Detail>("/scans/" + id) : null,
        ]);
        if (active) {
          setScans(history);
          setRepos(registered);
          setDetail(current);
          setLoaded(true);
          setError("");
          lastRefresh = Date.now();
          if (events.length) {
            cursor = events[events.length - 1].id;
            localStorage.setItem("laundromat.events", String(cursor));
          }
        }
      } catch (e) {
        lastRefresh = 0;
        if (active)
          setError(
            e instanceof TypeError
              ? "Local API offline"
              : e instanceof Error
                ? e.message
                : "Local API unavailable",
          );
      } finally {
        if (active) timer = setTimeout(poll, 2200);
      }
    }
    poll();
    return () => {
      active = false;
      clearTimeout(timer);
    };
  }, []);
  const selectedRepair = detail?.repairs?.find(r => r.finding_id === new URLSearchParams(location.search).get("finding")) || detail?.repair;
  const visible = scans.filter((s) => !filter || s.snapshot.repository === filter);
  return (
    <>
      <header>
        <a className="brand" href="/">
          <i aria-hidden="true" />
          Laundromat
        </a>
        <span>Local review</span>
      </header>
      <main>
        <nav>
          <a href="/">Repository history</a>
          {id && (
            <>
              {" "}
              / <a href={"/review/" + id}>Scan detail</a>
            </>
          )}
          {repairView && " / Repair evidence"}
        </nav>
        {error && (
          <p role="alert" className="alert">
            {error}.{" "}
            {loaded
              ? "Showing the last loaded evidence."
              : "Start the local API or check the scan address."}
          </p>
        )}
        {!loaded && !error && <p role="status">Loading review history…</p>}
        {loaded && !id && (
          <>
            <div className="title">
              <h1>Repository history</h1>
              <label>
                Repository{" "}
                <select value={filter} onChange={(e) => setFilter(e.target.value)}>
                  <option value="">All repositories</option>
                  {repos.map((r) => (
                    <option key={r} value={r}>
                      {tail(r)}
                    </option>
                  ))}
                </select>
              </label>
            </div>
            <div className="stats">
              {[
                ["Scans", visible.length],
                ...(["caught","confirmed","applied","adjudicated_false_positives"] as const).map((key, i) =>
                  [["Caught","Property confirmed","Applied","Adjudicated false positives"][i],
                   visible.reduce((total, r) => total + (r.counts_summary?.[key] ?? 0), 0)]),
                [
                  "With findings",
                  visible.filter((s) => s.status === "findings").length,
                ],
                [
                  "Incomplete",
                  visible.filter((s) => ["incomplete", "interrupted"].includes(s.status)).length,
                ],
              ].map(([k, v]) => (
                <div key={k}>
                  <span>{k}</span>
                  <strong>{v}</strong>
                </div>
              ))}
            </div>
            {repos
              .filter(
                (r) => (!filter || filter === r) && !scans.some((s) => s.snapshot.repository === r),
              )
              .map((r) => (
                <p key={r}>{tail(r)} · Never scanned</p>
              ))}
            {!visible.length ? (
              <section>
                <h2>No scans yet</h2>
                <code>laundromat scan PATH</code>
              </section>
            ) : (
              <section>
                <h2>Scan timeline</h2>
                <div className="scroll">
                  <table>
                    <thead>
                      <tr>
                        <th>Repository / time</th>
                        <th>Trigger</th>
                        <th>Snapshot</th>
                        <th>Coverage / findings</th>
                        <th>Status</th>
                      </tr>
                    </thead>
                    <tbody>
                      {visible.map((s) => (
                        <tr key={s.id}>
                          <td>
                            <a href={"/review/" + s.id}>
                              {tail(s.snapshot.repository)}
                            </a>
                            <small>{date(s.created)}</small>
                          </td>
                          <td>{s.trigger}</td>
                          <td>
                            <code>{s.snapshot.sha256.slice(0, 10)}</code>
                          </td>
                          <td>
                            {Object.entries(s.counts)
                              .map(([k, v]) => k + " " + v)
                              .join(" · ") || "0 findings"}
                            <small>{coverageText(s.coverage)}</small>
                          </td>
                          <td>
                            <Badge value={s.status} />
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </section>
            )}
          </>
        )}
        {detail && (
          <>
            <div className="title">
              <div>
                <h1>{repairView ? "Repair evidence" : "Scan detail"}</h1>
                <p>
                  {tail(detail.snapshot.repository)} · {detail.trigger} · {date(detail.created)}
                </p>
              </div>
              <Badge value={detail.status} />
            </div>
            <div className="tabs">
              <a aria-current={!repairView ? "page" : undefined} href={"/review/" + id}>
                Scan detail
              </a>
              {detail.repair && (
                <a
                  aria-current={repairView ? "page" : undefined}
                  href={"/review/" + id + "/repair"}
                >
                  Repair evidence
                </a>
              )}
            </div>
            {repairView && selectedRepair ? (
              <Evidence r={selectedRepair} id={detail.id} authorized={detail.status !== "incomplete" && (detail.verified_actions?.length ?? 1) > 0} proposal={!!detail.proposal_state} />
            ) : (
              <>
                <section>
                  <h2>Snapshot</h2>
                  <code>{detail.snapshot.sha256}</code>
                  {detail.mode && <p>Repository mode · <strong>{detail.mode}</strong></p>}
                  {detail.updates?.map((u) => (
                    <p key={u.remote}>{u.local} → {u.remote}<br />
                      Reviewed commit · <code>{u.tip}</code></p>
                  ))}
                  <p>
                    {detail.scope == null ? "Determining changed files" : detail.scope.length + " scoped paths or commits"} ·{" "}
                    {detail.elapsed_ms ?? "—"} ms
                    {detail.task_to_verdict_ms != null && " · task to verdict " + detail.task_to_verdict_ms + " ms"}
                  </p>
                  <p role="status">{detail.next_stage}{detail.proposal_state && " · Proposal " + detail.proposal_state}</p>
                  {detail.last_observation && <small>{detail.last_observation.kind} · {date(detail.last_observation.time)}</small>}
                  {detail.last_successful_observation && <p>Last observation · {detail.last_successful_observation.reason} · {date(detail.last_successful_observation.time)}</p>}
                  {detail.recovery && <p>{detail.recovery === "Retry this scan"
                    ? <button onClick={async () => {
                      try { const res = await fetch("/scans/" + id + "/retry", { method: "POST" });
                        if (!res.ok) throw Error("Recovery failed"); location.reload();
                      } catch (e) { setError(String(e)); }
                    }}>Retry this scan</button>
                    : detail.recovery}</p>}
                  {detail.task_status && <p>Task {detail.task_status}</p>}
                  <details>
                    <summary>Scope and coverage</summary>
                    <Data value={{ scope: detail.scope, coverage: detail.coverage }} />
                  </details>
                  {detail.changes?.map((c) => (
                    <div key={c.path}>
                      <h3>
                        {c.change} · {c.path}
                      </h3>
                      <pre>{c.diff}</pre>
                    </div>
                  ))}
                </section>
                <section>
                  <h2>Findings</h2>
                  {!detail.findings.length && (
                    <p>
                      {detail.status === "clean"
                        ? "No findings in the checked scope."
                        : "No recorded findings."}
                    </p>
                  )}
                  {detail.findings.map((f, i) => {
                    const timeline = (detail.transitions || []).filter((t) => t.finding === f.id);
                    const last = timeline[timeline.length - 1];
                    const push = detail.push_reviews?.find((r) => r.finding_id === f.id);
                    return (
                    <article key={f.id + i}>
                      <Badge value={f.severity === "P1" ? "Critical" : f.severity} />
                      <strong>
                        {f.category} · {f.path}
                        {f.line && ":" + f.line}
                      </strong>
                      <p>{f.explanation}</p>
                      <small>
                        {last?.state || f.state || "Candidate"} · {f.property || f.repair_status} {f.change && " · " + f.change}
                      </small>
                      {push && <PushFinding item={push} />}
                      {detail.repairs?.some((r) => r.finding_id === f.id) && <p><a href={"/review/" + id + "/repair?finding=" + f.id}>Review repair evidence</a></p>}
                      <details>
                        <summary>Observations and scope limits</summary>
                        {(f.scope_limits || detail.scope_limits)?.map((limit) => <p key={limit}>{limit}</p>)}
                        <Data value={{ finding: f, timeline }} />
                      </details>
                    </article>
                  );})}
                </section>
                <section>
                  <h2>Coverage and observations</h2>
                  <p>{coverageText(detail.coverage)}</p>
                  {detail.scope_limits?.map((limit) => <p key={limit}>{limit}</p>)}
                  <details><summary>Severity, transitions and structural checks</summary>
                    <Data value={{ counts: detail.counts_summary, transitions: detail.transitions, structural: detail.structural_observations }} /></details>
                </section>
                {detail.push_decision && (
                  <section>
                    <h2>Push decision</h2>
                    <Badge value={detail.push_decision.action} />
                    <p>{detail.push_decision.reason}</p>
                    {detail.staging_issue && <p>{detail.staging_issue}</p>}
                    {detail.proposal_ready && detail.push_reviews?.filter((r) => r.state === "proposed")
                      .map((r, _, proposals) => <pre key={r.finding_id}>{"laundromat approve " + detail.id + (proposals.length > 1 ? " --finding " + r.finding_id : "")}</pre>)}
                  </section>
                )}
                {!!detail.dependency_changes?.length && (
                  <section>
                    <h2>Recorded dependency changes</h2>
                    {detail.dependency_changes.map((d) => (
                      <article key={d.package}>
                        <strong>
                          {d.package} · {d.previous} → {d.resolved}
                        </strong>
                        <p>
                          New install-time scripts ·{" "}
                          {d.gained?.join(", ") || (d.gained ? "none" : "unknown")}
                        </p>
                        <p>
                          Recorded parent references package ·{" "}
                          {d.parent_references == null ? "unknown" : d.parent_references ? "yes" : "no"}
                        </p>
                      </article>
                    ))}
                  </section>
                )}
                {detail.issues?.map((x) => (
                  <p className="alert" key={x}>
                    {x}
                  </p>
                ))}
              </>
            )}
          </>
        )}
      </main>
    </>
  );
}

createRoot(document.getElementById("root")!).render(<ReviewBoundary><App /></ReviewBoundary>);
