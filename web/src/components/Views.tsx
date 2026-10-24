import type { ManifestFile, RuleRecord, RulesFile } from "../data.ts"
import {
  downloadName,
  fileByPath,
  filterFindings,
  findingCard,
  formatHash,
  NO_FINDINGS_NOTE,
  reportRiskScore,
  rescanStatus,
  sanitizerDiscrepancies,
  shareVerdict,
  uniqueSorted,
  type ExampleRecord,
  type ExampleView,
  type Route,
} from "../model.ts"
import { Icon } from "../icons.tsx"
import { ScorePanel } from "./ScorePanel.tsx"
import { SourceView } from "./SourceView.tsx"

function navigate(route: Route) {
  const next = formatHash(route)
  if (window.location.hash !== next) window.location.hash = next
}

function downloadReport(filename: string, text: string) {
  const blob = new Blob([text], { type: "application/json" })
  const url = URL.createObjectURL(blob)
  const link = document.createElement("a")
  link.href = url
  link.download = filename
  document.body.appendChild(link)
  link.click()
  link.remove()
  URL.revokeObjectURL(url)
}

export function ExamplesHome({ examples }: { examples: ExampleRecord[] }) {
  return (
    <section>
      <h2>Examples</h2>
      <p>Each card opens one synthetic fixture and the J2 reports generated for that directory.</p>
      <ul className="example-list">
        {examples.map((example) => {
          const report = example.originalReport
          return (
            <li key={example.id}>
              <article className="card">
                <h3>{example.title}</h3>
                <p>{example.summary}</p>
                <p className="fine">{example.provenance}</p>
                <dl className="meta">
                  <div>
                    <dt>Findings</dt>
                    <dd>{report.summary.findings}</dd>
                  </div>
                  <div>
                    <dt>Risk score</dt>
                    <dd>
                      {report.summary.risk_score} / 100 · {report.risk.label}
                    </dd>
                  </div>
                  <div>
                    <dt>Safe to share</dt>
                    <dd>{shareVerdict(report.findings)}</dd>
                  </div>
                </dl>
                <div className="actions">
                  <a className="button" href={formatHash({ page: "example", exampleId: example.id, view: "files", severity: "", category: "", rule: "", file: "", finding: "" })}>
                    <Icon name="files" /> Open example
                  </a>
                  <a className="button button-secondary" href={formatHash({ page: "example", exampleId: example.id, view: "findings", severity: "", category: "", rule: "", file: "", finding: "" })}>
                    <Icon name="findings" /> View findings
                  </a>
                  <a className="button button-secondary" href={formatHash({ page: "example", exampleId: example.id, view: "compare", severity: "", category: "", rule: "", file: "", finding: "" })}>
                    <Icon name="compare" /> Compare sanitization
                  </a>
                </div>
              </article>
            </li>
          )
        })}
      </ul>
    </section>
  )
}

function FileList({
  example,
  route,
  view,
}: {
  example: ExampleRecord
  route: Extract<Route, { page: "example" }>
  view: ExampleView
}) {
  return (
    <ul className="file-list">
      {example.files.map((file) => {
        const count = example.originalReport.findings.filter((finding) => finding.file === file.path).length
        const href = formatHash({ ...route, view, file: file.path })
        const current = route.file === file.path
        return (
          <li key={file.path}>
            <a href={href} aria-current={current ? "true" : undefined}>
              <span className="file-path">
                <Icon name="file" /> {file.path}
              </span>
              <span className="file-count">{count} findings</span>
            </a>
          </li>
        )
      })}
    </ul>
  )
}

function Filters({
  route,
  findings,
}: {
  route: Extract<Route, { page: "example" }>
  findings: ExampleRecord["originalReport"]["findings"]
}) {
  const severities = uniqueSorted(findings.map((finding) => finding.severity))
  const categories = uniqueSorted(findings.map((finding) => finding.category))
  const rules = uniqueSorted(findings.map((finding) => finding.rule_id))
  const files = uniqueSorted(findings.map((finding) => finding.file))
  const fields = [
    ["severity", "Severity", severities],
    ["category", "Category", categories],
    ["rule", "Rule", rules],
    ["file", "File", files],
  ] as const
  return (
    <form className="filters" onSubmit={(event) => event.preventDefault()}>
      {fields.map(([key, label, options]) => (
        <label key={key}>
          {label}
          <select
            value={route[key]}
            onChange={(event) => navigate({ ...route, [key]: event.target.value })}
          >
            <option value="">All</option>
            {options.map((option) => (
              <option key={option} value={option}>
                {option}
              </option>
            ))}
          </select>
        </label>
      ))}
    </form>
  )
}

function FindingList({
  route,
  findings,
  rescan,
}: {
  route: Extract<Route, { page: "example" }>
  findings: ExampleRecord["originalReport"]["findings"]
  rescan?: ExampleRecord["sanitizedReport"]["findings"]
}) {
  if (findings.length === 0) {
    return <p>{NO_FINDINGS_NOTE}</p>
  }
  return (
    <ul className="finding-list">
      {findings.map((item) => {
        const card = findingCard(item)
        const selected = route.finding === item.fingerprint
        return (
          <li key={item.fingerprint + item.file + item.line}>
            <article className={selected ? "finding selected-finding" : "finding"}>
              <a href={formatHash({ ...route, view: "findings", file: item.file, finding: item.fingerprint })}>
                <span className={`sev sev-${card.severity}`}>{card.severity}</span>
                <span className="rule-id">{card.ruleId}</span>
                <span>
                  {card.file}:{card.line}
                  {card.column > 0 ? `:${card.column}` : ""}
                </span>
              </a>
              <p>{card.message}</p>
              <p>
                <span className="label">Category</span> {card.category}
              </p>
              {card.maskedValue ? (
                <p>
                  <span className="label">Masked value</span> <code>{card.maskedValue}</code>
                </p>
              ) : (
                <p className="fine">No masked secret. This is a configuration finding.</p>
              )}
              <details>
                <summary>Explanation and recommendation</summary>
                <p>{card.reason}</p>
                <p>{card.recommendation}</p>
                <p className="fine">Fingerprint {card.fingerprint}</p>
              </details>
              {rescan ? (
                <p className="fine">
                  {rescanStatus(item, rescan)}. A missing fingerprint is not a clearance to share the tree.
                </p>
              ) : null}
            </article>
          </li>
        )
      })}
    </ul>
  )
}

export function ExampleWorkspace({
  example,
  route,
}: {
  example: ExampleRecord
  route: Extract<Route, { page: "example" }>
}) {
  const original = example.originalReport
  const score = reportRiskScore(original)
  const filtered = filterFindings(original.findings, route)
  const requested = route.file
  const source = requested ? fileByPath(example.files, requested) : example.files[0]
  const missingFile = Boolean(requested) && !source
  const selected = original.findings.find((item) => item.fingerprint === route.finding)
  const selectedLine = selected && source && selected.file === source.path ? selected.line : null
  const highlight = new Set(
    original.findings.filter((item) => source && item.file === source.path).map((item) => item.line),
  )
  const countText =
    filtered.length === original.findings.length
      ? `${original.findings.length} findings`
      : `Showing ${filtered.length} of ${original.findings.length} findings`
  return (
    <section>
      <header className="example-head">
        <h2>{example.title}</h2>
        <p>{example.summary}</p>
        <p className="fine">Fixture provenance: {example.provenance}</p>
        <div className="actions">
          <a className="button button-secondary" href={formatHash({ ...route, view: "files" })} aria-current={route.view === "files" ? "page" : undefined}>
            <Icon name="files" /> Browse files
          </a>
          <a className="button button-secondary" href={formatHash({ ...route, view: "findings" })} aria-current={route.view === "findings" ? "page" : undefined}>
            <Icon name="findings" /> View findings
          </a>
          <a className="button button-secondary" href={formatHash({ ...route, view: "compare" })} aria-current={route.view === "compare" ? "page" : undefined}>
            <Icon name="compare" /> Compare sanitization
          </a>
        </div>
      </header>
      <div className="workspace">
        <ScorePanel report={original} title="Original J2 risk score" />
        <div>
          <p className="fine">Filters do not change this score. It stays {score} / 100.</p>
          {route.view === "findings" ? (
            <>
              <Filters route={route} findings={original.findings} />
              <h3 aria-live="polite">{countText}</h3>
              <FindingList route={route} findings={filtered} />
              {filtered.length === 0 && original.findings.length > 0 ? (
                <p>No findings match these filters. The original risk score is unchanged.</p>
              ) : null}
              {missingFile ? (
                <p role="alert">No fixture file named {requested} is packaged for this example.</p>
              ) : source ? (
                <>
                  <p className="fine" aria-live="polite">
                    Synthetic fixture source {source.path}
                    {selectedLine ? `, line ${selectedLine} highlighted` : ""}. Shown as text. This is not an editor.
                  </p>
                  <SourceView
                    text={source.content}
                    label={`Synthetic fixture source: ${source.path}`}
                    highlightLines={highlight}
                    selectedLine={selectedLine}
                  />
                </>
              ) : null}
            </>
          ) : null}
          {route.view === "files" ? (
            <div className="split">
              <FileList example={example} route={route} view="files" />
              <div>
                {missingFile ? (
                  <p role="alert">No fixture file named {requested} is packaged for this example.</p>
                ) : source ? (
                  <>
                    <p className="fine" aria-live="polite">
                      Synthetic fixture source {source.path}
                      {selectedLine ? `, line ${selectedLine} highlighted` : ""}. Shown as text. This is not an editor.
                    </p>
                    <SourceView
                      text={source.content}
                      label={`Synthetic fixture source: ${source.path}`}
                      highlightLines={highlight}
                      selectedLine={selectedLine}
                    />
                  </>
                ) : null}
              </div>
            </div>
          ) : null}
          {route.view === "compare" ? <Compare example={example} route={route} /> : null}
          <div className="actions">
            <button type="button" onClick={() => downloadReport(downloadName(example.id, "original"), example.originalReportText)}>
              <Icon name="download" /> Download masked JSON report
            </button>
            <button type="button" onClick={() => downloadReport(downloadName(example.id, "rescan"), example.sanitizedReportText)}>
              <Icon name="download" /> Download rescan JSON report
            </button>
          </div>
        </div>
      </div>
    </section>
  )
}

function Compare({
  example,
  route,
}: {
  example: ExampleRecord
  route: Extract<Route, { page: "example" }>
}) {
  const requested = route.file || example.files[0]?.path || ""
  const original = fileByPath(example.files, requested)
  const sanitized = fileByPath(example.sanitizedFiles, requested)
  const missing = Boolean(route.file) && !original
  const skipped = example.sanitization.skipped.find((row) => row.file === requested)
  const modified = example.sanitization.modified_files.find((row) => row.file === requested)
  const notes = sanitizerDiscrepancies(example)
  const doc = example.sanitization
  return (
    <div className="compare">
      <h3>Partial sanitization</h3>
      <p>
        The sanitizer redacts only the high-confidence rule ids listed in its report. Heuristic credentials and
        risky configuration are copied through. Unchanged text is not a fix, and the output is not a safe project.
      </p>
      <dl className="meta">
        <div>
          <dt>Placeholder</dt>
          <dd>
            <code>{doc.placeholder}</code>
          </dd>
        </div>
        <div>
          <dt>Files copied</dt>
          <dd>{doc.summary.files_copied}</dd>
        </div>
        <div>
          <dt>Files modified</dt>
          <dd>{doc.summary.files_modified}</dd>
        </div>
        <div>
          <dt>Files skipped</dt>
          <dd>{doc.summary.files_skipped}</dd>
        </div>
        <div>
          <dt>Replacements</dt>
          <dd>{doc.summary.replacements}</dd>
        </div>
      </dl>
      <h4>Rule types the sanitizer can redact</h4>
      <ul>
        {doc.high_confidence_rules.map((rule) => (
          <li key={rule}>
            <code>{rule}</code>
          </li>
        ))}
      </ul>
      <h4>Files the report lists as modified</h4>
      {doc.modified_files.length === 0 ? (
        <p>The sanitization report lists no modified files.</p>
      ) : (
        <ul>
          {doc.modified_files.map((row) => (
            <li key={row.file}>
              <code>{row.file}</code> — {row.replacements} replacement(s), rules {row.rule_ids.join(", ")}
            </li>
          ))}
        </ul>
      )}
      <h4>Skipped or omitted</h4>
      {doc.skipped.length === 0 ? <p>The sanitization report lists no skipped files.</p> : (
        <ul>
          {doc.skipped.map((row) => (
            <li key={row.file + row.reason}>
              <code>{row.file}</code> — {row.reason}
            </li>
          ))}
        </ul>
      )}
      <p className="fine">
        Report source path: {doc.source}. Report output path: {doc.output}. The output path is the temporary
        directory from that J2 run and is not rewritten when it changes between generations.
      </p>
      {notes.length ? (
        <div role="alert">
          <h4>Discrepancy</h4>
          <ul>
            {notes.map((note) => (
              <li key={note}>{note}</li>
            ))}
          </ul>
        </div>
      ) : null}
      <div className="split">
        <FileList example={example} route={route} view="compare" />
        <div>
          {missing ? <p role="alert">No fixture file named {route.file} is packaged for this example.</p> : null}
          {original && sanitized ? (
            <>
              <p className="fine">
                {modified
                  ? `${requested} is listed as modified (${modified.rule_ids.join(", ")}).`
                  : `${requested} is not listed as modified.`}
                {skipped ? ` Skip reason: ${skipped.reason}.` : ""}
              </p>
              <div className="split">
                <SourceView text={original.content} label={`Fixture: ${requested}`} highlightLines={new Set()} selectedLine={null} />
                <SourceView text={sanitized.content} label={`Sanitizer output: ${requested}`} highlightLines={new Set()} selectedLine={null} />
              </div>
            </>
          ) : null}
          {original && !sanitized ? (
            <p role="alert">
              {requested} has no sanitized copy in the bundle
              {skipped ? ` (${skipped.reason})` : ""}.
            </p>
          ) : null}
        </div>
      </div>
      <div className="split">
        <div>
          <h4>Original findings</h4>
          <FindingList route={route} findings={example.originalReport.findings} rescan={example.sanitizedReport.findings} />
        </div>
        <div>
          <h4>Rescan findings</h4>
          <p className="fine">These rows are the second J2 scan of the sanitizer output.</p>
          {example.sanitizedReport.findings.length === 0 ? <p>{NO_FINDINGS_NOTE}</p> : (
            <ul className="finding-list">
              {example.sanitizedReport.findings.map((item) => (
                <li key={item.fingerprint + item.file + item.line}>
                  <p>
                    <span className={`sev sev-${item.severity}`}>{item.severity}</span> {item.rule_id} {item.file}:{item.line}
                    {item.masked_value ? <code> {item.masked_value}</code> : null}
                  </p>
                </li>
              ))}
            </ul>
          )}
          <ScorePanel report={example.sanitizedReport} title="Rescan J2 risk score" />
        </div>
      </div>
    </div>
  )
}

const FAMILY_LABELS: Record<string, string> = {
  known_token: "Known token formats",
  private_key: "Private keys",
  database_credential: "Database URLs",
  sensitive_data: "Sensitive-data heuristics",
  entropy: "Entropy detector",
  risky_config: "Risky configuration",
  other: "Other",
}

export function RulesView({ rules }: { rules: RulesFile }) {
  const families = uniqueSorted(rules.rules.map((rule) => rule.family))
  return (
    <section>
      <h2>Rule explorer</h2>
      <p>
        This list is the JSON catalog printed by <code>j2 src/export_rules.j2</code>. Patterns are shown as text.
        The browser does not execute them.
      </p>
      <p className="fine">
        Regex rules are defined in {rules.source}. The entropy detector is implemented separately in {rules.entropy_source}.
      </p>
      <h3>High-confidence ids the sanitizer can redact</h3>
      <ul>
        {rules.high_confidence_rules.map((id) => (
          <li key={id}>
            <code>{id}</code>
          </li>
        ))}
      </ul>
      {families.map((family) => (
        <section key={family}>
          <h3>{FAMILY_LABELS[family] ?? family}</h3>
          <ul className="rule-list">
            {rules.rules
              .filter((rule) => rule.family === family)
              .map((rule) => (
                <RuleCard key={rule.id} rule={rule} />
              ))}
          </ul>
        </section>
      ))}
    </section>
  )
}

function RuleCard({ rule }: { rule: RuleRecord }) {
  return (
    <li className="card">
      <h4>
        <code>{rule.id}</code>
      </h4>
      <p>
        <span className={`sev sev-${rule.severity}`}>{rule.severity}</span> {rule.category} · {rule.name}
      </p>
      <p>{rule.description}</p>
      <p>
        <span className="label">Applies</span> {rule.applies_label}
      </p>
      <p className="fine">
        Sanitization: {rule.sanitization ? "redacted by sanitize" : "copied through"}. Source: {rule.source}. Detector:{" "}
        {rule.detector}.
      </p>
      <details>
        <summary>Recommendation, limitations, and pattern text</summary>
        <p>{rule.recommendation}</p>
        <p>{rule.limitations}</p>
        <p className="fine">
          Minimum length {rule.min_len}. {rule.family === "entropy" ? `Minimum bits/char ${rule.min_bits}.` : null}{" "}
          Placeholders skipped: {rule.placeholders ? "yes" : "no"}.
        </p>
        {rule.patterns.map((pattern) => (
          <pre key={pattern} className="pattern" tabIndex={0}>
            <code>{pattern}</code>
          </pre>
        ))}
      </details>
    </li>
  )
}

export function HowView({ manifest }: { manifest: ManifestFile }) {
  return (
    <section className="how">
      <h2>How it works</h2>
      <h3>Original CLI</h3>
      <div className="flow" aria-hidden="true">
        <span>Filesystem discovery</span>
        <span>Text filtering</span>
        <span>J2 analysis</span>
        <span>Scoring and reporting</span>
        <span>Optional sanitizer copy</span>
      </div>
      <div className="text-equivalent">
        <h4>Text equivalent</h4>
        <ol>
          <li>You run <code>j2 --allow-fs src/main.j2 scan PATH</code> on a machine you control. <code>--allow-fs</code> is a capability on the <code>j2</code> process. The scan never receives <code>--allow-net</code>.</li>
          <li>Discovery walks the directory and applies <code>.safeshareignore</code>. Text files are read, with a size cap. Binaries and NUL buffers are skipped. That I/O stays serial.</li>
          <li>Pure analysis runs the rule table, the separate entropy detector, risky-configuration checks, and sensitive-data heuristics.</li>
          <li>Scoring and the terminal or JSON report run after analysis. <code>safe_to_share</code> is false. The share line is NO when credential findings exist, and otherwise “not guaranteed”.</li>
          <li>
            <code>sanitize</code> writes a copy outside the input tree and redacts four high-confidence patterns. A <code>j2 build</code> binary does not inherit <code>--allow-fs</code>; scan with the interpreter.
          </li>
        </ol>
      </div>
      <h3>Published demo</h3>
      <div className="flow" aria-hidden="true">
        <span>Synthetic fixtures</span>
        <span>Build-time J2</span>
        <span>Generated artifacts</span>
        <span>Static browser viewer</span>
      </div>
      <div className="text-equivalent">
        <h4>Text equivalent</h4>
        <ol>
          <li>Allowlisted synthetic directories are the only inputs. They are not a visitor’s files and not an arbitrary checkout.</li>
          <li>During dataset generation, the same interpreter commands scan each fixture, sanitize into a temporary directory outside that fixture, and scan the copy. Rule metadata is printed by <code>j2 src/export_rules.j2</code>.</li>
          <li>The bundle stores those JSON reports, the sanitizer’s report, and the approved fixture texts. Report masking stays as J2 wrote it.</li>
          <li>GitHub Pages serves the built HTML and JSON. The visitor’s browser only reads those static files. Hosting the site does not grant J2 filesystem capabilities and does not run the scanner.</li>
        </ol>
      </div>
      <h3>What this page is showing</h3>
      <ul>
        <li>J2 version recorded for this bundle: {manifest.j2_version}</li>
        <li>Generation mode: {manifest.generation_mode}</li>
        <li>{manifest.network}</li>
        <li>{manifest.sanitization_output_paths}</li>
      </ul>
      <h4>Commands recorded with the bundle</h4>
      <ul>
        {manifest.commands.map((command) => (
          <li key={command}>
            <code>{command}</code>
          </li>
        ))}
      </ul>
      <p>
        Native compilation can see independent pure calls. This demo does not show measurements of that, and the
        browser session is not evidence of native parallelism. A five-file fixture is expected to stay serial.
      </p>
    </section>
  )
}

export function ProvenanceFooter({ manifest }: { manifest: ManifestFile }) {
  return (
    <footer className="site-footer">
      <h2>Bundle provenance</h2>
      <dl className="meta">
        <div>
          <dt>J2</dt>
          <dd>{manifest.j2_version}</dd>
        </div>
        <div>
          <dt>Source commit</dt>
          <dd>{manifest.source_commit ?? "Not available when the bundle was generated"}</dd>
        </div>
        <div>
          <dt>Worktree</dt>
          <dd>
            {manifest.dirty === null
              ? "Git status was not available"
              : manifest.dirty
                ? "Dirty when generated"
                : "Clean when generated"}
          </dd>
        </div>
        <div>
          <dt>Generated</dt>
          <dd>{manifest.generated_at}</dd>
        </div>
        <div>
          <dt>Report schema</dt>
          <dd>{manifest.report_schema_version}</dd>
        </div>
      </dl>
    </footer>
  )
}
