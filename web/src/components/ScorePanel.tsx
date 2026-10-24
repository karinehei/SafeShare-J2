import { SCORE_NOTE, shareVerdict, type ScanReport } from "../model.ts"

export function ScorePanel({ report, title }: { report: ScanReport; title: string }) {
  const verdict = shareVerdict(report.findings)
  const risk = report.risk
  const rows = [
    ["Critical", risk.critical_points],
    ["High", risk.high_points],
    ["Medium", risk.medium_points],
    ["Low", risk.low_points],
    ["Critical-credential bonus", risk.credential_bonus],
  ] as const
  return (
    <section className="score-panel" aria-label={title}>
      <h3>{title}</h3>
      <p className="score-figure">
        <span className="score-number">{risk.score}</span>
        <span> / 100</span>
      </p>
      <p>
        <span className="label">Label</span> {risk.label}
      </p>
      <p>
        <span className="label">Assessment</span> {report.summary.assessment}
      </p>
      <p>
        <span className="label">Safe to share</span> {verdict}
      </p>
      <p className="fine">JSON field safe_to_share is false. There is no Safe, Approved, or YES state.</p>
      <table className="breakdown">
        <caption>Contribution breakdown from the J2 report</caption>
        <tbody>
          {rows.map(([name, points]) => (
            <tr key={name}>
              <th scope="row">{name}</th>
              <td>{points}</td>
            </tr>
          ))}
        </tbody>
      </table>
      <p className="reason">{risk.reason}</p>
      <p className="fine">{SCORE_NOTE}</p>
      <p className="fine">
        Files scanned {report.summary.files_scanned}. Files skipped {report.summary.files_skipped}. Findings{" "}
        {report.summary.findings}.
      </p>
    </section>
  )
}
