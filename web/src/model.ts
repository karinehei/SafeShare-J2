export interface SourceFile {
  path: string
  content: string
}

export interface Finding {
  rule_id: string
  severity: string
  category: string
  file: string
  line: number
  column: number
  message: string
  reason: string
  recommendation: string
  masked_value: string
  fingerprint: string
}

export interface RiskBreakdown {
  score: number
  label: string
  reason: string
  critical_points: number
  high_points: number
  medium_points: number
  low_points: number
  credential_bonus: number
}

export interface ScanReport {
  version: string
  summary: {
    files_scanned: number
    files_skipped: number
    findings: number
    risk_score: number
    assessment: string
    safe_to_share: false
  }
  risk: RiskBreakdown
  findings: Finding[]
}

export interface SanitizationReport {
  version: string
  source: string
  output: string
  placeholder: string
  high_confidence_rules: string[]
  summary: {
    files_copied: number
    files_modified: number
    files_skipped: number
    replacements: number
  }
  modified_files: { file: string; replacements: number; rule_ids: string[] }[]
  skipped: { file: string; reason: string }[]
}

export interface ExampleRecord {
  id: string
  title: string
  summary: string
  provenance: string
  files: SourceFile[]
  sanitizedFiles: SourceFile[]
  originalReportText: string
  sanitizedReportText: string
  sanitizationText: string
  originalReport: ScanReport
  sanitizedReport: ScanReport
  sanitization: SanitizationReport
}

export interface Filters {
  severity: string
  category: string
  rule: string
  file: string
}

export type ExampleView = "files" | "findings" | "compare"

export type Route =
  | { page: "examples" }
  | { page: "rules" }
  | { page: "how" }
  | { page: "unknown"; raw: string }
  | ({
      page: "example"
      exampleId: string
      view: ExampleView
      finding: string
    } & Filters)

export const NO_FINDINGS_NOTE =
  "No known secret or credential patterns matched. This does not guarantee the files contain no sensitive information."

export const SCORE_NOTE =
  "This score is a heuristic with diminishing returns. It is not a probability and not a validated estimate of exposure."

const VIEWS = new Set<ExampleView>(["files", "findings", "compare"])

export function emptyFilters(): Filters {
  return { severity: "", category: "", rule: "", file: "" }
}

export function parseHash(raw: string): Route {
  const hash = raw.startsWith("#") ? raw.slice(1) : raw
  const [pathPart, queryPart] = hash.split("?")
  const parts = pathPart.split("/").filter(Boolean)
  const query = new URLSearchParams(queryPart ?? "")
  const filters: Filters = {
    severity: query.get("severity") ?? "",
    category: query.get("category") ?? "",
    rule: query.get("rule") ?? "",
    file: query.get("file") ?? "",
  }
  const finding = query.get("finding") ?? ""
  if (parts.length === 0 || (parts.length === 1 && parts[0] === "examples")) {
    return { page: "examples" }
  }
  if (parts[0] === "rules" && parts.length === 1) return { page: "rules" }
  if (parts[0] === "how" && parts.length === 1) return { page: "how" }
  if (parts[0] === "examples" && parts.length >= 2) {
    const view = parts[2] ?? "files"
    if (!VIEWS.has(view as ExampleView) || parts.length > 3) {
      return { page: "unknown", raw }
    }
    return {
      page: "example",
      exampleId: decodeURIComponent(parts[1]),
      view: view as ExampleView,
      finding,
      ...filters,
    }
  }
  return { page: "unknown", raw }
}

export function formatHash(route: Route): string {
  if (route.page === "examples") return "#/examples"
  if (route.page === "rules") return "#/rules"
  if (route.page === "how") return "#/how"
  if (route.page === "unknown") return route.raw.startsWith("#") ? route.raw : `#${route.raw}`
  const params = new URLSearchParams()
  for (const key of ["severity", "category", "rule", "file", "finding"] as const) {
    const value = key === "finding" ? route.finding : route[key]
    if (value) params.set(key, value)
  }
  const query = params.toString()
  const path = `#/examples/${encodeURIComponent(route.exampleId)}/${route.view}`
  return query ? `${path}?${query}` : path
}

export function filterFindings<T extends Pick<Finding, "severity" | "category" | "rule_id" | "file">>(
  findings: readonly T[],
  filters: Filters,
): T[] {
  return findings.filter((finding) => {
    if (filters.severity && finding.severity !== filters.severity) return false
    if (filters.category && finding.category !== filters.category) return false
    if (filters.rule && finding.rule_id !== filters.rule) return false
    if (filters.file && finding.file !== filters.file) return false
    return true
  })
}

/** The number J2 stored. Filtering must not replace it. */
export function reportRiskScore(report: ScanReport): number {
  return report.summary.risk_score
}

export function shareVerdict(findings: readonly Pick<Finding, "category">[]): "NO" | "Not guaranteed" {
  if (findings.some((finding) => finding.category === "secret" || finding.category === "credential")) {
    return "NO"
  }
  return "Not guaranteed"
}

export function routeForFinding(
  route: Extract<Route, { page: "example" }>,
  finding: Finding,
): Extract<Route, { page: "example" }> {
  return {
    ...route,
    view: "findings",
    file: finding.file,
    finding: finding.fingerprint,
  }
}

export function rescanStatus(finding: Finding, rescan: readonly Finding[]): string {
  const present = rescan.some((item) => item.fingerprint === finding.fingerprint)
  if (present) return "Same fingerprint in the rescan"
  return "Fingerprint not in the rescan"
}

export function fileByPath(files: readonly SourceFile[], filePath: string): SourceFile | undefined {
  return files.find((file) => file.path === filePath)
}

export function sanitizerDiscrepancies(example: ExampleRecord): string[] {
  const modified = new Set(example.sanitization.modified_files.map((row) => row.file))
  const notes: string[] = []
  for (const file of example.files) {
    const output = fileByPath(example.sanitizedFiles, file.path)
    if (!output) continue
    const changed = file.content !== output.content
    const listed = modified.has(file.path)
    if (changed !== listed) {
      notes.push(
        `${file.path}: sanitizer output ${changed ? "differs from" : "matches"} the fixture, while the sanitization report ${listed ? "lists it as modified" : "does not list it as modified"}.`,
      )
    }
  }
  return notes
}

export function findingCard(finding: Finding) {
  return {
    ruleId: finding.rule_id,
    severity: finding.severity,
    category: finding.category,
    file: finding.file,
    line: finding.line,
    column: finding.column,
    message: finding.message,
    reason: finding.reason,
    recommendation: finding.recommendation,
    maskedValue: finding.masked_value,
    fingerprint: finding.fingerprint,
  }
}

export function hydrateExample(raw: {
  id: string
  title: string
  summary: string
  provenance: string
  files: SourceFile[]
  sanitizedFiles: SourceFile[]
  originalReportText: string
  sanitizedReportText: string
  sanitizationText: string
}): ExampleRecord {
  return {
    ...raw,
    originalReport: JSON.parse(raw.originalReportText) as ScanReport,
    sanitizedReport: JSON.parse(raw.sanitizedReportText) as ScanReport,
    sanitization: JSON.parse(raw.sanitizationText) as SanitizationReport,
  }
}

export function downloadName(exampleId: string, which: "original" | "rescan" | "sanitization"): string {
  return `${exampleId}-${which}-report.json`
}

export function uniqueSorted(values: readonly string[]): string[] {
  return [...new Set(values)].sort((a, b) => a.localeCompare(b))
}
