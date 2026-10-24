import { describe, expect, it } from "vitest"
import { validateBundle, validateScanReport } from "./schema.ts"
import {
  downloadName,
  filterFindings,
  findingCard,
  formatHash,
  NO_FINDINGS_NOTE,
  parseHash,
  reportRiskScore,
  rescanStatus,
  routeForFinding,
  sanitizerDiscrepancies,
  shareVerdict,
  type ExampleRecord,
  type Finding,
  type Route,
  type ScanReport,
} from "./model.ts"

function finding(partial: Partial<Finding>): Finding {
  return {
    rule_id: "debug_enabled",
    severity: "low",
    category: "risky_config",
    file: "app.env",
    line: 1,
    column: 1,
    message: "Potentially risky configuration",
    reason: "Setting noted by the scanner",
    recommendation: "Review the setting",
    masked_value: "",
    fingerprint: "a".repeat(64),
    ...partial,
  }
}

function report(findings: Finding[], score = 11): ScanReport {
  return {
    version: "0.1.0",
    summary: {
      files_scanned: 2,
      files_skipped: 0,
      findings: findings.length,
      risk_score: score,
      assessment: "low",
      safe_to_share: false,
    },
    risk: {
      score,
      label: "LOW RISK",
      reason: "breakdown text stored by J2",
      critical_points: 0,
      high_points: 0,
      medium_points: 0,
      low_points: score,
      credential_bonus: 0,
    },
    findings,
  }
}

describe("hash navigation", () => {
  it("round-trips an example, view, filters, file, and finding", () => {
    const route: Route = {
      page: "example",
      exampleId: "demo-project",
      view: "findings",
      severity: "high",
      category: "secret",
      rule: "jwt_token",
      file: "src/app.ts",
      finding: "abc",
    }
    expect(parseHash(formatHash(route))).toEqual(route)
  })

  it("selecting a finding focuses that finding's file", () => {
    const route = parseHash("#/examples/demo-project/findings") as Extract<Route, { page: "example" }>
    const hit = finding({
      rule_id: "jwt_token",
      severity: "high",
      category: "secret",
      file: "src/app.ts",
      line: 4,
      fingerprint: "b".repeat(64),
      masked_value: "****",
    })
    const next = routeForFinding(route, hit)
    expect(next.file).toBe("src/app.ts")
    expect(next.finding).toBe(hit.fingerprint)
    expect(parseHash(formatHash(next)).page).toBe("example")
    if (parseHash(formatHash(next)).page === "example") {
      expect(parseHash(formatHash(next))).toMatchObject({ file: "src/app.ts", finding: hit.fingerprint })
    }
  })

  it("keeps the examples index and the other pages addressable", () => {
    expect(parseHash("")).toEqual({ page: "examples" })
    expect(parseHash("#/rules")).toEqual({ page: "rules" })
    expect(parseHash("#/how")).toEqual({ page: "how" })
    expect(parseHash("#/nope").page).toBe("unknown")
  })
})

describe("filters and score", () => {
  it("filters the list without changing the stored risk score", () => {
    const low = finding({})
    const high = finding({
      rule_id: "jwt_token",
      severity: "high",
      category: "secret",
      file: "src/app.ts",
      masked_value: "****",
      fingerprint: "c".repeat(64),
    })
    const stored = report([low, high], 42)
    const before = reportRiskScore(stored)
    const filtered = filterFindings(stored.findings, {
      severity: "low",
      category: "",
      rule: "",
      file: "",
    })
    expect(filtered).toHaveLength(1)
    expect(filtered[0].rule_id).toBe("debug_enabled")
    expect(stored.findings).toHaveLength(2)
    expect(reportRiskScore(stored)).toBe(before)
    expect(reportRiskScore(stored)).toBe(42)
  })
})

describe("share wording", () => {
  it("uses NO only for credential categories and never an approval word", () => {
    expect(shareVerdict([finding({ category: "secret" })])).toBe("NO")
    expect(shareVerdict([finding({ category: "credential" })])).toBe("NO")
    expect(shareVerdict([finding({ category: "risky_config" })])).toBe("Not guaranteed")
    expect(shareVerdict([])).toBe("Not guaranteed")
    expect(NO_FINDINGS_NOTE.toLowerCase()).toContain("does not guarantee")
    const allowed = new Set(["NO", "Not guaranteed"])
    expect(allowed.has(shareVerdict([]))).toBe(true)
  })
})

describe("sanitizer presentation", () => {
  it("reports a fingerprint that the rescan still contains", () => {
    const hit = finding({ fingerprint: "d".repeat(64), category: "secret", masked_value: "****" })
    expect(rescanStatus(hit, [hit])).toBe("Same fingerprint in the rescan")
    expect(rescanStatus(hit, [])).toBe("Fingerprint not in the rescan")
  })

  it("surfaces a disagreement between bytes and the sanitization report", () => {
    const example = {
      files: [{ path: "app.env", content: "one\n" }],
      sanitizedFiles: [{ path: "app.env", content: "two\n" }],
      sanitization: { modified_files: [] },
    } as unknown as ExampleRecord
    expect(sanitizerDiscrepancies(example)[0]).toContain("differs")
  })
})

describe("finding cards", () => {
  it("keeps the mask and does not copy a raw field", () => {
    const card = findingCard(finding({ category: "secret", masked_value: "****" }))
    expect(card.maskedValue).toBe("****")
    expect(Object.keys(card)).not.toContain("raw")
    expect(Object.keys(card)).not.toContain("content")
    expect(downloadName("demo-project", "original")).toBe("demo-project-original-report.json")
  })
})

describe("bundle schema", () => {
  it("rejects a report that claims safe_to_share", () => {
    const doc = report([])
    const broken = { ...doc, summary: { ...doc.summary, safe_to_share: true } }
    expect(validateScanReport(broken, "fixture").join(" ")).toContain("safe_to_share")
  })

  it("rejects a report without the risk breakdown", () => {
    const doc = JSON.parse(JSON.stringify(report([]))) as Record<string, unknown>
    delete doc.risk
    expect(validateScanReport(doc, "fixture").join(" ")).toContain("risk breakdown")
  })

  it("rejects an empty catalog", () => {
    expect(validateBundle({ catalog: {}, manifest: {}, rules: {} }).length).toBeGreaterThan(0)
  })
})
