// @ts-nocheck
/** Structural checks for a J2-produced explorer bundle. Not a detector. */

export const EXPLORER_EXAMPLE_IDS = [
  "demo-project",
  "high-confidence",
  "heuristic-remains",
  "risky-config",
  "placeholders",
]

const FINDING_KEYS = [
  "rule_id",
  "severity",
  "category",
  "file",
  "line",
  "column",
  "message",
  "reason",
  "recommendation",
  "masked_value",
  "fingerprint",
]

const RISK_KEYS = [
  "score",
  "label",
  "reason",
  "critical_points",
  "high_points",
  "medium_points",
  "low_points",
  "credential_bonus",
]

const SECRET_CATEGORIES = new Set(["secret", "credential", "heuristic"])

function isInt(value) {
  return typeof value === "number" && Number.isInteger(value)
}

function isHex64(value) {
  return typeof value === "string" && /^[0-9a-fA-F]{64}$/.test(value)
}

function validRel(path) {
  return (
    typeof path === "string" &&
    path.length > 0 &&
    !path.includes("..") &&
    !path.startsWith("/") &&
    !path.includes("\\")
  )
}

export function validateScanReport(doc, label) {
  const errors = []
  if (!doc || typeof doc !== "object" || Array.isArray(doc)) {
    return [`${label}: report is not an object`]
  }
  if (doc.version !== "0.1.0") errors.push(`${label}: version must be 0.1.0`)
  const summary = doc.summary
  if (!summary || typeof summary !== "object") {
    errors.push(`${label}: missing summary`)
  } else {
    if (summary.safe_to_share !== false) {
      errors.push(`${label}: safe_to_share must remain false`)
    }
    for (const key of ["files_scanned", "files_skipped", "findings", "risk_score"]) {
      if (!isInt(summary[key])) errors.push(`${label}: summary.${key} must be an integer`)
    }
    if (typeof summary.assessment !== "string" || summary.assessment === "") {
      errors.push(`${label}: summary.assessment must be a string`)
    }
  }
  const risk = doc.risk
  if (!risk || typeof risk !== "object") {
    errors.push(`${label}: missing risk breakdown`)
  } else {
    for (const key of RISK_KEYS) {
      if (!(key in risk)) errors.push(`${label}: risk.${key} is missing`)
    }
    if (isInt(risk.score) && summary && isInt(summary.risk_score) && risk.score !== summary.risk_score) {
      errors.push(`${label}: risk.score does not match summary.risk_score`)
    }
  }
  if (!Array.isArray(doc.findings)) {
    errors.push(`${label}: findings must be a list`)
    return errors
  }
  if (summary && isInt(summary.findings) && summary.findings !== doc.findings.length) {
    errors.push(`${label}: summary.findings does not match the findings list`)
  }
  doc.findings.forEach((finding, index) => {
    const where = `${label} finding ${index}`
    if (!finding || typeof finding !== "object") {
      errors.push(`${where}: not an object`)
      return
    }
    for (const key of FINDING_KEYS) {
      if (!(key in finding)) errors.push(`${where}: missing ${key}`)
    }
    if (SECRET_CATEGORIES.has(finding.category)) {
      if (typeof finding.masked_value !== "string" || !finding.masked_value.includes("*")) {
        errors.push(`${where}: credential finding is missing a mask`)
      }
    } else if (finding.category === "risky_config" && finding.masked_value !== "") {
      errors.push(`${where}: configuration finding must not carry a masked secret`)
    }
    if ("fingerprint" in finding && !isHex64(finding.fingerprint)) {
      errors.push(`${where}: fingerprint must be 64 hex characters`)
    }
  })
  return errors
}

function validateSanitization(doc, label) {
  const errors = []
  if (!doc || typeof doc !== "object") return [`${label}: sanitization report is not an object`]
  if (doc.version !== "0.1.0") errors.push(`${label}: sanitization version must be 0.1.0`)
  if (typeof doc.placeholder !== "string" || doc.placeholder === "") {
    errors.push(`${label}: missing redaction placeholder`)
  }
  if (!Array.isArray(doc.high_confidence_rules) || doc.high_confidence_rules.length === 0) {
    errors.push(`${label}: missing high_confidence_rules`)
  }
  const summary = doc.summary
  if (!summary || typeof summary !== "object") {
    errors.push(`${label}: missing sanitization summary`)
  } else {
    for (const key of ["files_copied", "files_modified", "files_skipped", "replacements"]) {
      if (!isInt(summary[key])) errors.push(`${label}: sanitization summary.${key} must be an integer`)
    }
  }
  if (!Array.isArray(doc.modified_files)) errors.push(`${label}: modified_files must be a list`)
  if (!Array.isArray(doc.skipped)) errors.push(`${label}: skipped must be a list`)
  return errors
}

function validateRules(doc) {
  const errors = []
  if (!doc || typeof doc !== "object") return ["rules export is not an object"]
  if (doc.version !== "0.1.0") errors.push("rules export version must be 0.1.0")
  if (!Array.isArray(doc.high_confidence_rules) || doc.high_confidence_rules.length !== 4) {
    errors.push("rules export must list four high-confidence redact ids")
  }
  if (!Array.isArray(doc.rules) || doc.rules.length < 17) {
    errors.push("rules export is shorter than the J2 catalog")
    return errors
  }
  const high = new Set(doc.high_confidence_rules ?? [])
  const seen = new Set()
  let entropy = 0
  for (const rule of doc.rules) {
    if (!rule || typeof rule.id !== "string") {
      errors.push("rule entry is missing an id")
      continue
    }
    if (seen.has(rule.id)) errors.push(`duplicate rule id ${rule.id}`)
    seen.add(rule.id)
    for (const key of ["description", "limitations", "source", "severity", "category", "family"]) {
      if (typeof rule[key] !== "string" || rule[key] === "") {
        errors.push(`${rule.id}: ${key} must be a non-empty string`)
      }
    }
    if (!Array.isArray(rule.patterns) || rule.patterns.length === 0) {
      errors.push(`${rule.id}: patterns must come from the J2 export`)
    }
    if (typeof rule.sanitization !== "boolean") {
      errors.push(`${rule.id}: sanitization must be a boolean`)
    } else if (rule.sanitization !== high.has(rule.id)) {
      errors.push(`${rule.id}: sanitization flag disagrees with high_confidence_rules`)
    }
    if (rule.family === "entropy") {
      entropy += 1
      if (rule.source !== "src/entropy.j2" || rule.detector !== "entropy") {
        errors.push("entropy rule must point at src/entropy.j2")
      }
    }
  }
  if (!seen.has("high_entropy_string") || entropy !== 1) {
    errors.push("rules export must include the entropy detector once")
  }
  for (const id of ["aws_access_key_id", "jwt_token", "debug_enabled", "pem_private_key"]) {
    if (!seen.has(id)) errors.push(`rules export is missing ${id}`)
  }
  return errors
}

function validateFiles(files, label) {
  const errors = []
  if (!Array.isArray(files) || files.length === 0) {
    return [`${label}: file list is empty`]
  }
  const seen = new Set()
  for (const file of files) {
    if (!file || !validRel(file.path) || typeof file.content !== "string") {
      errors.push(`${label}: invalid file entry`)
      continue
    }
    if (seen.has(file.path)) errors.push(`${label}: duplicate file ${file.path}`)
    seen.add(file.path)
  }
  return errors
}

export function validateBundle({ catalog, manifest, rules }) {
  const errors = []
  if (!catalog || catalog.kind !== "safeshare-j2-explorer-catalog" || !Array.isArray(catalog.examples)) {
    errors.push("catalog.json is missing or is not an explorer catalog")
    return errors
  }
  if (!manifest || manifest.kind !== "safeshare-j2-explorer-manifest") {
    errors.push("manifest.json is missing or is not an explorer manifest")
  } else {
    if (typeof manifest.j2_version !== "string" || !manifest.j2_version.includes("0.1.0")) {
      errors.push("manifest is missing the J2 0.1.0 version string")
    }
    if (manifest.generation_mode !== "j2-interpreter") {
      errors.push("manifest generation_mode must be j2-interpreter")
    }
    if (!Array.isArray(manifest.commands) || !manifest.commands.some((cmd) => String(cmd).includes("j2 --allow-fs src/main.j2 scan"))) {
      errors.push("manifest is missing the J2 scan command")
    }
    if (manifest.report_schema_version !== "0.1.0") {
      errors.push("manifest report_schema_version must be 0.1.0")
    }
    if (typeof manifest.generated_at !== "string" || manifest.generated_at === "") {
      errors.push("manifest is missing generated_at")
    }
  }
  errors.push(...validateRules(rules))
  const ids = catalog.examples.map((example) => example && example.id)
  if (ids.join("|") !== EXPLORER_EXAMPLE_IDS.join("|")) {
    errors.push(`catalog examples must be ${EXPLORER_EXAMPLE_IDS.join(", ")}`)
  }
  if (manifest && Array.isArray(manifest.examples) && manifest.examples.join("|") !== EXPLORER_EXAMPLE_IDS.join("|")) {
    errors.push("manifest example list does not match the catalog")
  }
  for (const example of catalog.examples) {
    if (!example || typeof example.id !== "string") {
      errors.push("example is missing an id")
      continue
    }
    const label = example.id
    if (typeof example.title !== "string" || typeof example.provenance !== "string") {
      errors.push(`${label}: missing title or provenance`)
    }
    errors.push(...validateFiles(example.files, `${label} fixture`))
    errors.push(...validateFiles(example.sanitizedFiles, `${label} sanitized`))
    for (const [field, name] of [
      ["originalReportText", "original report"],
      ["sanitizedReportText", "rescan report"],
      ["sanitizationText", "sanitization report"],
    ]) {
      if (typeof example[field] !== "string" || example[field].trim() === "") {
        errors.push(`${label}: missing ${name} text`)
        continue
      }
      try {
        const parsed = JSON.parse(example[field])
        if (field === "sanitizationText") errors.push(...validateSanitization(parsed, label))
        else errors.push(...validateScanReport(parsed, `${label} ${name}`))
      } catch {
        errors.push(`${label}: ${name} is not JSON`)
      }
    }
  }
  return errors
}
