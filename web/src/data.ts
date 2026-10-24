import { validateBundle } from "./schema.ts"
import { hydrateExample, type ExampleRecord } from "./model.ts"

export interface ManifestFile {
  kind: string
  j2_version: string
  source_commit: string | null
  dirty: boolean | null
  generated_at: string
  generation_mode: string
  commands: string[]
  network: string
  report_schema_version: string
  sanitization_output_paths: string
  examples: string[]
}

export interface RuleRecord {
  id: string
  name: string
  category: string
  severity: string
  family: string
  applies: string
  applies_label: string
  description: string
  recommendation: string
  limitations: string
  placeholders: boolean
  min_len: number
  min_bits: number
  pattern: string
  patterns: string[]
  sanitization: boolean
  source: string
  detector: string
}

export interface RulesFile {
  version: string
  source: string
  entropy_source: string
  high_confidence_rules: string[]
  rules: RuleRecord[]
}

export interface LoadedBundle {
  manifest: ManifestFile
  rules: RulesFile
  examples: ExampleRecord[]
}

const MISSING = [
  "Published demo data could not be loaded.",
  "J2 runs when the bundle is generated, before publication. This page does not scan or sanitize.",
  "On macOS Apple Silicon with J2 0.1.0: python3 scripts/demo/generate.py",
  "On Windows or Linux, copy a bundle that command already wrote (or the safeshare-j2-demo-data artifact) into web/public/demo-data/.",
  "Copying that bundle does not mean J2 executed on this machine.",
].join("\n")

export function jsonFromResponseBody(url: string, status: number, contentType: string, body: string): unknown {
  if (status < 200 || status >= 300) {
    throw new Error(`${url} returned HTTP ${status}`)
  }
  const trimmed = body.trimStart()
  if (contentType.toLowerCase().includes("text/html") || trimmed.startsWith("<")) {
    throw new Error(`${url} is not in the published bundle. The server returned an HTML page instead of JSON.`)
  }
  try {
    return JSON.parse(body) as unknown
  } catch {
    throw new Error(`${url} is not valid JSON.`)
  }
}

async function fetchJson(url: string, signal: AbortSignal | undefined) {
  const response = await fetch(url, { signal })
  const body = await response.text()
  return jsonFromResponseBody(url, response.status, response.headers.get("content-type") ?? "", body)
}

export async function loadPublishedBundle(signal?: AbortSignal): Promise<LoadedBundle> {
  const root = `${import.meta.env.BASE_URL}demo-data/`
  try {
    const [catalog, manifest, rules] = await Promise.all([
      fetchJson(`${root}catalog.json`, signal),
      fetchJson(`${root}manifest.json`, signal),
      fetchJson(`${root}rules.json`, signal),
    ])
    const errors = validateBundle({ catalog, manifest, rules })
    if (errors.length) {
      throw new Error(errors.join("\n"))
    }
    return {
      manifest: manifest as ManifestFile,
      rules: rules as RulesFile,
      examples: catalog.examples.map(hydrateExample),
    }
  } catch (error) {
    if (error instanceof DOMException && error.name === "AbortError") throw error
    const detail = error instanceof Error ? error.message : String(error)
    throw new Error(`${MISSING}\n\n${detail}`)
  }
}
