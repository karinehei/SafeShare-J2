import { readFileSync, existsSync } from "node:fs"
import path from "node:path"
import { fileURLToPath } from "node:url"
import { validateBundle } from "../src/schema.ts"

const webRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..")
const dir = path.join(webRoot, "public", "demo-data")
const names = ["catalog.json", "manifest.json", "rules.json"]

function fail(message: string) {
  console.error(message)
  console.error("")
  console.error("SafeShare J2 Explorer has no scan results to display.")
  console.error("This build does not invent findings or reuse a silent fallback.")
  console.error("")
  console.error("Generate the bundle on macOS Apple Silicon with J2 0.1.0:")
  console.error("  python3 scripts/demo/generate.py")
  console.error("")
  console.error("On Windows or Linux, copy a bundle that command already produced")
  console.error("(or the safeshare-j2-demo-data artifact from the GitHub Pages workflow)")
  console.error("into web/public/demo-data/. Copying the bundle does not mean J2 ran on this machine.")
  process.exitCode = 1
}

const missing = names.filter((name) => !existsSync(path.join(dir, name)))
if (missing.length) {
  fail(`Missing ${missing.join(", ")} under web/public/demo-data/.`)
} else {
  let catalog
  let manifest
  let rules
  try {
    catalog = JSON.parse(readFileSync(path.join(dir, "catalog.json"), "utf8"))
    manifest = JSON.parse(readFileSync(path.join(dir, "manifest.json"), "utf8"))
    rules = JSON.parse(readFileSync(path.join(dir, "rules.json"), "utf8"))
    const errors = validateBundle({ catalog, manifest, rules })
    if (errors.length) {
      fail(errors.map((item: string) => `- ${item}`).join("\n"))
    } else {
      console.log(`demo data ok: ${catalog.examples.length} examples, J2 ${manifest.j2_version}`)
    }
  } catch (error) {
    if (process.exitCode !== 1) {
      fail(`Demo data is not valid JSON (${error instanceof Error ? error.message : error}).`)
    }
  }
}
