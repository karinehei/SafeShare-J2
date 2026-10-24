import { describe, expect, it } from "vitest"
import { jsonFromResponseBody } from "./data.ts"

const page = "<!doctype html><html><body>SafeShare J2 Explorer</body></html>"

describe("published JSON responses", () => {
  it("reads a JSON document", () => {
    expect(jsonFromResponseBody("/SafeShare-J2/demo-data/catalog.json", 200, "application/json", '{"ok":true}')).toEqual({
      ok: true,
    })
  })

  it("names a missing file when the server returns the HTML page", () => {
    expect(() => jsonFromResponseBody("/SafeShare-J2/demo-data/catalog.json", 200, "text/html", page)).toThrow(
      /catalog\.json is not in the published bundle/,
    )
  })

  it("names a missing file when the HTML body has no content type", () => {
    expect(() => jsonFromResponseBody("/SafeShare-J2/demo-data/manifest.json", 200, "", page)).toThrow(
      /manifest\.json is not in the published bundle/,
    )
  })

  it("keeps the HTTP status when the file is absent", () => {
    expect(() => jsonFromResponseBody("/SafeShare-J2/demo-data/rules.json", 404, "text/html", page)).toThrow(
      /HTTP 404/,
    )
  })
})
