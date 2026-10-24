/// <reference types="vitest/config" />
import react from "@vitejs/plugin-react"
import { spawnSync } from "node:child_process"
import { fileURLToPath } from "node:url"
import { defineConfig } from "vite"

function requireDemoData() {
  return {
    name: "require-demo-data",
    buildStart() {
      if (process.env.VITEST) return
      const script = fileURLToPath(new URL("./scripts/check-demo-data.ts", import.meta.url))
      const result = spawnSync(process.execPath, [script], { stdio: "inherit" })
      if (result.status !== 0) {
        throw new Error("Demo data is missing or invalid.")
      }
    },
  }
}

export default defineConfig({
  base: "/SafeShare-J2/",
  plugins: [react(), requireDemoData()],
  test: {
    environment: "node",
    include: ["src/**/*.test.ts"],
  },
})
