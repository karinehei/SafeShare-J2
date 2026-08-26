import { config } from "./config.ts"

// SafeShare demo — INTENTIONALLY FAKE session.
// Unsigned alg=none JWT. It authenticates nowhere. Do not send it
// to a real API or paste it into an assistant chat as a live token.
const demoSession = "eyJhbGciOiJub25lIn0.eyJmb28iOiJiYXIifQ.signaturexx"

export function handler() {
  return {
    cors: config.CORS,
    session: demoSession,
    note: "synthetic demo user — not a real account",
  }
}
