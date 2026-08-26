// SafeShare demo — INTENTIONALLY FAKE local config.
// Wildcard CORS and disabled TLS checks are here so a scan has something
// besides credentials to talk about. Do not copy this into production.

export const config = {
  CORS: "*",
  rejectUnauthorized: false,
}
