# Synthetic fixture provenance

These trees exist so the GitHub Pages explorer can show real J2 output. They are not live projects. Repository self-scan ignores `/examples/` in `.safeshareignore` for the same reason it ignores `demo-project/` and `tests/`: the strings below are intentional fixtures.

Every value is either a documented public example or a dummy alphabet already used in this repository's tests. Do not add live credentials here.

| Fixture | Value | Where it comes from |
| --- | --- | --- |
| `demo-project/.env` | `AKIAIOSFODNN7EXAMPLE` | AWS general reference documentation example access key id. It cannot sign requests. |
| `demo-project/src/app.ts` | `eyJhbGciOiJub25lIn0.eyJmb28iOiJiYXIifQ.signaturexx` | Unsigned `alg=none` JWT used by `demo-project/` and `tests/demo_project_test.j2`. It authenticates nowhere. |
| `examples/high-confidence/credentials.env` | `AKIAIOSFODNN7EXAMPLE` | Same published AWS documentation example. |
| `examples/high-confidence/credentials.env` | `ghp_0123456789abcdef0123456789abcdef1234` | Dummy `ghp_` body from `tests/detectors_test.j2` and `tests/sanitize_test.j2`. Not a GitHub token. |
| `examples/high-confidence/credentials.env` | `postgres://ada:hunter2_secret@db.internal:5432/app` | Dummy database userinfo from `tests/detectors_test.j2`. |
| `examples/high-confidence/id_rsa` | PEM header plus `SECRETMATERIAL` | Block shape from `tests/sanitize_test.j2`. The body is a label, not key material. |
| `examples/heuristic-remains/app.env` | `sk-abcdefghijklmnopqrstuvwxyzABCDEF` | Dummy OpenAI-style shape from `tests/detectors_test.j2`. |
| `examples/heuristic-remains/app.env` | `hunter2_secret` | Dummy password from `tests/detectors_test.j2`. |
| `examples/heuristic-remains/app.env` | `nR8vL2qZxP4mK9sW1cY7bH3fT6dG0jA5uE2iO9pQ4wX8kM3n` | Entropy token constant from `tests/entropy_test.j2`. |
| `examples/heuristic-remains/app.env` | `Bearer abcdefghijklmnopqrstuvwxyz012345` | Dummy bearer token from `tests/detectors_test.j2`. |
| `examples/risky-config/app.env` | `DEBUG`, `NODE_ENV`, `CORS`, `verify_ssl`, `authentication` | Assignment shapes from `tests/risky_config_test.j2`. No credential literals. |
| `examples/placeholders/` | `changeme`, `${API_KEY}`, short digests, the RFC 4122 sample UUID, a public key block, loopback URLs without passwords | Negative cases from `tests/false_positive_test.j2`. |

`examples/high-confidence/` is built so sanitize can redact the four higher-confidence rule ids. `examples/heuristic-remains/` keeps an AWS documentation example so the redaction is visible, and keeps the heuristic rows because sanitize copies those through. Absence of findings in `examples/placeholders/` is not a clearance to share a tree.
