# SafeShare demo project

Tiny tree for a **two-minute** live scan. It looks like an app someone is about to zip and paste into an AI chat.

**All credentials are synthetic and unusable.** The AWS id is the public documentation example. The JWT is unsigned (`alg=none`) and authenticates nowhere. Database URLs point at loopback with no password.

## Scan

From the repository root:

```
j2 run --allow-fs src/main.j2 scan ./demo-project --ai-share
```

You should see **five findings**, not a wall of noise:

| Severity | File | What the demo is showing |
| --- | --- | --- |
| CRITICAL | `.env` | AWS access key **id shape** (not a live key) |
| HIGH | `src/app.ts` | JWT-shaped session pasted into source |
| HIGH | `src/config.ts` | TLS verification turned off |
| MEDIUM | `src/config.ts` | CORS set to `*` |
| LOW | `docker-compose.yml` | `DEBUG=true` left on |

Safe to share should read **NO**. Zero findings would still not mean the tree is safe to paste; this fixture is built so the report has a plot.

`--ai-share` flags `.env`, `AGENTS.md`, and this README as files people commonly drop into assistant chats.

## What was left out on purpose

No GitHub tokens, PEM blocks, database passwords, or extra `sk-` keys. Those would drown the story. For volume and scoring, use `generate-corpus` instead of this folder.
