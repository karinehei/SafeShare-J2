# Agent notes (SafeShare demo)

This tree is a **two-minute SafeShare fixture**, not a product.

- Every credential-shaped string is **synthetic and unusable**.
- Do not paste `.env` or `src/app.ts` into ChatGPT, Claude, Gemini, Cursor, or Copilot as if they were a real app.
- Run SafeShare first:

```
j2 --allow-fs src/main.j2 scan ./demo-project --ai-share
```

Expected story: one AWS-shaped key in `.env`, a fake session JWT in source, sloppy local TLS/CORS in `src/config.ts`, and DEBUG left on in compose.
