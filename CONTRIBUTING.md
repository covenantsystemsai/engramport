# Contributing to EngramPort

Thanks for your interest. EngramPort is the MCP wrapper layer of a larger product: the hosted memory substrate (MandelDB) lives in a private repo and is operated by Covenant Systems AI LLC. The MCP wrapper, which is what this repository contains, is open source under MIT and welcomes contributions.

## What lives here vs. what lives in the substrate

| In this repo | In the private substrate |
|---|---|
| MCP server (stdio + HTTP) | MandelDB engine |
| Tool definitions and handlers | Pinecone + Supabase glue |
| Client-facing auth (OIDC token mint, disk cache, prewarm) | Per-tenant credential vault |
| Provider-routing config (Anthropic / OpenAI / Google) | LLM router internals |
| Docs for client integration | Substrate operations |

If your change touches something in the right column (substrate behavior, model routing, governance, embeddings), open an issue first to scope the conversation; substrate-level changes go through the maintainers.

## Local development

```bash
git clone https://github.com/covenantsystemsai/engramport
cd engramport
npm install
npm run build
```

Sign up at [engramport.com](https://engramport.com) for an `ENGRAMPORT_API_KEY`. Set env:

```bash
export ENGRAMPORT_API_KEY="ek_bot_..."
export ENGRAMPORT_NAMESPACE="dev-test"
export LLM_PROVIDER="anthropic"
export LLM_API_KEY="sk-ant-..."
```

Run stdio mode:

```bash
node dist/index.js
```

Or HTTP mode (binds to `ENGRAMPORT_PORT`, default 3001):

```bash
ENGRAMPORT_MODE=http node dist/index.js
```

## Pull request expectations

- Branch from `main`. Use a descriptive branch name.
- Run `npm run build` before opening the PR; commits must compile.
- Add or update tests for behavior changes if a test harness ships in your patch.
- Keep the PR focused. Refactors-and-features in one PR will be asked to split.
- The MCP tool surface is part of the public contract. Tool name changes, schema changes, or return-shape changes need a clear deprecation path; do not break existing client integrations silently.

## Reporting security issues

Do not open public issues for security vulnerabilities. Email [security@covenantsystems.ai](mailto:security@covenantsystems.ai). We will acknowledge within 48 hours.

## Code of conduct

Be direct, be honest, ship working code. Personal attacks, harassment, or bad-faith behavior in issues or PRs will get the offender banned without ceremony.

---

EngramPort is a product of Covenant Systems AI LLC. © 2026.
