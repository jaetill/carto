# Carto — Claude Context

## What this app is
A penetration testing engagement management platform. Imports and parses output
from security tools (Nmap, Metasploit, Nessus, SharpHound, Nuclei, Ghostwriter),
maps hosts/connections/users/credentials into a Neo4j graph database, and
visualizes network topology and attack paths. Built for personal offensive security
use — not a multi-tenant SaaS.

Hosted at **https://carto.jaetill.com**.

## Tech stack
- **Frontend**: Vite + Tailwind SPA. Two build modes:
  - `cloud` (default) — Cognito auth + API Gateway backend
  - `standalone` — localStorage only, single bundled HTML file (`dist-local/`)
  - Switches backend via `@carto/api` alias → `adapters/cloud.js` or `adapters/local.js`
  - Graph visualization via **Cytoscape.js**; ZIP import via **JSZip**
- **Backend**: Single Lambda (`cartoApi`) handles all routes via path detection.
  Lambda uses **ES modules** (`.mjs` files) — note: `require()` does not work.
- **Graph DB**: **Neo4j** — Lambda connects via env vars; all topology/relationship
  queries go through `graph.mjs`.
- **Storage**: S3 bucket `jaetill-carto` (private) for JSON persistence.
- **Auth**: Cognito Hosted UI on shared pool `us-east-2_xneeJzaDJ`, client `3r633l045s8fse9v1ebubk8re6`,
  managed-login branding `ffc6f1fe-5324-4e48-aee3-3788635546f8`. OAuth Authorization Code + PKCE,
  hand-rolled in `src/js/auth.js` (no `aws-amplify` dependency).
- **Authz**: Group `carto-users` required. Frontend `app.js` redirects non-members
  to portal; Lambda `cartoApi` returns 403 if claim missing.
  All API routes require Cognito JWT in `Authorization` header.

## AWS resources
| Resource | Value |
|---|---|
| S3 bucket | `jaetill-carto` |
| CloudFront distribution | `E36OPEPVLCLUYJ` → `carto.jaetill.com` |
| API Gateway | `9o7c3668a4` (prod stage) |
| Cognito user pool | `us-east-2_xneeJzaDJ` (shared with portal, meal-planner, game-night) |
| Cognito web client | `3r633l045s8fse9v1ebubk8re6` |
| Cognito branding | `ffc6f1fe-5324-4e48-aee3-3788635546f8` |
| API GW Cognito authorizer | `b7mlmb` |
| Lambda function | `cartoApi` |
| Lambda execution role | `cartoApi-role` |
| GitHub deploy role | `carto-github-deploy` (OIDC) |
| Region | `us-east-2` |

## Lambda config (`cartoApi`)
**Env vars:**
| Var | Purpose |
|---|---|
| `NEO4J_URI` | Bolt URI (e.g. `neo4j+s://...`) |
| `NEO4J_USERNAME` | Neo4j username |
| `NEO4J_DATABASE` | Neo4j database name |

**Secrets Manager:** `carto/secrets` stores `NEO4J_PASSWORD`. Fetched once per
cold start (~50-100ms) and cached in memory for reuse across warm invocations.

## API routes (`9o7c3668a4/prod`)
All routes require `Authorization: {CognitoIdToken}` header. All handled by
`cartoApi` Lambda via path detection in `lambda/index.mjs`.

| Method | Path | Purpose |
|---|---|---|
| GET | `/engagements` | List all engagements |
| POST | `/engagements` | Save full engagements list |
| GET | `/engagement/{id}/data` | Load hosts, notes, credentials |
| POST | `/engagement/{id}/data` | Save hosts/notes/credentials (triggers Neo4j sync) |
| GET | `/engagement/{id}/snapshots` | Load command snapshots |
| POST | `/engagement/{id}/snapshots` | Save snapshots (triggers Neo4j sync) |
| GET | `/engagement/{id}/imports` | Load tool imports |
| POST | `/engagement/{id}/imports` | Save imports (triggers Neo4j sync) |
| GET | `/engagement/{id}/graph` | Get topology graph from Neo4j |
| GET | `/engagement/{id}/graph/paths` | Get attack paths from Neo4j |
| POST | `/engagement/{id}/graph/paths` | Add custom attack path |
| POST | `/engagement/{id}/graph/paths/delete` | Remove attack path |
| POST | `/engagement/{id}/graph/sync` | Force full Neo4j resync |

## Lambda files (`lambda/`)
All files are ES modules (`.mjs`). Lambda has its own `package.json` with
`neo4j-driver` and `@aws-sdk/client-s3` — these are bundled into the zip.

| File | Purpose |
|---|---|
| `index.mjs` | Entry point — routes requests by path to handlers |
| `s3.mjs` | `s3Get(key)` / `s3Put(key, data)` helpers for `jaetill-carto` bucket |
| `graph.mjs` | All Neo4j Cypher operations (sync hosts, connections, users, creds, paths) |
| `sync.mjs` | Parses snapshots/imports → extracts relationships → calls graph.mjs |

## S3 data layout
```
engagements.json                          — array of engagement metadata
engagements/{engagementId}/data.json      — { hosts, notes, credentials }
engagements/{engagementId}/snapshots.json — array of command snapshots
engagements/{engagementId}/imports.json   — array of tool imports
```

**Never delete S3 data files on deploy** — deploy.yml excludes `engagements.json`
and `engagements/*` from sync.

## Frontend source (`src/js/`)
```
app.js                        — init, nav, sidebar, auth guard
app.local.js                  — standalone mode variant
config.js                     — Amplify/Cognito config, DEBUG_MODE
nav.js                        — navigation state
data/
  index.js                    — factory functions, top-level data API
  adapters/cloud.js           — API Gateway adapter (Cognito-authed fetches)
  adapters/local.js           — localStorage adapter for standalone mode
  graph.js                    — graph queries and mock topology builder
  parsers.js                  — command output parsers (netstat, pslist, etc.)
  mockScenario.js             — fake engagement for dev/demo
components/
  renderEngagements.js        — sidebar engagement list
  renderEngagement.js         — main engagement view (tabbed)
  renderHost.js               — host detail view
  renderHostGraph.js          — per-host topology subgraph
  renderTopology.js           — full engagement network graph (Cytoscape)
  renderPathing.js            — attack path visualization and editing
  renderImport.js             — file import UI (Nmap, Metasploit, etc.)
  renderCredentials.js        — credential tracking
  renderUser.js               — user analysis view
ui/elements.js                — btn(), field() helpers
ui/toast.js                   — toast notifications
```

## Deployment
- `deploy.yml` on push to `master`
- Frontend build: `npm run build` → sync `dist/` to `jaetill-carto` S3
  - **Excludes `engagements.json` and `engagements/*`** to protect engagement data
- Lambda: `cd lambda && npm ci` → zip all `.mjs` files + `node_modules` →
  deploy to `cartoApi`
- CloudFront invalidation on `/*`

## Key gotchas
- Lambda uses **ES modules** — all Lambda files are `.mjs`, use `import`/`export`.
  Do not use `require()` or CommonJS patterns.
- Lambda zip **must include `node_modules`** (neo4j-driver is not available in
  the Lambda runtime) — the deploy step runs `npm ci` in `lambda/` before zipping.
- Neo4j sync is triggered automatically on every POST to `/data`, `/snapshots`,
  and `/imports`. The graph stays in sync with S3 without manual intervention.
- Two build modes — if working on frontend, be aware that `@carto/api` resolves
  differently in cloud vs standalone mode.
- The standalone build (`npm run build:local`) produces a single self-contained
  HTML file for offline use — no AWS dependencies.


---

## Platform inheritance

This project adopts the [Agentic Dev Environment](https://github.com/jaetill/agentic-dev-environment) platform per [ADR-0001](docs/adr/0001-platform-adoption.md).

### AI configuration

The platform's subagents, slash commands, and hooks are delivered via the `ai-team` plugin subscription (per workspace ADR-0015). `.claude/settings.json` retains only the plugin subscription, permissions block, and marketplace pointer.

### Finding lifecycle (per workspace ADR-0016)

Reviewer agents calibrate severity, low/nit findings get `deferred-until-adjacent`, Sentry/critical issues auto-trigger the implementer.