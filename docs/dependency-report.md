## Dependency Watch (2026-06-15)

---

### `package.json` (root — frontend / build tooling)

**Security Advisories (prod)**

No vulnerabilities found (21 prod dependencies scanned).

**Outdated Packages**

All production dependencies are current (installed version matches `wanted` and `latest`).

| Package | Wanted | Latest | Change |
|---|---|---|---|
| `@sentry/browser` | 10.58.0 | 10.58.0 | ✓ current |
| `cytoscape` | 3.34.0 | 3.34.0 | ✓ current |
| `jszip` | 3.10.1 | 3.10.1 | ✓ current |

---

### `lambda/package.json` (Lambda — runtime dependencies)

**Security Advisories (prod)**

No vulnerabilities found (221 prod dependencies scanned).

**Outdated Packages — Major Version Bumps (breaking-change risk)**

| Package | Installed (wanted) | Latest | Risk |
|---|---|---|---|
| `neo4j-driver` | 5.28.3 | **6.1.0** | Major — API changes likely; test Cypher session/transaction handling before upgrading |
| `@sentry/aws-serverless` | 9.47.1 | **10.58.0** | Major — Sentry v10 ships a new init API and SDK architecture; review `Sentry.init()` call and `AWSLambda.wrapHandler` usage |
| `@octokit/rest` | 21.1.1 | **22.0.1** | Major — Octokit v22 dropped some REST convenience methods; verify any GitHub API calls in `lambda/` |

**Outdated Packages — Current (no action needed)**

| Package | Wanted | Latest |
|---|---|---|
| `@aws-sdk/client-s3` | 3.1068.0 | 3.1068.0 |

---

### Summary

| Severity | Count | Action |
|---|---|---|
| CRITICAL / HIGH security advisory | 0 | — |
| Major version bump | 3 | Review breaking changes before upgrading; do not batch blindly |
| Minor / patch bump | 0 | — |

**Recommended next steps (lambda/ only):**

1. **`neo4j-driver` 5 → 6** — Highest impact. Neo4j driver v6 renames session/transaction APIs. Read the migration guide before touching `graph.mjs`.
2. **`@sentry/aws-serverless` 9 → 10** — Medium impact. Sentry restructured its SDK in v10; the Lambda wrapper import path changed. Check `index.mjs` Sentry init.
3. **`@octokit/rest` 21 → 22** — Lower impact. Scope is limited to any GitHub API calls in the Lambda (grep `octokit` in `lambda/`).
