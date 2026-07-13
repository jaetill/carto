## Dependency Watch (2026-07-13)

---

### `package.json` (root — frontend)

**Audit:** 0 vulnerabilities in production dependencies.

#### Minor / Patch Updates (low priority — batch in monthly sweep)

| Package | Installed Range | Wanted | Latest |
|---|---|---|---|
| `@sentry/browser` | `^10.53.1` | 10.65.0 | 10.65.0 |
| `cytoscape` | `^3.31.0` | 3.34.0 | 3.34.0 |
| `jszip` | `^3.10.1` | 3.10.1 | 3.10.1 |

All three are minor/patch bumps within the same major version. No breaking-change risk. Safe to `npm update` in bulk.

---

### `lambda/package.json` (Lambda — backend)

**Audit:** 18 moderate vulnerabilities (all transitive, rooted in `@opentelemetry/core <2.8.0`).

#### Security Advisories — Moderate

| Advisory | CVE/GHSA | CVSS | Direct dep to update | Fix |
|---|---|---|---|---|
| OpenTelemetry Core: Unbounded memory allocation in W3C Baggage propagation | [GHSA-8988-4f7v-96qf](https://github.com/advisories/GHSA-8988-4f7v-96qf) | 5.3 (Medium) | `@sentry/aws-serverless` | Upgrade to `^10.65.0` (major bump 9→10) |

**Root cause:** `@sentry/aws-serverless@9.x` pulls in `@opentelemetry/core <2.8.0` which has an unbounded memory allocation issue reachable via malformed W3C Baggage headers. The fix is gated behind a major version bump (`@sentry/aws-serverless` 9→10). All 18 affected packages (`@sentry/node`, `@opentelemetry/instrumentation-*`, etc.) are transitive — upgrading the direct dep resolves all of them.

**Action:** Upgrade `@sentry/aws-serverless` to `^10.65.0`. Review [Sentry v10 migration guide](https://docs.sentry.io/platforms/javascript/migration/v9-to-v10/) for breaking changes before deploying.

#### Major Version Bumps (note — breaking-change risk)

| Package | Current Range | Latest | Risk |
|---|---|---|---|
| `@sentry/aws-serverless` | `^9.0.0` | **10.65.0** | Also resolves security advisory above. Review v10 migration guide. |
| `neo4j-driver` | `^5.28.1` | **6.2.0** | Major — Neo4j 6.x drops some 5.x APIs. Review [Neo4j Driver 6 changelog](https://github.com/neo4j/neo4j-javascript-driver/blob/HEAD/CHANGELOG.md) before updating. Core Bolt protocol and session/query APIs may have changed. |
| `@octokit/rest` | `^21.0.0` | **22.0.1** | Major — review Octokit v22 changelog for endpoint or auth changes. |

#### Minor / Patch Updates (low priority — batch in monthly sweep)

| Package | Current Range | Wanted | Latest |
|---|---|---|---|
| `@aws-sdk/client-s3` | `^3.750.0` | 3.1085.0 | 3.1085.0 |

Minor version jump within AWS SDK v3 — backward-compatible. Safe to `npm update`.

---

### Summary

| Severity | Count | Action |
|---|---|---|
| Moderate security advisory | 1 (18 transitive findings) | Upgrade `lambda/@sentry/aws-serverless` 9→10 |
| Major version bump available | 3 | Evaluate and schedule: `@sentry/aws-serverless`, `neo4j-driver`, `@octokit/rest` |
| Minor/patch behind | 4 | Batch `npm update` in monthly sweep |
