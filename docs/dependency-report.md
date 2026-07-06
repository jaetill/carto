## Dependency Watch (2026-07-06)

---

### `package.json` (root — frontend)

#### Security Advisories
None. `npm audit` reports 0 vulnerabilities across 21 production dependencies.

#### Major Version Bumps
None.

#### Minor / Patch Updates (low priority — batch in monthly sweep)
| Package | Declared Range | Latest Available |
|---|---|---|
| `@sentry/browser` | `^10.53.1` | `10.63.0` |
| `cytoscape` | `^3.31.0` | `3.34.0` |

`jszip` is current (`3.10.1`).

---

### `lambda/package.json` (Lambda — backend)

#### Security Advisories — Moderate

**Advisory GHSA-8988-4f7v-96qf — `@opentelemetry/core` Unbounded Memory Allocation**
- **CVSS:** 5.3 (AV:N/AC:L/PR:N/UI:N — remotely exploitable, no auth)
- **CWE:** CWE-770 (Allocation of Resources Without Limits or Throttling)
- **Affected range:** `@opentelemetry/core` < 2.8.0
- **Root cause:** `@sentry/aws-serverless` ≤ 9.47.1 pulls in a vulnerable transitive
  `@opentelemetry/core`. All 18 vulnerable packages (`@opentelemetry/instrumentation-*`,
  `@sentry/node`, etc.) trace back to this single root.
- **Fix:** Upgrade `@sentry/aws-serverless` from `^9.0.0` → `^10.63.0` (major bump).
  The fix is marked `isSemVerMajor: true` — review Sentry v9→v10 migration guide before updating.

> Although severity is Moderate (not High/Critical), the attack vector is network-accessible
> and no authentication is required. Recommend addressing in the next planned Lambda deploy.

#### Major Version Bumps (breaking-change risk — review before updating)
| Package | Declared Range | Latest | Notes |
|---|---|---|---|
| `@sentry/aws-serverless` | `^9.0.0` | `10.63.0` | Also fixes the moderate advisory above — prioritize |
| `neo4j-driver` | `^5.28.1` | `6.2.0` | Neo4j Driver 6.x may change Bolt protocol or API surface |
| `@octokit/rest` | `^21.0.0` | `22.0.1` | Review GitHub REST API client breaking changes |

#### Minor / Patch Updates (low priority — batch in monthly sweep)
| Package | Declared Range | Latest Available |
|---|---|---|
| `@aws-sdk/client-s3` | `^3.750.0` | `3.1079.0` |

---

### Summary

| Manifest | Critical | High | Moderate | Major Bumps | Minor/Patch |
|---|---|---|---|---|---|
| `package.json` (root) | 0 | 0 | 0 | 0 | 2 |
| `lambda/package.json` | 0 | 0 | 18 | 3 | 1 |

**Recommended actions:**
1. **Lambda:** Upgrade `@sentry/aws-serverless` `^9.0.0` → `^10.63.0` to resolve all 18 moderate advisories. This is a major bump — consult the [Sentry v9→v10 migration guide](https://docs.sentry.io/platforms/javascript/guides/aws-lambda/migration/v9-to-v10/) before deploying.
2. **Lambda:** Evaluate `neo4j-driver` 5→6 and `@octokit/rest` 21→22 major bumps on their own schedules; neither has a known CVE but both carry breaking-change risk.
3. **Root:** Minor bumps for `@sentry/browser` and `cytoscape` — safe to batch into a monthly sweep.
