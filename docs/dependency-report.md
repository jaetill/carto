## Dependency Watch (2026-06-22)

---

### `package.json` (root — frontend / dev tooling)

#### Security Advisories
No vulnerabilities found (0 prod, 0 total).

#### Outdated Packages
All prod dependencies resolve to their latest published versions within the declared semver ranges. No updates required.

| Package | Current range | Installed | Latest |
|---|---|---|---|
| `@sentry/browser` | `^10.53.1` | 10.59.0 | 10.59.0 |
| `cytoscape` | `^3.31.0` | 3.34.0 | 3.34.0 |
| `jszip` | `^3.10.1` | 3.10.1 | 3.10.1 |

No actionable findings for root manifest.

---

### `lambda/package.json` (Lambda — runtime dependencies)

#### Security Advisories — MODERATE (18 vulnerabilities)

All 18 moderate vulnerabilities trace to a single root cause:

> **GHSA-8988-4f7v-96qf** — `@opentelemetry/core < 2.8.0`  
> Unbounded memory allocation in W3C Baggage propagation (CVSS 5.3 / CWE-770).  
> An unauthenticated attacker can cause memory exhaustion by sending crafted `baggage` headers.

**Direct dependency affected:** `@sentry/aws-serverless` `^9.0.0` (installed `9.47.1`)  
**Fix:** upgrade to `@sentry/aws-serverless@10.59.0` — this is a **major version bump** (9 → 10).

Affected transitive packages (all resolved by the same fix):
`@opentelemetry/core`, `@opentelemetry/instrumentation-amqplib`,
`@opentelemetry/instrumentation-aws-sdk`, `@opentelemetry/instrumentation-connect`,
`@opentelemetry/instrumentation-express`, `@opentelemetry/instrumentation-fs`,
`@opentelemetry/instrumentation-hapi`, `@opentelemetry/instrumentation-http`,
`@opentelemetry/instrumentation-koa`, `@opentelemetry/instrumentation-mongoose`,
`@opentelemetry/instrumentation-mysql2`, `@opentelemetry/instrumentation-pg`,
`@opentelemetry/instrumentation-undici`, `@opentelemetry/resources`,
`@opentelemetry/sdk-trace-base`, `@opentelemetry/sql-common`, `@sentry/node`.

**Action required:** upgrade `@sentry/aws-serverless` and review Sentry v10 migration guide before deploying.

---

#### Outdated Packages

##### Major version bumps available (breaking-change risk)

| Package | Current range | Installed | Latest | Risk |
|---|---|---|---|---|
| `@sentry/aws-serverless` | `^9.0.0` | 9.47.1 | **10.59.0** | API changes between Sentry SDK v9 → v10; also resolves all 18 moderate advisories above |
| `neo4j-driver` | `^5.28.1` | 5.28.3 | **6.1.0** | Major driver release — review Neo4j driver v6 changelog for breaking API changes before upgrading |
| `@octokit/rest` | `^21.0.0` | 21.1.1 | **22.0.1** | Octokit REST v22 — review changelog for endpoint or auth API changes |

##### Minor / patch (low priority — batch in monthly sweep)

| Package | Current range | Installed | Latest |
|---|---|---|---|
| `@aws-sdk/client-s3` | `^3.750.0` | 3.1073.0 | 3.1073.0 |

`@aws-sdk/client-s3` is current within its major range; no action needed.

---

### Summary

| Manifest | Critical | High | Moderate | Major bumps | Minor/patch |
|---|---|---|---|---|---|
| `package.json` (root) | 0 | 0 | 0 | 0 | 0 |
| `lambda/package.json` | 0 | 0 | 18 | 3 | 0 |

**Recommended immediate action:** upgrade `@sentry/aws-serverless` from `^9.0.0` → `^10.59.0` in `lambda/package.json` — this single change resolves all 18 moderate advisories and closes the major version gap for Sentry. Review the Sentry v10 and Neo4j driver v6 migration guides before scheduling those upgrades.
