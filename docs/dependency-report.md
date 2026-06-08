## Dependency Watch (2026-06-08)

No security advisories found across any manifest. All flagged items are version
drift (installed behind the semver-resolved latest).

---

### `package.json` (root — frontend)

**No security advisories.**

#### Minor / patch updates (low priority — batch in monthly sweep)

| Package | Installed range | Resolved (wanted) | Latest |
|---|---|---|---|
| `@sentry/browser` | `^10.53.1` | `10.56.0` | `10.56.0` |
| `cytoscape` | `^3.31.0` | `3.34.0` | `3.34.0` |
| `jszip` | `^3.10.1` | `3.10.1` | `3.10.1` |

All three are within their declared semver range; a plain `npm install` after
clearing the lock file will bring them current. No breaking changes expected.

---

### `lambda/package.json` (Lambda — backend)

**No security advisories.**

#### Major version bumps available (note — review for breaking changes before upgrading)

| Package | Pinned range | Latest in range | Latest overall | Risk |
|---|---|---|---|---|
| `@octokit/rest` | `^21.0.0` | `21.1.1` | **22.0.1** | API surface changes between v21→v22; review changelog before bumping. |
| `@sentry/aws-serverless` | `^9.0.0` | `9.47.1` | **10.56.0** | Sentry SDK v10 changes tracing API; root frontend already uses v10 — align once Lambda is ready. |
| `neo4j-driver` | `^5.28.1` | `5.28.3` | **6.1.0** | Driver v6 drops several v5 APIs; audit `graph.mjs` Cypher session usage before migrating. |

#### Minor / patch updates (low priority — batch in monthly sweep)

| Package | Pinned range | Resolved (wanted) | Latest |
|---|---|---|---|
| `@aws-sdk/client-s3` | `^3.750.0` | `3.1063.0` | `3.1063.0` |

`@aws-sdk/client-s3` is a large minor jump (3.750 → 3.1063) but stays within
v3; AWS SDK v3 follows a rolling-minor scheme with no breaking changes between
minor releases.

---

### Summary

| Severity | Count | Action |
|---|---|---|
| CRITICAL / HIGH security advisory | 0 | — |
| Major version bump | 3 | Review changelogs; schedule intentional upgrade |
| Minor / patch drift | 4 | Batch in next monthly sweep |

No actionable findings.
