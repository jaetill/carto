# ADR-0001: Adopt the Agentic Dev Environment platform

- **Status:** Accepted
- **Date:** 2026-05-16
- **Deciders:** Jason Tilley
- **Tags:** platform, governance, AI-workflows

## Context and Problem Statement

`carto` is a pen-test engagement management tool. Subscribing to the [Agentic Dev Environment](https://github.com/jaetill/agentic-dev-environment) platform brings consistent engineering standards used on sibling projects.

## Decision Outcome

Adopt via the `ai-team` plugin subscription. Phases 1-4 immediate; Phases 5-7 deferred.

## Deviations from platform defaults

- **Frontend:** vanilla JS + Tailwind + Cytoscape + JSZip. Same family as game-night-pwa.
- **Lambda runtime:** ES modules (.mjs). Use `import`/`export`, not `require`. The lambda/ npm-ci step in CI runs successfully.
- **Two build modes:** cloud (default, Cognito+API) and standalone (localStorage-only single HTML). Phase 3 lint/format applies to both; Phase 4 CI tests the cloud build.
- **Backend:** Cognito Hosted UI on shared pool, single Lambda `cartoApi` doing path-detection routing.
- **Storage:** S3 (private) for JSON; Neo4j for graph.

## Consequences

### Positive

- Plugin subagents available immediately
- Standards inheritance
- Finding-lifecycle policy (ADR-0016) applies from day one

### Negative

- Phase 3-4 PRs add ~10-15 dev dependencies
- Lambda is ESM — eslint config needs to treat `lambda/**/*.mjs` as `sourceType: module` (not `commonjs` like sibling Lambdas)

## Links

- [Workspace ADR-0015](https://github.com/jaetill/agentic-dev-environment/blob/main/docs/adr/0015-platform-as-plugin.md)
- [Workspace ADR-0016](https://github.com/jaetill/agentic-dev-environment/blob/main/docs/adr/0016-finding-lifecycle-calibration-deferral.md)