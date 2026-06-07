# ADR-0002: Use DynamoDB for feedback rate limiting

- **Status:** Proposed
- **Date:** 2026-06-07
- **Deciders:** Jason Tilley
- **Tags:** aws, lambda, new-external-dep, rate-limiting

## Context and Problem Statement

The feedback Lambda (`carto-feedback`) rate-limits submissions per IP using an in-memory `Map`. Because Lambda instances are ephemeral and scale independently, each warm instance maintains its own counter — a burst of requests spread across N instances effectively multiplies the real limit by N. How should we implement rate limiting that works correctly across concurrent Lambda invocations?

## Decision Drivers

- Rate limits must be accurate across all concurrent Lambda instances
- Solution must not block legitimate users if the backing store has a transient outage
- Operational cost should be near-zero at current (low) traffic volumes
- No new long-running infrastructure to operate (no Redis cluster, no VPC)

## Considered Options

- Option A: DynamoDB atomic counters with fixed-window TTL
- Option B: ElastiCache (Redis) with `INCR` + `EXPIRE`
- Option C: API Gateway usage plans (built-in throttling)

## Decision Outcome

Chosen option: **Option A — DynamoDB atomic counters**, because it provides correct cross-instance counting with zero idle cost, no VPC requirement, and a fail-open design that avoids blocking users during DynamoDB transient errors.

## Consequences

### Positive

- Rate limits are now accurate regardless of how many Lambda instances are warm
- PAY_PER_REQUEST billing means near-zero cost at current traffic (~pennies/month)
- TTL-based cleanup removes stale rows automatically — no cron or manual maintenance
- Fail-open on DynamoDB errors preserves availability for legitimate users

### Negative

- New AWS service dependency (DynamoDB) in the Lambda's operational surface
- New IAM policy (`dynamodb:UpdateItem`) and Terraform resource to maintain
- `@aws-sdk/client-dynamodb` added to Lambda bundle — minor increase in cold-start time and zip size

### Neutral

- Fixed-window algorithm is unchanged from the in-memory version; only the storage backend moved
- The `RATE_LIMIT_TABLE` env var is configurable, so testing can point to a separate table

## Pros and Cons of the Options

### Option A: DynamoDB atomic counters with fixed-window TTL

- Pro: Serverless, zero idle cost, scales automatically
- Pro: `UpdateItem` with `ADD` is atomic — no read-then-write race
- Pro: TTL cleans up stale windows without application logic
- Pro: No VPC required — Lambda stays in default networking
- Con: New AWS service dependency and IAM surface
- Con: ~5-10 ms per rate-limit check (vs. sub-ms in-memory)

### Option B: ElastiCache (Redis) with INCR + EXPIRE

- Pro: Sub-millisecond latency, industry-standard pattern
- Con: Requires VPC + NAT gateway — significant infrastructure and cost overhead
- Con: Fixed hourly cost (~$13/month minimum for `cache.t4g.micro`) regardless of traffic
- Con: Operational burden: patching, failover, monitoring

### Option C: API Gateway usage plans

- Pro: Zero application code — purely configuration
- Con: Throttles at the API Gateway layer, not per-route — cannot scope to feedback endpoint only without a separate API
- Con: Does not distinguish by IP — would need API keys, defeating the purpose of an unauthenticated feedback endpoint

## Implementation notes

- DynamoDB table: `carto-rate-limits` (Terraform: `terraform/envs/prod/dynamodb.tf`)
- IAM policy: `feedback_dynamodb` grants only `dynamodb:UpdateItem` (least-privilege)
- Lambda env var: `RATE_LIMIT_TABLE` points to the table name
- Key schema: `feedback#<ip>#<windowEpochMs>` — each hour-window gets a fresh item
- TTL set to 2x window length to outlive DynamoDB's up-to-48h TTL propagation lag

## Links

- [Issue #40](https://github.com/jaetill/carto/issues/40) — original bug report for in-memory rate limiter bypass
- [DynamoDB atomic counters](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/WorkingWithItems.html#WorkingWithItems.AtomicCounters) — AWS documentation
