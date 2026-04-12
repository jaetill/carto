# Carto IAM Audit

**Date:** 2026-04-09
**Auditor:** Jason + Claude
**Role under review:** `cartoApi-role`

## Current State

Single Lambda function (`cartoApi`) uses one IAM execution role:

| Lambda | Uses S3? | S3 Operations | Other AWS | Env Vars |
|--------|----------|---------------|-----------|----------|
| cartoApi | Yes | GetObject, PutObject | CloudWatch Logs | NEO4J_URI, NEO4J_USERNAME, NEO4J_PASSWORD, NEO4J_DATABASE |

### Trust Policy

Standard Lambda trust — `lambda.amazonaws.com` can assume the role via `sts:AssumeRole`.

### Current Policies on Role

**Inline: `cartoS3Access`**
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["s3:GetObject", "s3:PutObject"],
      "Resource": "arn:aws:s3:::jaetill-carto/*"
    },
    {
      "Effect": "Allow",
      "Action": "s3:ListBucket",
      "Resource": "arn:aws:s3:::jaetill-carto"
    }
  ]
}
```

**Managed: `AWSLambdaBasicExecutionRole` (AWS-managed)**
```json
{
  "Effect": "Allow",
  "Action": [
    "logs:CreateLogGroup",
    "logs:CreateLogStream",
    "logs:PutLogEvents"
  ],
  "Resource": "*"
}
```

## Code Analysis

### S3 usage (`s3.mjs`)
The Lambda imports only two S3 SDK commands:
- `GetObjectCommand` — used by `s3Get(key)` to read JSON files
- `PutObjectCommand` — used by `s3Put(key, data)` to write JSON files

No other S3 operations are used anywhere in the codebase (`index.mjs`, `graph.mjs`, `sync.mjs`).

### Non-AWS SDK calls
- **Neo4j driver** — connects to external Neo4j database via `NEO4J_URI` env var. This is a direct TCP/bolt connection, not an AWS service, so no IAM permissions needed.
- **No other AWS SDK calls** besides S3 and implicit CloudWatch logging.

## Findings

### F1: Unused `s3:ListBucket` permission (Low)
`s3:ListBucket` is granted on the bucket but **no Lambda code uses `ListObjectsCommand` or any list operation**. The code only does `GetObject` and `PutObject` on known keys. This slightly expands the blast radius — an attacker could enumerate all engagement data file paths.

### F2: Over-broad CloudWatch Logs scope (Low)
The attached `AWSLambdaBasicExecutionRole` is an AWS-managed policy that grants `logs:CreateLogGroup`, `logs:CreateLogStream`, and `logs:PutLogEvents` on `Resource: "*"`. This means the Lambda could write logs to any log group in the account, not just its own (`/aws/lambda/cartoApi`).

**Note:** Unlike the meal-planner audit where a custom managed policy was scoped to a single function's log group (breaking logging for the other 6 functions), here the AWS-managed policy uses `*` — so logging actually works, but it's broader than necessary.

### F3: No `s3:DeleteObject` — good (No action needed)
Unlike the meal-planner role, this role correctly omits `s3:DeleteObject`. The code never deletes S3 objects, and the permission is not granted. This is correct.

### F4: Single function, single role — good (No action needed)
Unlike meal-planner which shared one role across 7 functions, carto has a 1:1 mapping of function to role. This is best practice.

## Remediation

### R1: Remove `s3:ListBucket` from inline policy
No code uses `ListBucket`. Remove the second statement entirely.

**Before:**
```json
[
  {
    "Effect": "Allow",
    "Action": ["s3:GetObject", "s3:PutObject"],
    "Resource": "arn:aws:s3:::jaetill-carto/*"
  },
  {
    "Effect": "Allow",
    "Action": "s3:ListBucket",
    "Resource": "arn:aws:s3:::jaetill-carto"
  }
]
```

**After:**
```json
[
  {
    "Effect": "Allow",
    "Action": ["s3:GetObject", "s3:PutObject"],
    "Resource": "arn:aws:s3:::jaetill-carto/*"
  }
]
```

### R2: Replace AWS-managed logging policy with scoped custom policy (stretch)
Replace `AWSLambdaBasicExecutionRole` (managed, `Resource: *`) with a custom managed policy scoped to the cartoApi log group:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "logs:CreateLogGroup",
      "Resource": "arn:aws:logs:us-east-2:214599503944:*"
    },
    {
      "Effect": "Allow",
      "Action": ["logs:CreateLogStream", "logs:PutLogEvents"],
      "Resource": "arn:aws:logs:us-east-2:214599503944:log-group:/aws/lambda/cartoApi:*"
    }
  ]
}
```

This is lower priority since there's only one function on the role and the risk is minimal for a personal account.

## Summary

The `cartoApi-role` is already in reasonably good shape:
- S3 actions are limited to Get/Put (no Delete) — correct
- Single function per role — correct
- Bucket is correctly scoped to `jaetill-carto`

Two minor improvements available:
1. Remove unused `s3:ListBucket` (quick win)
2. Scope CloudWatch Logs to the specific log group (stretch goal)

## Changes Applied

| # | Change | Status |
|---|--------|--------|
| R1 | Remove s3:ListBucket from inline policy | Done (2026-04-09) |
| R2 | Replace AWS-managed logging policy with scoped custom | Done (2026-04-09) |
