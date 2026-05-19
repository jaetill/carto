# Terraform - carto production environment

Phase 6 IaC retrofit per platform ADR-0007. Imports existing AWS infrastructure into Terraform state.

## Slice 1 (S3) - ready to plan and apply

Files: `s3.tf` with import blocks in `imports.tf`.

CloudFront resource defs in `cloudfront.tf.pending`. Blocked by IAM gap (see imports.tf comments).

### Workflow

```sh
cd terraform/envs/prod
tofu init
tofu plan -out slice1.plan
tofu apply slice1.plan
```

After apply: remove import blocks from imports.tf.

## Remaining slices

### Slice 2 - IAM
```sh
aws iam list-roles --query "Roles[?contains(RoleName, 'carto')].RoleName"
# carto-github-deploy
# (cartoApi execution role - check via aws lambda get-function-configuration --function-name cartoApi)
```

### Slice 3 - Lambda (cartoApi)
```sh
aws lambda get-function --function-name cartoApi --region us-east-2
```

### Slice 4 - API Gateway
```sh
aws apigatewayv2 get-apis --region us-east-2 --query "Items[?contains(Name, 'carto')]"
```

### Slice 5 - Secrets Manager (Neo4j password)
```sh
aws secretsmanager list-secrets --query "SecretList[?contains(Name, 'carto') || contains(Name, 'neo4j')].Name"
```

## State key

`s3://jaetill-tfstate/carto/prod/terraform.tfstate`