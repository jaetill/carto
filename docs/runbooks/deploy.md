# Deploy

Carto deploys via `.github/workflows/deploy.yml` on push to `master`. Two build modes (cloud + standalone).

## Frontend (cloud build)

```sh
npm install
npm run build
aws s3 sync dist/ s3://jaetill-carto/ --delete
aws cloudfront create-invalidation --distribution-id <id> --paths "/index.html"
```

## Lambda

The single Lambda `cartoApi` handles all routes via path detection. ES modules (`.mjs`).

```sh
cd lambda
npm install
zip -r cartoApi.zip *.mjs node_modules/
aws lambda update-function-code --function-name cartoApi --zip-file fileb://cartoApi.zip
```

## Standalone bundle

For the localStorage-only single-file variant:

```sh
npm run build:local
# produces dist-local/index.local.html as a self-contained file
```

## Rollback

Frontend: `git revert` + push triggers re-deploy. Lambda: re-zip prior commit's lambda/*.mjs and upload.