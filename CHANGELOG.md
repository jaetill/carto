# Changelog

## 1.0.0 (2026-05-23)


### Features

* adopt Agentic Dev Environment platform (Phase 1+2) ([956be11](https://github.com/jaetill/carto/commit/956be11dd26a27df6258bd3b4a4f0cfed3f2ce97))
* adopt Agentic Dev Environment platform (Phase 1+2) ([70c11c3](https://github.com/jaetill/carto/commit/70c11c3ee1ff9540e48c570164c5cc3e60e52463))
* adopt CI workflows (Phase 4 of platform adoption) ([e4ae1aa](https://github.com/jaetill/carto/commit/e4ae1aa021d1ba97225eab5cfe7425c81c83d322))
* adopt CI workflows (Phase 4 of platform adoption) ([c16d48d](https://github.com/jaetill/carto/commit/c16d48d1fd3c0f4813a7ffc1be71797531fefbea))
* **ci:** migrate claude-pr-review to platform reusable (ADR-0018) ([7f683f5](https://github.com/jaetill/carto/commit/7f683f5a7d9ea87589f71dee5cbb1d2b2c91df20))
* **iac:** Phase 6 Slice 1 - terraform skeleton + S3 import ([#11](https://github.com/jaetill/carto/issues/11)) ([d73ad22](https://github.com/jaetill/carto/commit/d73ad22af34a172327210aad7a407d8de90b9d89))
* **iac:** Slice 2 (IAM) - 2 roles + 4 inline policies ([#12](https://github.com/jaetill/carto/issues/12)) ([0d75748](https://github.com/jaetill/carto/commit/0d7574838314dd1d817ecc2a06fc4e7fadd0982c))
* **iac:** Slice 3 (Lambdas) - import cartoApi ([#13](https://github.com/jaetill/carto/issues/13)) ([e729daf](https://github.com/jaetill/carto/commit/e729daf860ca5241d22017d58b81c807bfaa4c0f))
* **iac:** Slice 4 (API Gateway) - CartoAPI REST + perms ([#14](https://github.com/jaetill/carto/issues/14)) ([fcd0fa3](https://github.com/jaetill/carto/commit/fcd0fa3b04bf9c33f32d369e93876430b8cb9f46))
* **iac:** Slice 5 (Secrets + Log group) - Phase 6 complete on carto ([#15](https://github.com/jaetill/carto/issues/15)) ([0d6ba15](https://github.com/jaetill/carto/commit/0d6ba15657f0f05d55a32b722656fbeb78e0d24f))
* **observability:** Phase 5 - Sentry browser SDK + release tagging ([#4](https://github.com/jaetill/carto/issues/4)) ([6fc9afb](https://github.com/jaetill/carto/commit/6fc9afb1234cacb6d6e1b6caa20db94fc364a341))
* **observability:** wrap cartoApi Lambda with Sentry (Phase 5 complete for carto) ([#10](https://github.com/jaetill/carto/issues/10)) ([bddc39b](https://github.com/jaetill/carto/commit/bddc39b33c2f00e94935a00a9f4d87c89cb78752))
* **orchestration:** fleet-dispatch support + retire legacy triage-bot (ADR-0020) ([#18](https://github.com/jaetill/carto/issues/18)) ([efeaf44](https://github.com/jaetill/carto/commit/efeaf443138bb877eae438bc694edaaaa3ca502f))
* Phase 7 - user feedback widget + Lambda ([#16](https://github.com/jaetill/carto/issues/16)) ([3ee2ca8](https://github.com/jaetill/carto/commit/3ee2ca8ffa0a8117090ac8cd1cd23afdd320a889))
* Phase 7 - user feedback widget + Lambda ([#17](https://github.com/jaetill/carto/issues/17)) ([05023f7](https://github.com/jaetill/carto/commit/05023f76e7a2941c1a0fddcea2fc7ea27ff21634))


### Bug Fixes

* **build:** strip utf-8 bom from package.json (broke vite postcss config) ([#5](https://github.com/jaetill/carto/issues/5)) ([a44777b](https://github.com/jaetill/carto/commit/a44777b964ac6336c3152e94b06ba6275d2403de))
* **ci:** hoist NB comment out of if-block scalar (workflow was unparseable) ([#9](https://github.com/jaetill/carto/issues/9)) ([be14a29](https://github.com/jaetill/carto/commit/be14a297e96089ced650457caef7f3a1d77e1a6d))
* **deploy:** complete truncated deploy.yml ([#8](https://github.com/jaetill/carto/issues/8)) ([3ef0a87](https://github.com/jaetill/carto/commit/3ef0a8785e63fb7a2f5d5d84c34451294f58e24c))
* **docs:** repair mkdocs --strict build ([#7](https://github.com/jaetill/carto/issues/7)) ([3823a8e](https://github.com/jaetill/carto/commit/3823a8e007d901f1da5080f5e9a83be4c7823b4c))
* **implementer:** allow fleet-App dispatch; drop API-key fallback ([#21](https://github.com/jaetill/carto/issues/21)) ([2523ba9](https://github.com/jaetill/carto/commit/2523ba9737f559970ed7eac317b1f0c7fdad62d7))
