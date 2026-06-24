# Changelog

## [1.1.2](https://github.com/jaetill/carto/compare/v1.1.1...v1.1.2) (2026-06-24)


### Bug Fixes

* **ci:** add npm dependency scanning for root and lambda packages (closes [#83](https://github.com/jaetill/carto/issues/83)) ([#92](https://github.com/jaetill/carto/issues/92)) ([a128b6c](https://github.com/jaetill/carto/commit/a128b6cec4cef98de3b1db1e87b178d00cdc81b9))
* **ci:** drop unused IMPLEMENTER_PAT forwarding from implementer caller (refs [#363](https://github.com/jaetill/carto/issues/363)) ([#107](https://github.com/jaetill/carto/issues/107)) ([57f5421](https://github.com/jaetill/carto/commit/57f5421d46e471c86bfcabfc16a5854686733c14))
* **ci:** pin reusable workflow refs to immutable SHAs (closes [#45](https://github.com/jaetill/carto/issues/45)) ([#80](https://github.com/jaetill/carto/issues/80)) ([259b49d](https://github.com/jaetill/carto/commit/259b49d9d77b0a892bb2bf614d39a58e2026a1db))
* **config:** set DEBUG_MODE=false so production builds use real data ([#106](https://github.com/jaetill/carto/issues/106)) ([08996af](https://github.com/jaetill/carto/commit/08996afaeb02643a4df06dd82c4fc6930b738c12)), closes [#105](https://github.com/jaetill/carto/issues/105)
* **deps:** enable Dependabot npm scanning for root and Lambda packages ([#91](https://github.com/jaetill/carto/issues/91)) ([5dea711](https://github.com/jaetill/carto/commit/5dea71149578348be224a46aafffae3825039821)), closes [#81](https://github.com/jaetill/carto/issues/81)

## [1.1.1](https://github.com/jaetill/carto/compare/v1.1.0...v1.1.1) (2026-06-21)


### Bug Fixes

* **ci:** pin iac-guard reusable ref to immutable SHA (ADR-0048) ([#75](https://github.com/jaetill/carto/issues/75)) ([3c4d9ad](https://github.com/jaetill/carto/commit/3c4d9ad8a9a092a8e74003bd8f5f4f030ef640b9)), closes [#49](https://github.com/jaetill/carto/issues/49)
* **iac:** expose iac_guard_role_arn output so AWS_IAC_GUARD_ROLE_ARN is auditable ([#50](https://github.com/jaetill/carto/issues/50)) ([#76](https://github.com/jaetill/carto/issues/76)) ([f3a13b2](https://github.com/jaetill/carto/commit/f3a13b249f9b02abc8df8c1d37585f15d5bc77a5))
* **iam:** restore branch-level enforcement to OIDC trust via ref condition ([#78](https://github.com/jaetill/carto/issues/78)) ([bcb13a4](https://github.com/jaetill/carto/commit/bcb13a42b44f61e64a6a1fb319eca722cf3d5b6a)), closes [#30](https://github.com/jaetill/carto/issues/30)

## [1.1.0](https://github.com/jaetill/carto/compare/v1.0.0...v1.1.0) (2026-06-18)


### Features

* **iac:** add ADR-0035 iac-additive-guard caller ([#280](https://github.com/jaetill/carto/issues/280)) ([#47](https://github.com/jaetill/carto/issues/47)) ([bedfbd6](https://github.com/jaetill/carto/commit/bedfbd690b5233920b431ec625ddf3f27a40e532))
* **iam:** grant Lambda alias permissions to carto-github-deploy (ADR-0043 phase 2) ([#35](https://github.com/jaetill/carto/issues/35)) ([e11a2c9](https://github.com/jaetill/carto/commit/e11a2c904e58224329c2808f9e431b049052b16d))


### Bug Fixes

* **ci:** scope reusable secrets explicitly (ADR-0048) ([#74](https://github.com/jaetill/carto/issues/74)) ([a395e64](https://github.com/jaetill/carto/commit/a395e6469be29ca286a3fe42f6eaa14af3e24d91))
* **config:** export API_BASE so feedback.js import resolves at build time ([#36](https://github.com/jaetill/carto/issues/36)) ([f49e749](https://github.com/jaetill/carto/commit/f49e749987fc159dac51c36922c8ee0f11357430)), closes [#27](https://github.com/jaetill/carto/issues/27)
* **iac:** gate carto-iac-drift on iac-plan environment, not pull_request sub ([#52](https://github.com/jaetill/carto/issues/52)) ([#57](https://github.com/jaetill/carto/issues/57)) ([90bcd10](https://github.com/jaetill/carto/commit/90bcd101ee4e94e89fa44b154c324b6e45f62f7c))
* **iac:** replace ReadOnlyAccess with scoped plan policy on iac-drift role ([#53](https://github.com/jaetill/carto/issues/53)) ([#68](https://github.com/jaetill/carto/issues/68)) ([2b758a7](https://github.com/jaetill/carto/commit/2b758a74f754375bc037d773481d70237706c317))
* **iac:** scope APIGatewayRead to carto REST API, not wildcard ([#71](https://github.com/jaetill/carto/issues/71)) ([#72](https://github.com/jaetill/carto/issues/72)) ([71c2c16](https://github.com/jaetill/carto/commit/71c2c1620177c763059c085564c42deb4adf9412))
* **iac:** scope IAMRead to carto role ARNs, not wildcard ([#70](https://github.com/jaetill/carto/issues/70)) ([#73](https://github.com/jaetill/carto/issues/73)) ([89c414c](https://github.com/jaetill/carto/commit/89c414ca45c7612ebe247af8d2c2cec97b081b70))
* **iam:** accept environment-scoped OIDC sub for gated prod deploys (ADR-0043) ([#28](https://github.com/jaetill/carto/issues/28)) ([9882b92](https://github.com/jaetill/carto/commit/9882b92bf7a708608a67e6b83e4155174dd0bf87))
* **lambda:** route POST /feedback to feedbackHandler, bypassing group check ([#38](https://github.com/jaetill/carto/issues/38)) ([#39](https://github.com/jaetill/carto/issues/39)) ([67acb62](https://github.com/jaetill/carto/commit/67acb62d57eaa83a8e7bcee23df8ba4b79a67244))
* **lambda:** suppress raw exception messages from 500 responses ([#62](https://github.com/jaetill/carto/issues/62)) ([b6acb75](https://github.com/jaetill/carto/commit/b6acb75119ad8fe7e9b68726783f3bb8daab8d3e)), closes [#59](https://github.com/jaetill/carto/issues/59)

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
