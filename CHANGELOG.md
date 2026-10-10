# Changelog

## [0.3.0](https://github.com/Bredda/tavian/compare/v0.2.0...v0.3.0) (2026-10-10)


### Features

* **admin:** add the administration API with its own tokens and recorded changes ([#132](https://github.com/Bredda/tavian/issues/132)) ([0c16715](https://github.com/Bredda/tavian/commit/0c16715bf0c326b33f0a99887d618ee9f63e14e7))
* **admin:** expire, rotate and revoke admin tokens, and see their last use ([#138](https://github.com/Bredda/tavian/issues/138)) ([bd0c83d](https://github.com/Bredda/tavian/commit/bd0c83d08d0f15f714200a10807648960a5f8c2d))
* **admin:** give admin tokens a role: admin, operator or auditor ([#137](https://github.com/Bredda/tavian/issues/137)) ([cedd121](https://github.com/Bredda/tavian/commit/cedd1217975915ec1cce1b266b499d82d361e8c2))
* **admin:** list, compare, validate, apply and roll back configuration revisions ([#135](https://github.com/Bredda/tavian/issues/135)) ([415536d](https://github.com/Bredda/tavian/commit/415536df657ea5696a5b0c74fa1729afaac0e83e))
* **audit:** a read-only database role and an export of the chain for the auditor ([#139](https://github.com/Bredda/tavian/issues/139)) ([6b14011](https://github.com/Bredda/tavian/commit/6b140115d25d7fc4c6126a347ff91e0a323c8568))
* **config:** add tavian config, the command line of the admin API ([#136](https://github.com/Bredda/tavian/issues/136)) ([3b9397d](https://github.com/Bredda/tavian/commit/3b9397dd1683c250249f39247f4e547e1818bc6c))


### Documentation

* add a Bruno collection with the demo scenario and the API ([#122](https://github.com/Bredda/tavian/issues/122)) ([6c7c3d4](https://github.com/Bredda/tavian/commit/6c7c3d458b38431b6f8981787fb12e6d96fe81e8))
* require a DCO sign-off and fix the Go version policy ([#125](https://github.com/Bredda/tavian/issues/125)) ([f35c9c4](https://github.com/Bredda/tavian/commit/f35c9c4d87066af30a18d5ae5f630693c6aa728d))
* track the work in GitHub issues, milestones and a project ([#98](https://github.com/Bredda/tavian/issues/98)) ([d4a3e73](https://github.com/Bredda/tavian/commit/d4a3e7306416dc2b819ac2838c2623deef8cf991))

## [0.2.0](https://github.com/Bredda/tavian/compare/v0.1.0...v0.2.0) (2026-10-09)


### Features

* act on findings with block, redact, restrict_destinations and flag ([#20](https://github.com/Bredda/tavian/issues/20)) ([7760207](https://github.com/Bredda/tavian/commit/776020716f8efd070fe85b1265768b75663e6d08))
* add API key expiry and a clearance per key and group ([#11](https://github.com/Bredda/tavian/issues/11)) ([6229933](https://github.com/Bredda/tavian/commit/62299336ad5ec5d9ad3cec094bafd2cf071df758))
* add shadow mode and tavian policy test for policies ([#21](https://github.com/Bredda/tavian/issues/21)) ([10ff706](https://github.com/Bredda/tavian/commit/10ff7067c053e1c1d35ac8f524d77b83b8eb5aec))
* cap the number of requests handled at once ([#10](https://github.com/Bredda/tavian/issues/10)) ([264a0cd](https://github.com/Bredda/tavian/commit/264a0cdcbc84c4719081d9c762ae02c36d9ce900))
* chain and seal decision records, add tavian verify-audit ([#23](https://github.com/Bredda/tavian/issues/23)) ([a829de5](https://github.com/Bredda/tavian/commit/a829de560d2dd59d216b65ad244a3095805b3563))
* classify requests and enforce the caller's clearance ([#17](https://github.com/Bredda/tavian/issues/17)) ([78799ff](https://github.com/Bredda/tavian/commit/78799ff307950499491a6fece3cf9f8c0b05416c))
* detect PII, secrets and custom terms ([#15](https://github.com/Bredda/tavian/issues/15)) ([3695c82](https://github.com/Bredda/tavian/commit/3695c82ca2a8c8b9b64d84d5141e0ba64938041b))
* enforce quotas with reserve and settle ([#22](https://github.com/Bredda/tavian/issues/22)) ([63c4e00](https://github.com/Bredda/tavian/commit/63c4e00034a8fddbea14a09534bf6fb7ca346625))
* evaluate declarative policies with CEL ([#19](https://github.com/Bredda/tavian/issues/19)) ([3d979e3](https://github.com/Bredda/tavian/commit/3d979e3cbc4d06f1d716dbf682e4df99c7ca37e7))
* inspect request content and fail closed ([#14](https://github.com/Bredda/tavian/issues/14)) ([0a4b944](https://github.com/Bredda/tavian/commit/0a4b9443332237743d3b7e863e0d657e39aa9fb4))
* price requests, estimate energy and carbon, enforce monthly budgets ([#25](https://github.com/Bredda/tavian/issues/25)) ([46893bb](https://github.com/Bredda/tavian/commit/46893bb28fd26f8bf1a0f8452a7b3a2785da98e3))
* prune the outbox, sum usage by the hour, rebuild daily quotas ([#24](https://github.com/Bredda/tavian/issues/24)) ([9518452](https://github.com/Bredda/tavian/commit/9518452ecbc8c02abe8214594be3040e0788f9e8))
* record a decision for every authenticated chat request ([#16](https://github.com/Bredda/tavian/issues/16)) ([caf9802](https://github.com/Bredda/tavian/commit/caf98024c93e128f8966d727fa614314cd740ca9))
* route by classification and assert it after routing ([#18](https://github.com/Bredda/tavian/issues/18)) ([e4fc1bb](https://github.com/Bredda/tavian/commit/e4fc1bbcd9524049420adb0fb68c74803445bd60))


### Bug Fixes

* connect to PostgreSQL through the egress guard ([#9](https://github.com/Bredda/tavian/issues/9)) ([805ffc2](https://github.com/Bredda/tavian/commit/805ffc2eaaf8c03b2e9a7073a68d5e605d976585))


### Documentation

* align security docs and ADRs with the implementation ([#8](https://github.com/Bredda/tavian/issues/8)) ([6f2bea2](https://github.com/Bredda/tavian/commit/6f2bea206eaccf3195e5f3318296f4f15e869429))
* refresh README, architecture and security notes after M1 ([#12](https://github.com/Bredda/tavian/issues/12)) ([f63f75c](https://github.com/Bredda/tavian/commit/f63f75c05e3075c7d5cfc91e9c4db0f329837bad))

## 0.1.0 (2026-10-08)


### Features

* add M1 walking skeleton ([06ac025](https://github.com/Bredda/tavian/commit/06ac025c82e545dc73d2f332bf077eb64abe076e))
* authenticate with OIDC access tokens ([#7](https://github.com/Bredda/tavian/issues/7)) ([59b84c0](https://github.com/Bredda/tavian/commit/59b84c0f291e4816f59b4174dcab7b80a3082a06))
* record usage events in PostgreSQL through a transactional outbox ([#3](https://github.com/Bredda/tavian/issues/3)) ([19c8f89](https://github.com/Bredda/tavian/commit/19c8f89ddcea4a242262f6dd313774b0e4eb85a0))
* serve an embedded API reference at /docs ([#4](https://github.com/Bredda/tavian/issues/4)) ([8aea89f](https://github.com/Bredda/tavian/commit/8aea89f4d42a0bbe143de2fd2640b1ad21b23233))


### Bug Fixes

* return the client's model name in responses ([#6](https://github.com/Bredda/tavian/issues/6)) ([fc91579](https://github.com/Bredda/tavian/commit/fc915796030a8a0f6107593cfbe2f52790d8a5aa))
* start releases at 0.1.0 and pin full Go toolchain version ([#2](https://github.com/Bredda/tavian/issues/2)) ([3b6ac5f](https://github.com/Bredda/tavian/commit/3b6ac5f9098752433da6b1bb052a39bd1642f317))


### Documentation

* add design documents ([5863a25](https://github.com/Bredda/tavian/commit/5863a250e832c634314ef64cdfb75a8f9426da7d))
