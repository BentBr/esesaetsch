# Changelog

## [0.3.0](https://github.com/BentBr/esesaetsch/compare/v0.2.0...v0.3.0) (2026-06-23)


### Features

* add dependabot config for cargo ([177d878](https://github.com/BentBr/esesaetsch/commit/177d87876a378d4289e8175a8fd51edb3004182e))
* add dependabot config for cargo and github actions ([a9c5210](https://github.com/BentBr/esesaetsch/commit/a9c5210979cb9d7561be732d2f04287ae810a182))
* **cli:** add completions and man subcommands ([7e15c4c](https://github.com/BentBr/esesaetsch/commit/7e15c4cc0f8b50f9abbe0c7fcd70248d0c6331b3))
* native installation packages ([bd8d84e](https://github.com/BentBr/esesaetsch/commit/bd8d84ebb70ec2b288e976dcfff937d9ec642932))
* **packaging:** add macOS pkg distribution, plist, and postinstall ([bec2081](https://github.com/BentBr/esesaetsch/commit/bec20813b941999fd8586b01ca6047ba9d6852bc))
* **packaging:** add nfpm config for deb/rpm/arch/apk ([666235c](https://github.com/BentBr/esesaetsch/commit/666235c7f357094e48305a9feb1fd4fd97d06a68))
* **packaging:** add systemd unit, default config, and maintainer scripts ([4996218](https://github.com/BentBr/esesaetsch/commit/49962189c34f2904b6e188651dfbc4f91bbb2a5b))
* **packaging:** add WiX source for the Windows msi ([ea209de](https://github.com/BentBr/esesaetsch/commit/ea209de588720ad36b705321f9edffdb302f731b))


### Bug Fixes

* drop musl_target, the musl download, the apk build, and the musl tarball ([608279e](https://github.com/BentBr/esesaetsch/commit/608279ecf20e44b4f88a1537b2ff70cdcb589fe7))
* **packaging:** build apk from musl binary and guard checksums on PRs ([ffb378c](https://github.com/BentBr/esesaetsch/commit/ffb378c3532687404b81943010dc7449b5d6c2bf))
* **packaging:** correct checksums self-inclusion, musl tarball name, macOS man gzip ([714cdfa](https://github.com/BentBr/esesaetsch/commit/714cdfa2caaadff11f7b6340e7cae42b03df2753))
* **packaging:** drop man-page assertion from smoke tests ([a3360f2](https://github.com/BentBr/esesaetsch/commit/a3360f28a481bb478b7fd0f030db7610d4966d4e))
* **packaging:** give nfpm a digit-leading version on PR builds ([b26d695](https://github.com/BentBr/esesaetsch/commit/b26d6958a2d08733406c1f20dc93dc9f1edd27bb))
* **packaging:** pass wxs to cargo-wix via --include ([e678d1c](https://github.com/BentBr/esesaetsch/commit/e678d1c9a3ad832a72e49bfe5a2891f406844a4d))
* **packaging:** set explicit 0644 mode on packaged content files ([25213a2](https://github.com/BentBr/esesaetsch/commit/25213a2a3c8c59974d9cf2c45e150aec576ad5ac))
* **packaging:** wire --version, fix wix encoding, strip v for nfpm, guard PR builds ([7d50156](https://github.com/BentBr/esesaetsch/commit/7d5015612cad2a37ef3894f1872119c24ff15ed8))

## [0.2.0](https://github.com/BentBr/esesaetsch/compare/v0.1.0...v0.2.0) (2026-05-14)


### Features

* adding host-key verification ([aa66e3d](https://github.com/BentBr/esesaetsch/commit/aa66e3dee2b83d872d0b044f7d8c08d49993e967))
* first iteration - setup ([58de9b6](https://github.com/BentBr/esesaetsch/commit/58de9b645222062449dea2a9122bb74c5ed1192e))
* implementation of crypto ([79a1a07](https://github.com/BentBr/esesaetsch/commit/79a1a07a65218ec40075c737e6dadf026eda5c03))
* logging for sessions ([24efb67](https://github.com/BentBr/esesaetsch/commit/24efb670142572b617c8499e4664461af27b6927))
* real integration of auth, pty and cli ([aa66fe1](https://github.com/BentBr/esesaetsch/commit/aa66fe1f1b0248ea3e9b0438490cc2608f509478))
* release-please fixes + pam for unix ([b0d330d](https://github.com/BentBr/esesaetsch/commit/b0d330d383e2afa2ae686140cc3b311e8b492820))
* updated russh + finished pub key auth ([116d845](https://github.com/BentBr/esesaetsch/commit/116d845195583123fad6c40d7a45add4d5ed6ec0))


### Bug Fixes

* making sure win uses correct constants ([6bff218](https://github.com/BentBr/esesaetsch/commit/6bff2182be964b0ae7849fb7eacf163915d0832a))

## Changelog

All notable changes are recorded here. This file is generated automatically by
[release-please](https://github.com/googleapis/release-please) from
[Conventional Commits](https://www.conventionalcommits.org/) on `main`.

<!-- release-please-changelog-stub -->
