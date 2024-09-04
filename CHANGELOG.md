# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased

## 0.15.0 (2024-08-26)

- tonic support is back
- CI refactoring
  - MSRV is bumped to 75
- minor dependencies updates (commit: d87b7ef90912759b0ad608bfcb7b021bb9c14e14)

## 0.14.0 (2024-01-22)

- update to axum 0.7
  - tower-http 0.5, header 0.4, http 1.0
- jsonwebtoken 9.2
- tonic support removed temporarily (waiting for tonic migration to axum 0.7)

## 0.13.0 (2023-11-20)

- added support for custom http client in jwks discovery (fixes #41)
- `algs` added to configurable validation options
- missing alg in JWK no longer defaults to RS256 but to all algs of the same alg familly
- jsonwebtoken updated (8.3.0 -> 9.1.0)
- make RegisteredClaims serializable (fixes #38)

## 0.12.0 (2023-10-14)

- internal refactoring (no public breaking changes)
- claim checker allowing closures (#32)
- jwks from file or text (#37)

## 0.11.0 (2023-09-06)

- support for multiple authorizers
  - JwtAuthorizer::layer() deprecated in favor of JwtAuthorizer::build() and IntoLayer::into_layer()
- better optional claims extraction (commit: 940acb17a1de82788bc72c3657da87609ce741e9)
  - error 401 rather than INTERNAL_SERVER_ERROR, when no claims exist (no authorizer layer)
  - do not log error

## 0.10.1 (2023-07-11)

### Fixed

- (RegisteredClaims) audience claim, should be a string o an array of strings

### Added

- (NumericDate) optional feature enables `time` dep as an alternative to `chrono`

## 0.10.0 (2023-05-19)

- tonic services support
- choices of TLS support (corresponding to underlying reqwest crate features)
- `RegisteredClaims` added (representing RFC7519 registered claims), used as default for `JwtAuthorizer`

## 0.9.0 (2023-04-14)

### Added

- Other sources for jwt token are configurable (#10)
  - Cookie
  - AuthorizationHeader (default)
- Raw PEM file content as an input for JwtAuthorizer (#15)

### Changed

- Remove 'static lifetime requirement (#8)

## 0.8.1 (2023-03-16)

No public API changes, no new features.

### Changed

- KeyStore, KeySource refactor for better performance and security

### Fixed

- Allow non root OIDC issuer (issue #1)

## 0.8.0 (2023-02-28)

### Added

- validation configuration (exp, nbf, aud, iss, disable_validation)
- more integration tests added

### Fixed

- `JwtAuthorizer.from_ec()`, `JwtAuthorizer.from_ed()` imported PEM as DER resulting in failed validations

## 0.7.0 (2023-02-14)

### Changed

- Refresh configuration - simplification,  minimal_refresh_interval removed (replaced by refresh_interval in KeyNotFound refresh strategy)

### Added

- integration tests, unit tests

## 0.6.0 (2023-02-05)

### Added

- JwtAuthorizer::from_oidc(issuer_uri) - building from oidc discovery page

### Changed

- JwtAuthorizer::layer() becomes async

### Minor Changes

- demo-server refactoring

## 0.5.0 - (2023-1-28)

### Changed

- JwtAuthorizer creation simplified:
   - JwtAuthorizer::from_* creates an instance, new() is not necessary anymore
- with_check() renamed to check()

### Added

- jwks store refresh configuration

### Fixed

- claims extractor (JwtClaims) without authorizer should not panic, should send a 500 error

## 0.4.0 - (2023-1-21)

### Added

- claims checker (stabilisation, tests, documentation)

### Fixed

- added missing WWW-Authenticate header to errors

## 0.3.2 - (2023-1-18)

### Fixed

- fix: when jwks store endpoint is unavailable response should be an error 500 (not 403)

## 0.3.1 - (2023-1-14)

### Fixed

- fix: panicking when a bearer token is missing in protected request (be6bf9fb)

## 0.3.0 - (2023-1-13)

### Added

- building the authorizer layer from rsa, ec, ed PEM files and from secret phrase (9bd99b2a)

## 0.2.0 - (2023-1-10)

Initial release
