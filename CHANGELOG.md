# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased

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
