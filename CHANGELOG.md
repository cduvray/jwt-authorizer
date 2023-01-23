# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased

### Changed

- JwtAuthorizer creation simplified:

   - JwtAuthorizer::from_* creates an instance, new() is not necessary anymore

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