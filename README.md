# jwt-authorizer

JWT authorizer Layer for Axum and Tonic.

[![Build status](https://github.com/cduvray/jwt-authorizer/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/tokio-rs/cduvray/jwt-authorizer/workflows/ci.yml)
[![Crates.io](https://img.shields.io/crates/v/jwt-authorizer)](https://crates.io/crates/jwt-authorizer)
[![Documentation](https://docs.rs/jwt-authorizer/badge.svg)](https://docs.rs/jwt-authorizer)

## Features

- JWT token verification (Bearer)
    - Algoritms: ECDSA, RSA, EdDSA, HMAC
- JWKS endpoint support
    - Configurable refresh
    - OpenId Connect Discovery
- Validation
    - exp, nbf, iss, aud
- Claims extraction
- Claims checker
- Tracing support (error logging)

## Usage

See documentation of the [`jwt-authorizer`](./jwt-authorizer/docs/README.md) module or the [`demo-server`](./demo-server/) example.

## Development

Minimum supported Rust version is 1.65.

## Contributing

Contributions are wellcome!

## License

MIT
