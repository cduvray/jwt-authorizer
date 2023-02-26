# jwt-authorizer

JWT authorizer Layer for Axum.

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
