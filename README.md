# jwt-authorizer

JWT authorizer Layer for Axum.

## Features

- JWT token verification (Bearer)
    - Algoritms: ECDSA, RSA, EdDSA, HS
- JWKS endpoint support
    - Configurable refresh
- Claims extraction
- Claims checker

## Usage

See documentation of the [`jwt-authorizer`](./jwt-authorizer/docs/README.md) module or the [`demo-server`](./demo-server/) example.

## Development 

### Key generation 

EC (ECDSA) - (algorigthm ES256 - ECDSA using SHA-256)

curve name: prime256v1 (secp256r1, secp384r1)

> openssl ecparam -genkey -noout -name prime256v1 | openssl pkcs8 -topk8 -nocrypt -out ec-private.pem

> openssl ec -in ec-private.pem -pubout -out ec-public-key.pem

EdDSA (Edwards-curve Digital Signature Algorithm)

(Ed25519 - implémentation spécifique de EdDSA, utilisant la Courbe d'Edwards tordue)

> openssl genpkey -algorithm ed25519

## Contributing

Contributions are wellcome!

## License

MIT