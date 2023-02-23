# Key generation

## RSA

> openssl genrsa -out rsa-private2.pem 1024
> openssl rsa -in rsa-private2.pem -out rsa-public2.pem -pubout -outform PEM

## EC (ECDSA) - (algorigthm ES256 - ECDSA using SHA-256)

curve name: prime256v1 (secp256r1, secp384r1)

> openssl ecparam -genkey -noout -name prime256v1 | openssl pkcs8 -topk8 -nocrypt -out ec-private.pem

> openssl ec -in ec-private.pem -pubout -out ec-public-key.pem

## EdDSA - Edwards-curve Digital Signature Algorithm

(Ed25519 - EdDSA signature scheme using SHA-512 (SHA-2) and Curve25519)

> openssl genpkey -algorithm ed25519
