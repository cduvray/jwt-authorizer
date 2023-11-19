# Key generation

## RSA

> openssl genrsa -out rsa-private2.pem 1024
> openssl rsa -in rsa-private2.pem -out rsa-public2.pem -pubout -outform PEM

## EC (ECDSA) - (algorigthm ES256 - ECDSA using SHA-256)

curve name: prime256v1 (secp256r1, secp384r1)

> openssl ecparam -genkey -noout -name prime256v1 | openssl pkcs8 -topk8 -nocrypt -out ec-private1.pem
> openssl ecparam -genkey -noout -name secp384r1 | openssl pkcs8 -topk8 -nocrypt -out ec384-private1.pem

> openssl ec -in ec-private1.pem -pubout -out ec-public1.pem
> openssl ec -in ec384-private1.pem -pubout -out ec384-public1.pem

## EdDSA - Edwards-curve Digital Signature Algorithm

(Ed25519 - EdDSA signature scheme using SHA-512 (SHA-2) and Curve25519)

> openssl genpkey -algorithm ed25519

## JWK - combined file of above keys

> rnbyc  -j -f rsa-public1.pem -k rsa01 -a RS256 -f ecdsa-public1.pem -k ec01 -a ES256  -f ed25519-public1.pem -k ed01 -a EdDSA -o public1.jw
