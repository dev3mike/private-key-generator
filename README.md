# OIDC Key Generator 🔑

A simple command-line tool to generate RSA key pairs and JWK (JSON Web Key) files for OIDC servers.

## Features ✨

- Generates RSA private and public keys (PEM format)
- Creates JWK Set files with private and public key information
- Exports base64 encoded versions of the PEM files
- Secure key generation with minimum 2048-bit size
- Automatic key ID (kid) generation

## How to run it? 📦

```bash
go mod tidy
go run main.go
```

## Output Files 📄

The tool generates three files in the `keys` directory:

1. `private_key.pem`: Private key in PEM format
2. `private_key_base64.txt`: Base64 encoded version of the PEM file
3. `private_key_jwks.json`: JWK Set in JSON format
4. `public_key.pem`: Public key in PEM format
5. `public_key_base64.txt`: Base64 encoded version of the PEM file
6. `public_key_jwks.json`: JWK Set in JSON format

The base64 encoded PEM is also printed to the console for easy copying.

## Options 🛠️

```bash
# Generate with custom key size
go run main.go -size 4096

# Use custom output directory
go run main.go -out /path/to/keys
```