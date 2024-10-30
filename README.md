# OIDC Key Generator 🔑

A simple command-line tool to generate RSA key pairs and JWK (JSON Web Key) files for OIDC servers.

## Features ✨

- Generates RSA private keys (PEM format)
- Creates JWK Set file with public key information
- Exports base64 encoded version of the PEM file
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
2. `base64.txt`: Base64 encoded version of the PEM file
3. `jwks.json`: JWK Set in JSON format

The base64 encoded PEM is also printed to the console for easy copying.

## Options 🛠️

```bash
# Generate with custom key size
go run main.go -size 4096

# Use custom output directory
go run main.go -out /path/to/keys
```