package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
)

const (
	defaultKeySize = 2048
	defaultOutDir  = "keys"
)

type JWK struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
	Alg string `json:"alg"`
	Use string `json:"use"`
}

type JWKSet struct {
	Keys []JWK `json:"keys"`
}

func generateKeyID(publicKey *rsa.PublicKey) (string, error) {
	publicKeyDER, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return "", err
	}

	hasher := sha1.New()
	hasher.Write(publicKeyDER)
	return base64.RawURLEncoding.EncodeToString(hasher.Sum(nil)), nil
}

func main() {
	// Parse command line flags
	keySize := flag.Int("size", defaultKeySize, "RSA key size in bits (2048 or 4096 recommended)")
	outDir := flag.String("out", defaultOutDir, "Output directory for the keys")
	flag.Parse()

	// Validate key size
	if *keySize < 2048 {
		log.Fatal("Key size must be at least 2048 bits for security reasons")
	}

	// Create output directory if it doesn't exist
	if err := os.MkdirAll(*outDir, 0700); err != nil {
		log.Fatalf("Failed to create output directory: %v", err)
	}

	// Generate private key
	privateKey, err := rsa.GenerateKey(rand.Reader, *keySize)
	if err != nil {
		log.Fatalf("Failed to generate private key: %v", err)
	}

	// Generate key ID
	kid, err := generateKeyID(&privateKey.PublicKey)
	if err != nil {
		log.Fatalf("Failed to generate key ID: %v", err)
	}

	// Convert private key to PEM format
	privateKeyPEM := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	}

	// Write private key to file
	privateKeyPath := filepath.Join(*outDir, "private_key.pem")
	privateKeyFile, err := os.OpenFile(privateKeyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		log.Fatalf("Failed to create private key file: %v", err)
	}
	defer privateKeyFile.Close()

	if err := pem.Encode(privateKeyFile, privateKeyPEM); err != nil {
		log.Fatalf("Failed to write private key: %v", err)
	}

	// Create JWK
	jwk := JWK{
		Kty: "RSA",
		Kid: kid,
		N:   base64.RawURLEncoding.EncodeToString(privateKey.N.Bytes()),
		E:   base64.RawURLEncoding.EncodeToString([]byte{1, 0, 1}), // 65537 in base64
		Alg: "RS256",
		Use: "sig",
	}

	jwkSet := JWKSet{
		Keys: []JWK{jwk},
	}

	// Write JWK to file
	jwkPath := filepath.Join(*outDir, "jwks.json")
	jwkFile, err := os.OpenFile(jwkPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		log.Fatalf("Failed to create JWK file: %v", err)
	}
	defer jwkFile.Close()

	encoder := json.NewEncoder(jwkFile)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(jwkSet); err != nil {
		log.Fatalf("Failed to write JWK: %v", err)
	}

	fmt.Printf("Successfully generated files:\n")
	fmt.Printf("Private key: %s\n", privateKeyPath)
	fmt.Printf("JWK Set: %s\n", jwkPath)
}
