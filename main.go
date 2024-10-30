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
	privateKeyPEMBytes := pem.EncodeToMemory(privateKeyPEM)

	// Write private key to PEM file
	privateKeyPath := filepath.Join(*outDir, "private_key.pem")
	if err := os.WriteFile(privateKeyPath, privateKeyPEMBytes, 0600); err != nil {
		log.Fatalf("Failed to write private key: %v", err)
	}

	// Write base64 version of PEM to file
	base64Content := base64.StdEncoding.EncodeToString(privateKeyPEMBytes)
	base64Path := filepath.Join(*outDir, "private_key_base64.txt")
	if err := os.WriteFile(base64Path, []byte(base64Content), 0600); err != nil {
		log.Fatalf("Failed to write base64 file: %v", err)
	}

	// Create private key JWK
	privateJWK := JWK{
		Kty: "RSA",
		Kid: kid,
		N:   base64.RawURLEncoding.EncodeToString(privateKey.N.Bytes()),
		E:   base64.RawURLEncoding.EncodeToString([]byte{1, 0, 1}), // 65537 in base64
		Alg: "RS256",
		Use: "sig",
	}

	privateJWKSet := JWKSet{
		Keys: []JWK{privateJWK},
	}

	// Marshal private JWK to JSON
	privateJWKBytes, err := json.MarshalIndent(privateJWKSet, "", "  ")
	if err != nil {
		log.Fatalf("Failed to marshal private JWK: %v", err)
	}

	// Write private JWK to JSON file
	privateJWKPath := filepath.Join(*outDir, "private_key_jwks.json")
	if err := os.WriteFile(privateJWKPath, privateJWKBytes, 0644); err != nil {
		log.Fatalf("Failed to write private JWK: %v", err)
	}

	// Generate public key files
	publicKey := &privateKey.PublicKey

	// Convert public key to PEM format
	publicKeyDER, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		log.Fatalf("Failed to marshal public key: %v", err)
	}

	publicKeyPEM := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyDER,
	}
	publicKeyPEMBytes := pem.EncodeToMemory(publicKeyPEM)

	// Write public key to PEM file
	publicKeyPath := filepath.Join(*outDir, "public_key.pem")
	if err := os.WriteFile(publicKeyPath, publicKeyPEMBytes, 0644); err != nil {
		log.Fatalf("Failed to write public key: %v", err)
	}

	// Write base64 version of public key PEM to file
	publicKeyBase64 := base64.StdEncoding.EncodeToString(publicKeyPEMBytes)
	publicKeyBase64Path := filepath.Join(*outDir, "public_key_base64.txt")
	if err := os.WriteFile(publicKeyBase64Path, []byte(publicKeyBase64), 0644); err != nil {
		log.Fatalf("Failed to write public key base64 file: %v", err)
	}

	// Create public key JWK (same as private but different file)
	publicJWKSet := JWKSet{
		Keys: []JWK{privateJWK}, // We can use the same JWK as it only contains public components
	}

	// Marshal public JWK to JSON
	publicJWKBytes, err := json.MarshalIndent(publicJWKSet, "", "  ")
	if err != nil {
		log.Fatalf("Failed to marshal public JWK: %v", err)
	}

	// Write public JWK to JSON file
	publicJWKPath := filepath.Join(*outDir, "public_key_jwks.json")
	if err := os.WriteFile(publicJWKPath, publicJWKBytes, 0644); err != nil {
		log.Fatalf("Failed to write public JWK: %v", err)
	}

	fmt.Printf("Successfully generated files:\n")
	fmt.Printf("Private key (PEM): %s\n", privateKeyPath)
	fmt.Printf("Private key (Base64): %s\n", base64Path)
	fmt.Printf("Private JWK Set (JSON): %s\n", privateJWKPath)
	fmt.Printf("Public key (PEM): %s\n", publicKeyPath)
	fmt.Printf("Public key (Base64): %s\n", publicKeyBase64Path)
	fmt.Printf("Public JWK Set (JSON): %s\n", publicJWKPath)

	// Print base64 content to console
	fmt.Printf("\nPrivate key Base64 encoded PEM:\n%s\n", base64Content)
	fmt.Printf("\nPublic key Base64 encoded PEM:\n%s\n", publicKeyBase64)
}
