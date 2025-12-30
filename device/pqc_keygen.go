// SPDX-License-Identifier: MIT

package device

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
)

// GeneratePQCKeypair generates a new ML-KEM-768 keypair from a random seed.
// Returns the seed (64 bytes) and public key (1184 bytes) as hex strings.
func GeneratePQCKeypair() (seedHex, publicKeyHex string, err error) { // TODO aparcar use bytes
	// Generate random seed (64 bytes for ML-KEM-768)
	var seed NoisePQCSeed
	if _, err := io.ReadFull(rand.Reader, seed[:]); err != nil {
		return "", "", fmt.Errorf("failed to generate random seed: %w", err)
	}

	// Derive public key from seed
	publicKey, err := PQCPublicKeyFromSeed(seed)
	if err != nil {
		return "", "", fmt.Errorf("failed to derive public key: %w", err)
	}

	seedHex = hex.EncodeToString(seed[:])
	publicKeyHex = hex.EncodeToString(publicKey[:])

	return seedHex, publicKeyHex, nil
}

// PQCPublicKeyFromSeed derives a PQC public key from a seed.
// This uses the same derivation as the device would use.
func PQCPublicKeyFromSeed(seed NoisePQCSeed) (NoisePQCPublicKey, error) {
	// Use the existing PQCGenerateKeyPairFromSeed function
	publicKey, _, err := PQCGenerateKeyPairFromSeed(seed)
	if err != nil {
		return NoisePQCPublicKey{}, err
	}
	return publicKey, nil
}

// ParsePQCSeedHex parses a hex-encoded PQC seed string.
func ParsePQCSeedHex(hexStr string) (NoisePQCSeed, error) {
	var seed NoisePQCSeed
	if err := seed.FromHex(hexStr); err != nil {
		return NoisePQCSeed{}, fmt.Errorf("failed to parse seed: %w", err)
	}
	return seed, nil
}

// ParsePQCPublicKeyHex parses a hex-encoded PQC public key string.
func ParsePQCPublicKeyHex(hexStr string) (NoisePQCPublicKey, error) {
	var pubKey NoisePQCPublicKey
	if err := pubKey.FromHex(hexStr); err != nil {
		return NoisePQCPublicKey{}, fmt.Errorf("failed to parse public key: %w", err)
	}
	return pubKey, nil
}
