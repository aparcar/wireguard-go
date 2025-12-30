// SPDX-License-Identifier: MIT

package device

import (
	"encoding/hex"
	"testing"
)

func TestGeneratePQCKeypair(t *testing.T) {
	seedHex, publicKeyHex, err := GeneratePQCKeypair()
	if err != nil {
		t.Fatalf("GeneratePQCKeypair failed: %v", err)
	}

	// Check seed length (64 bytes = 128 hex chars)
	if len(seedHex) != 128 {
		t.Errorf("Expected seed hex length 128, got %d", len(seedHex))
	}

	// Check public key length (1184 bytes = 2368 hex chars)
	if len(publicKeyHex) != 2368 {
		t.Errorf("Expected public key hex length 2368, got %d", len(publicKeyHex))
	}

	// Verify seed is valid hex
	_, err = hex.DecodeString(seedHex)
	if err != nil {
		t.Errorf("Seed is not valid hex: %v", err)
	}

	// Verify public key is valid hex
	_, err = hex.DecodeString(publicKeyHex)
	if err != nil {
		t.Errorf("Public key is not valid hex: %v", err)
	}
}

func TestPQCGenerateKeyPairFromSeed(t *testing.T) {
	// Generate a seed
	var seed NoisePQCSeed
	for i := range seed {
		seed[i] = byte(i)
	}

	// Generate key pair from seed
	publicKey, privateKey, err := PQCGenerateKeyPairFromSeed(seed)
	if err != nil {
		t.Fatalf("PQCGenerateKeyPairFromSeed failed: %v", err)
	}

	// Check public key length
	if len(publicKey) != NoisePQCPublicKeySize {
		t.Errorf("Expected public key size %d, got %d", NoisePQCPublicKeySize, len(publicKey))
	}

	// Private key is a DecapsulationKey, just check it's not nil
	if privateKey == nil {
		t.Errorf("Private key should not be nil")
	}

	// Generate again from same seed - should produce same keys
	publicKey2, privateKey2, err := PQCGenerateKeyPairFromSeed(seed)
	if err != nil {
		t.Fatalf("PQCGenerateKeyPairFromSeed second call failed: %v", err)
	}

	if publicKey != publicKey2 {
		t.Errorf("Same seed produced different public keys")
	}
	if privateKey2 == nil {
		t.Errorf("Second private key should not be nil")
	}
}

func TestPQCEncapsulateDecapsulate(t *testing.T) {
	// Generate a keypair
	publicKey, privateKey, err := PQCGenerateKeyPair()
	if err != nil {
		t.Fatalf("PQCGenerateKeyPair failed: %v", err)
	}

	// Convert private key to seed format
	var privateSeed NoisePQCSeed
	copy(privateSeed[:], privateKey[:NoisePQCSeedSize])

	// Encapsulate
	sharedSecret1, ciphertext, err := PQCEncapsulate(publicKey)
	if err != nil {
		t.Fatalf("PQCEncapsulate failed: %v", err)
	}

	// Check ciphertext size
	if len(ciphertext) != NoisePQCCiphertextSize {
		t.Errorf("Expected ciphertext size %d, got %d", NoisePQCCiphertextSize, len(ciphertext))
	}

	// Check shared secret size
	if len(sharedSecret1) != NoisePQCSharedSecretSize {
		t.Errorf("Expected shared secret size %d, got %d", NoisePQCSharedSecretSize, len(sharedSecret1))
	}

	// Decapsulate
	sharedSecret2, err := PQCDecapsulate(privateSeed, ciphertext)
	if err != nil {
		t.Fatalf("PQCDecapsulate failed: %v", err)
	}

	// Verify shared secrets match
	if sharedSecret1 != sharedSecret2 {
		t.Errorf("Shared secrets don't match after encapsulate/decapsulate")
	}
}

func TestNoisePQCPublicKeyHexConversion(t *testing.T) {
	// Generate a public key
	publicKey, _, err := PQCGenerateKeyPair()
	if err != nil {
		t.Fatalf("PQCGenerateKeyPair failed: %v", err)
	}

	// Convert to hex using hex.EncodeToString
	hexStr := hex.EncodeToString(publicKey[:])
	if len(hexStr) != 2368 {
		t.Errorf("Expected hex length 2368, got %d", len(hexStr))
	}

	// Convert back from hex
	var publicKey2 NoisePQCPublicKey
	err = publicKey2.FromHex(hexStr)
	if err != nil {
		t.Fatalf("FromHex failed: %v", err)
	}

	// Verify they match
	if publicKey != publicKey2 {
		t.Errorf("Public key doesn't match after hex conversion")
	}
}

func TestNoisePQCPublicKeyIsZero(t *testing.T) {
	var zeroKey NoisePQCPublicKey
	if !zeroKey.IsZero() {
		t.Errorf("Zero key should return true for IsZero()")
	}

	publicKey, _, err := PQCGenerateKeyPair()
	if err != nil {
		t.Fatalf("PQCGenerateKeyPair failed: %v", err)
	}

	if publicKey.IsZero() {
		t.Errorf("Generated key should not return true for IsZero()")
	}
}
