// SPDX-License-Identifier: MIT

package device

import (
	"testing"
)

func TestMcElieceGenerateKeyPair(t *testing.T) {
	kp, err := McElieceGenerateKeyPair()
	if err != nil {
		t.Fatalf("McElieceGenerateKeyPair failed: %v", err)
	}

	// Check public key size
	pubKeyBytes, err := kp.PublicKey.MarshalBinary()
	if err != nil {
		t.Fatalf("Failed to marshal public key: %v", err)
	}
	if len(pubKeyBytes) != NoiseMcEliecePublicKeySize {
		t.Errorf("Expected public key size %d, got %d", NoiseMcEliecePublicKeySize, len(pubKeyBytes))
	}

	// Check private key size
	privKeyBytes, err := kp.PrivateKey.MarshalBinary()
	if err != nil {
		t.Fatalf("Failed to marshal private key: %v", err)
	}
	if len(privKeyBytes) != NoiseMcEliecePrivateKeySize {
		t.Errorf("Expected private key size %d, got %d", NoiseMcEliecePrivateKeySize, len(privKeyBytes))
	}
}

func TestMcElieceEncapsulateDecapsulate(t *testing.T) {
	kp, err := McElieceGenerateKeyPair()
	if err != nil {
		t.Fatalf("McElieceGenerateKeyPair failed: %v", err)
	}

	// Encapsulate
	sharedSecret1, ct, err := McElieceEncapsulate(kp.PublicKey)
	if err != nil {
		t.Fatalf("McElieceEncapsulate failed: %v", err)
	}

	// Check ciphertext size
	if len(ct) != NoiseMcElieceCiphertextSize {
		t.Errorf("Expected ciphertext size %d, got %d", NoiseMcElieceCiphertextSize, len(ct))
	}

	// Decapsulate
	sharedSecret2, err := McElieceDecapsulate(kp.PrivateKey, ct)
	if err != nil {
		t.Fatalf("McElieceDecapsulate failed: %v", err)
	}

	// Verify shared secrets match
	if sharedSecret1 != sharedSecret2 {
		t.Errorf("Shared secrets don't match after encapsulate/decapsulate")
	}
}

func TestMcElieceKeyID(t *testing.T) {
	kp, err := McElieceGenerateKeyPair()
	if err != nil {
		t.Fatalf("McElieceGenerateKeyPair failed: %v", err)
	}

	// Get key ID
	keyID := McElieceKeyID(kp.PublicKey)

	// Check key ID size
	if len(keyID) != NoisePQCKeyIDSize {
		t.Errorf("Expected key ID size %d, got %d", NoisePQCKeyIDSize, len(keyID))
	}

	// Key ID should be non-zero
	allZero := true
	for _, b := range keyID {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Error("Key ID should not be all zeros")
	}

	// Same public key should produce same key ID
	keyID2 := McElieceKeyID(kp.PublicKey)
	if keyID != keyID2 {
		t.Error("Same public key should produce same key ID")
	}
}

func TestMcElieceKeyIDFromBytes(t *testing.T) {
	kp, err := McElieceGenerateKeyPair()
	if err != nil {
		t.Fatalf("McElieceGenerateKeyPair failed: %v", err)
	}

	// Get key ID using key object
	keyID1 := McElieceKeyID(kp.PublicKey)

	// Get key ID using bytes
	pubKeyBytes, err := kp.PublicKey.MarshalBinary()
	if err != nil {
		t.Fatalf("Failed to marshal public key: %v", err)
	}
	keyID2 := McElieceKeyIDFromBytes(pubKeyBytes)

	// Should be the same
	if keyID1 != keyID2 {
		t.Error("McElieceKeyID and McElieceKeyIDFromBytes should produce same result")
	}
}

func TestMcEliecePublicKeyFromBytes(t *testing.T) {
	kp, err := McElieceGenerateKeyPair()
	if err != nil {
		t.Fatalf("McElieceGenerateKeyPair failed: %v", err)
	}

	// Marshal public key
	pubKeyBytes, err := kp.PublicKey.MarshalBinary()
	if err != nil {
		t.Fatalf("Failed to marshal public key: %v", err)
	}

	// Reconstruct public key from bytes
	pk2, err := McEliecePublicKeyFromBytes(pubKeyBytes)
	if err != nil {
		t.Fatalf("McEliecePublicKeyFromBytes failed: %v", err)
	}

	// Verify by comparing key IDs
	keyID1 := McElieceKeyID(kp.PublicKey)
	keyID2 := McElieceKeyID(pk2)
	if keyID1 != keyID2 {
		t.Error("Reconstructed public key has different key ID")
	}

	// Verify by encapsulating
	ss1, ct, err := McElieceEncapsulate(kp.PublicKey)
	if err != nil {
		t.Fatalf("McElieceEncapsulate with original key failed: %v", err)
	}

	ss2, err := McElieceDecapsulate(kp.PrivateKey, ct)
	if err != nil {
		t.Fatalf("McElieceDecapsulate failed: %v", err)
	}

	if ss1 != ss2 {
		t.Error("Original key encapsulation didn't work correctly")
	}
}

func TestMcEliecePrivateKeyFromBytes(t *testing.T) {
	kp, err := McElieceGenerateKeyPair()
	if err != nil {
		t.Fatalf("McElieceGenerateKeyPair failed: %v", err)
	}

	// Marshal private key
	privKeyBytes, err := kp.PrivateKey.MarshalBinary()
	if err != nil {
		t.Fatalf("Failed to marshal private key: %v", err)
	}

	// Reconstruct private key from bytes
	sk2, err := McEliecePrivateKeyFromBytes(privKeyBytes)
	if err != nil {
		t.Fatalf("McEliecePrivateKeyFromBytes failed: %v", err)
	}

	// Encapsulate with original public key
	ss1, ct, err := McElieceEncapsulate(kp.PublicKey)
	if err != nil {
		t.Fatalf("McElieceEncapsulate failed: %v", err)
	}

	// Decapsulate with reconstructed private key
	ss2, err := McElieceDecapsulate(sk2, ct)
	if err != nil {
		t.Fatalf("McElieceDecapsulate with reconstructed key failed: %v", err)
	}

	if ss1 != ss2 {
		t.Error("Reconstructed private key produced different shared secret")
	}
}

func TestKyberGenerateKeyPair(t *testing.T) {
	kp, err := KyberGenerateKeyPair()
	if err != nil {
		t.Fatalf("KyberGenerateKeyPair failed: %v", err)
	}

	// Check public key size
	pubKeyBytes, err := kp.PublicKey.MarshalBinary()
	if err != nil {
		t.Fatalf("Failed to marshal public key: %v", err)
	}
	if len(pubKeyBytes) != NoiseKyberPublicKeySize {
		t.Errorf("Expected public key size %d, got %d", NoiseKyberPublicKeySize, len(pubKeyBytes))
	}

	// Check private key size
	privKeyBytes, err := kp.PrivateKey.MarshalBinary()
	if err != nil {
		t.Fatalf("Failed to marshal private key: %v", err)
	}
	if len(privKeyBytes) != NoiseKyberPrivateKeySize {
		t.Errorf("Expected private key size %d, got %d", NoiseKyberPrivateKeySize, len(privKeyBytes))
	}
}

func TestKyberEncapsulateDecapsulate(t *testing.T) {
	kp, err := KyberGenerateKeyPair()
	if err != nil {
		t.Fatalf("KyberGenerateKeyPair failed: %v", err)
	}

	// Encapsulate
	sharedSecret1, ct, err := KyberEncapsulate(kp.PublicKey)
	if err != nil {
		t.Fatalf("KyberEncapsulate failed: %v", err)
	}

	// Check ciphertext size
	if len(ct) != NoiseKyberCiphertextSize {
		t.Errorf("Expected ciphertext size %d, got %d", NoiseKyberCiphertextSize, len(ct))
	}

	// Decapsulate
	sharedSecret2, err := KyberDecapsulate(kp.PrivateKey, ct)
	if err != nil {
		t.Fatalf("KyberDecapsulate failed: %v", err)
	}

	// Verify shared secrets match
	if sharedSecret1 != sharedSecret2 {
		t.Errorf("Shared secrets don't match after encapsulate/decapsulate")
	}
}

func TestKyberPublicKeyFromBytes(t *testing.T) {
	kp, err := KyberGenerateKeyPair()
	if err != nil {
		t.Fatalf("KyberGenerateKeyPair failed: %v", err)
	}

	// Marshal public key
	pubKeyBytes, err := kp.PublicKey.MarshalBinary()
	if err != nil {
		t.Fatalf("Failed to marshal public key: %v", err)
	}

	// Reconstruct public key from bytes
	pk2, err := KyberPublicKeyFromBytes(pubKeyBytes)
	if err != nil {
		t.Fatalf("KyberPublicKeyFromBytes failed: %v", err)
	}

	// Encapsulate with reconstructed key
	ss1, ct, err := KyberEncapsulate(pk2)
	if err != nil {
		t.Fatalf("KyberEncapsulate with reconstructed key failed: %v", err)
	}

	// Decapsulate with original private key
	ss2, err := KyberDecapsulate(kp.PrivateKey, ct)
	if err != nil {
		t.Fatalf("KyberDecapsulate failed: %v", err)
	}

	if ss1 != ss2 {
		t.Error("Reconstructed public key encapsulation didn't work correctly")
	}
}

func TestKyberPrivateKeyFromBytes(t *testing.T) {
	kp, err := KyberGenerateKeyPair()
	if err != nil {
		t.Fatalf("KyberGenerateKeyPair failed: %v", err)
	}

	// Marshal private key
	privKeyBytes, err := kp.PrivateKey.MarshalBinary()
	if err != nil {
		t.Fatalf("Failed to marshal private key: %v", err)
	}

	// Reconstruct private key from bytes
	sk2, err := KyberPrivateKeyFromBytes(privKeyBytes)
	if err != nil {
		t.Fatalf("KyberPrivateKeyFromBytes failed: %v", err)
	}

	// Encapsulate with original public key
	ss1, ct, err := KyberEncapsulate(kp.PublicKey)
	if err != nil {
		t.Fatalf("KyberEncapsulate failed: %v", err)
	}

	// Decapsulate with reconstructed private key
	ss2, err := KyberDecapsulate(sk2, ct)
	if err != nil {
		t.Fatalf("KyberDecapsulate with reconstructed key failed: %v", err)
	}

	if ss1 != ss2 {
		t.Error("Reconstructed private key produced different shared secret")
	}
}

func TestGeneratePQCStaticKeypair(t *testing.T) {
	publicKey, privateKey, err := GeneratePQCStaticKeypair()
	if err != nil {
		t.Fatalf("GeneratePQCStaticKeypair failed: %v", err)
	}

	// Check public key size
	if len(publicKey) != NoiseMcEliecePublicKeySize {
		t.Errorf("Expected public key size %d, got %d", NoiseMcEliecePublicKeySize, len(publicKey))
	}

	// Check private key size
	if len(privateKey) != NoiseMcEliecePrivateKeySize {
		t.Errorf("Expected private key size %d, got %d", NoiseMcEliecePrivateKeySize, len(privateKey))
	}

	t.Logf("Generated PQC keypair:")
	t.Logf("  Public key: %d bytes", len(publicKey))
	t.Logf("  Private key: %d bytes", len(privateKey))
}

func TestGenerateKyberEphemeralKeypair(t *testing.T) {
	pk, skBytes, err := GenerateKyberEphemeralKeypair()
	if err != nil {
		t.Fatalf("GenerateKyberEphemeralKeypair failed: %v", err)
	}

	// Check public key size
	if len(pk) != NoiseKyberPublicKeySize {
		t.Errorf("Expected public key size %d, got %d", NoiseKyberPublicKeySize, len(pk))
	}

	// Check private key size
	if len(skBytes) != NoiseKyberPrivateKeySize {
		t.Errorf("Expected private key size %d, got %d", NoiseKyberPrivateKeySize, len(skBytes))
	}

	// Reconstruct keys and verify they work
	pk2, err := KyberPublicKeyFromBytes(pk[:])
	if err != nil {
		t.Fatalf("KyberPublicKeyFromBytes failed: %v", err)
	}

	sk2, err := KyberPrivateKeyFromBytes(skBytes)
	if err != nil {
		t.Fatalf("KyberPrivateKeyFromBytes failed: %v", err)
	}

	// Test encapsulate/decapsulate
	ss1, ct, err := KyberEncapsulate(pk2)
	if err != nil {
		t.Fatalf("KyberEncapsulate failed: %v", err)
	}

	ss2, err := KyberDecapsulate(sk2, ct)
	if err != nil {
		t.Fatalf("KyberDecapsulate failed: %v", err)
	}

	if ss1 != ss2 {
		t.Error("Ephemeral keypair encapsulate/decapsulate failed")
	}
}

func TestKyberPublicKeyToBytes(t *testing.T) {
	kp, err := KyberGenerateKeyPair()
	if err != nil {
		t.Fatalf("KyberGenerateKeyPair failed: %v", err)
	}

	pkBytes, err := KyberPublicKeyToBytes(kp.PublicKey)
	if err != nil {
		t.Fatalf("KyberPublicKeyToBytes failed: %v", err)
	}

	if len(pkBytes) != NoiseKyberPublicKeySize {
		t.Errorf("Expected %d bytes, got %d", NoiseKyberPublicKeySize, len(pkBytes))
	}

	// Verify the bytes are correct by reconstructing
	pk2, err := KyberPublicKeyFromBytes(pkBytes[:])
	if err != nil {
		t.Fatalf("KyberPublicKeyFromBytes failed: %v", err)
	}

	// Encapsulate and verify decapsulation works
	ss1, ct, err := KyberEncapsulate(pk2)
	if err != nil {
		t.Fatalf("KyberEncapsulate failed: %v", err)
	}

	ss2, err := KyberDecapsulate(kp.PrivateKey, ct)
	if err != nil {
		t.Fatalf("KyberDecapsulate failed: %v", err)
	}

	if ss1 != ss2 {
		t.Error("Encapsulate with reconstructed key didn't produce matching secret")
	}
}
