/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"crypto/mlkem"
	"errors"

	"golang.org/x/crypto/blake2s"
)

// PQCGenerateKeyPair generates a new ML-KEM-768 keypair.
// Returns the public key (encapsulation key) and seed for the private key.
func PQCGenerateKeyPair() (NoisePQCPublicKey, NoisePQCSeed, error) {
	var pubKey NoisePQCPublicKey
	var seed NoisePQCSeed

	dk, err := mlkem.GenerateKey768()
	if err != nil {
		return pubKey, seed, err
	}

	// Get the encapsulation (public) key
	ek := dk.EncapsulationKey()
	ekBytes := ek.Bytes()
	if len(ekBytes) != NoisePQCPublicKeySize {
		return pubKey, seed, errors.New("unexpected encapsulation key size")
	}
	copy(pubKey[:], ekBytes)

	// Get the seed (decapsulation key bytes)
	seedBytes := dk.Bytes()
	if len(seedBytes) != NoisePQCSeedSize {
		return pubKey, seed, errors.New("unexpected seed size")
	}
	copy(seed[:], seedBytes)

	return pubKey, seed, nil
}

// PQCGenerateKeyPairFromSeed generates a deterministic ML-KEM-768 keypair from a seed.
// The seed must be exactly NoisePQCSeedSize bytes.
func PQCGenerateKeyPairFromSeed(seed NoisePQCSeed) (NoisePQCPublicKey, *mlkem.DecapsulationKey768, error) {
	var pubKey NoisePQCPublicKey

	dk, err := mlkem.NewDecapsulationKey768(seed[:])
	if err != nil {
		return pubKey, nil, err
	}

	// Get the encapsulation (public) key
	ek := dk.EncapsulationKey()
	ekBytes := ek.Bytes()
	if len(ekBytes) != NoisePQCPublicKeySize {
		return pubKey, nil, errors.New("unexpected encapsulation key size")
	}
	copy(pubKey[:], ekBytes)

	return pubKey, dk, nil
}

// PQCEncapsulate performs ML-KEM-768 encapsulation using the peer's public key.
// Returns the shared secret and ciphertext.
// The ciphertext should be sent to the peer who can decapsulate it with their private key.
func PQCEncapsulate(peerPublicKey NoisePQCPublicKey) (NoisePQCSharedSecret, NoisePQCCiphertext, error) {
	var sharedSecret NoisePQCSharedSecret
	var ciphertext NoisePQCCiphertext

	// Create encapsulation key from peer's public key bytes
	ek, err := mlkem.NewEncapsulationKey768(peerPublicKey[:])
	if err != nil {
		return sharedSecret, ciphertext, err
	}

	// Encapsulate to get shared secret and ciphertext
	ssBytes, ctBytes := ek.Encapsulate()

	if len(ssBytes) != NoisePQCSharedSecretSize {
		return sharedSecret, ciphertext, errors.New("unexpected shared secret size")
	}
	copy(sharedSecret[:], ssBytes)

	if len(ctBytes) != NoisePQCCiphertextSize {
		return sharedSecret, ciphertext, errors.New("unexpected ciphertext size")
	}
	copy(ciphertext[:], ctBytes)

	return sharedSecret, ciphertext, nil
}

// PQCDecapsulate performs ML-KEM-768 decapsulation using our seed.
// Returns the shared secret derived from the ciphertext.
// This recovers the same shared secret that was generated during encapsulation.
func PQCDecapsulate(seed NoisePQCSeed, ciphertext NoisePQCCiphertext) (NoisePQCSharedSecret, error) {
	var sharedSecret NoisePQCSharedSecret

	// Create decapsulation key from seed
	dk, err := mlkem.NewDecapsulationKey768(seed[:])
	if err != nil {
		return sharedSecret, err
	}

	// Decapsulate to recover the shared secret
	ssBytes, err := dk.Decapsulate(ciphertext[:])
	if err != nil {
		return sharedSecret, err
	}

	if len(ssBytes) != NoisePQCSharedSecretSize {
		return sharedSecret, errors.New("unexpected shared secret size")
	}
	copy(sharedSecret[:], ssBytes)

	return sharedSecret, nil
}

// PQCMixSecrets combines the classical ECDH shared secret with the PQC shared secret.
// This is used to create a hybrid secret that is secure against both classical
// and quantum attacks. The mixing uses HKDF with the Noise protocol's chaining key.
//
// The hybrid approach ensures that the resulting key is secure as long as
// either the classical or the PQC key exchange is secure.
func PQCMixSecrets(chainKey [blake2s.Size]byte, ecdhSecret, pqcSecret []byte) [blake2s.Size]byte {
	// Use BLAKE2s as the mixing function, consistent with WireGuard's Noise implementation
	// Mix: H(chainKey || ecdhSecret || pqcSecret)
	h, _ := blake2s.New256(nil)
	h.Write(chainKey[:])
	h.Write(ecdhSecret)
	h.Write(pqcSecret)

	var result [blake2s.Size]byte
	copy(result[:], h.Sum(nil))
	return result
}
