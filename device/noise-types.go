/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"crypto/subtle"
	"encoding/hex"
	"errors"
)

const (
	NoisePublicKeySize    = 32
	NoisePrivateKeySize   = 32
	NoisePresharedKeySize = 32

	// PQC: Compact hybrid using McEliece6688128 (static) + Kyber512 (ephemeral)
	// This design fits the entire PQC handshake in a single IPv6 MTU frame (1280 bytes)
	//
	// McEliece6688128 - NIST Level 5 (256-bit security) for static keys
	// Public keys are pre-provisioned out-of-band (~1MB), only ciphertexts transmitted
	NoiseMcEliecePublicKeySize  = 1044992 // McEliece6688128 public key (pre-provisioned)
	NoiseMcEliecePrivateKeySize = 13932   // McEliece6688128 private key
	NoiseMcElieceCiphertextSize = 208     // McEliece6688128 ciphertext
	NoiseMcElieceSharedKeySize  = 32      // McEliece6688128 shared secret

	// Kyber512 - NIST Level 1 (128-bit security) for ephemeral keys (forward secrecy)
	NoiseKyberPublicKeySize  = 800  // Kyber512 public key
	NoiseKyberPrivateKeySize = 1632 // Kyber512 private key
	NoiseKyberCiphertextSize = 768  // Kyber512 ciphertext
	NoiseKyberSharedKeySize  = 32   // Kyber512 shared secret

	// Key identifier size (BLAKE2s hash of full McEliece public key)
	NoisePQCKeyIDSize = 32
)

type (
	NoisePublicKey    [NoisePublicKeySize]byte
	NoisePrivateKey   [NoisePrivateKeySize]byte
	NoisePresharedKey [NoisePresharedKeySize]byte
	NoiseNonce        uint64 // padded to 12-bytes

	// PQC types for compact hybrid handshake
	NoiseMcElieceCiphertext [NoiseMcElieceCiphertextSize]byte
	NoiseKyberPublicKey     [NoiseKyberPublicKeySize]byte
	NoiseKyberCiphertext    [NoiseKyberCiphertextSize]byte
	NoisePQCKeyID           [NoisePQCKeyIDSize]byte // BLAKE2s hash of McEliece public key
)

func loadExactHex(dst []byte, src string) error {
	slice, err := hex.DecodeString(src)
	if err != nil {
		return err
	}
	if len(slice) != len(dst) {
		return errors.New("hex string does not fit the slice")
	}
	copy(dst, slice)
	return nil
}

func (key NoisePrivateKey) IsZero() bool {
	var zero NoisePrivateKey
	return key.Equals(zero)
}

func (key NoisePrivateKey) Equals(tar NoisePrivateKey) bool {
	return subtle.ConstantTimeCompare(key[:], tar[:]) == 1
}

func (key *NoisePrivateKey) FromHex(src string) (err error) {
	err = loadExactHex(key[:], src)
	key.clamp()
	return
}

func (key *NoisePrivateKey) FromMaybeZeroHex(src string) (err error) {
	err = loadExactHex(key[:], src)
	if key.IsZero() {
		return
	}
	key.clamp()
	return
}

func (key *NoisePublicKey) FromHex(src string) error {
	return loadExactHex(key[:], src)
}

func (key NoisePublicKey) IsZero() bool {
	var zero NoisePublicKey
	return key.Equals(zero)
}

func (key NoisePublicKey) Equals(tar NoisePublicKey) bool {
	return subtle.ConstantTimeCompare(key[:], tar[:]) == 1
}

func (key *NoisePresharedKey) FromHex(src string) error {
	return loadExactHex(key[:], src)
}

// PQC helper methods

func (key NoiseKyberPublicKey) IsZero() bool {
	var zero NoiseKyberPublicKey
	return key.Equals(zero)
}

func (key NoiseKyberPublicKey) Equals(tar NoiseKyberPublicKey) bool {
	return subtle.ConstantTimeCompare(key[:], tar[:]) == 1
}

func (key *NoiseKyberPublicKey) FromHex(src string) error {
	return loadExactHex(key[:], src)
}

func (id NoisePQCKeyID) IsZero() bool {
	var zero NoisePQCKeyID
	return id.Equals(zero)
}

func (id NoisePQCKeyID) Equals(tar NoisePQCKeyID) bool {
	return subtle.ConstantTimeCompare(id[:], tar[:]) == 1
}

func (id *NoisePQCKeyID) FromHex(src string) error {
	return loadExactHex(id[:], src)
}
