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

	// PQC key sizes for ML-KEM-768 (post-quantum key encapsulation)
	NoisePQCPublicKeySize    = 1184 // ML-KEM-768 public key (encapsulation key)
	NoisePQCSeedSize         = 64   // ML-KEM-768 seed for deterministic key generation (d || z)
	NoisePQCCiphertextSize   = 1088 // ML-KEM-768 ciphertext
	NoisePQCSharedSecretSize = 32   // ML-KEM-768 shared secret
)

type (
	NoisePublicKey    [NoisePublicKeySize]byte
	NoisePrivateKey   [NoisePrivateKeySize]byte
	NoisePresharedKey [NoisePresharedKeySize]byte
	NoiseNonce        uint64 // padded to 12-bytes

	// PQC key types for ML-KEM-768 post-quantum cryptography
	NoisePQCPublicKey    [NoisePQCPublicKeySize]byte
	NoisePQCSeed         [NoisePQCSeedSize]byte // Seed for deterministic key generation
	NoisePQCCiphertext   [NoisePQCCiphertextSize]byte
	NoisePQCSharedSecret [NoisePQCSharedSecretSize]byte
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

// PQC key helper methods

func (key NoisePQCPublicKey) IsZero() bool {
	var zero NoisePQCPublicKey
	return key.Equals(zero)
}

func (key NoisePQCPublicKey) Equals(tar NoisePQCPublicKey) bool {
	return subtle.ConstantTimeCompare(key[:], tar[:]) == 1
}

func (key *NoisePQCPublicKey) FromHex(src string) error {
	return loadExactHex(key[:], src)
}

func (key *NoisePQCPublicKey) FromBytes(src []byte) error {
	if len(src) != NoisePQCPublicKeySize {
		return errors.New("invalid PQC public key size")
	}
	copy(key[:], src)
	return nil
}

func (key NoisePQCSeed) IsZero() bool {
	var zero NoisePQCSeed
	return key.Equals(zero)
}

func (key NoisePQCSeed) Equals(tar NoisePQCSeed) bool {
	return subtle.ConstantTimeCompare(key[:], tar[:]) == 1
}

func (key *NoisePQCSeed) FromHex(src string) error {
	return loadExactHex(key[:], src)
}

func (key *NoisePQCSeed) FromBytes(src []byte) error {
	if len(src) != NoisePQCSeedSize {
		return errors.New("invalid PQC seed size")
	}
	copy(key[:], src)
	return nil
}

func (key NoisePQCCiphertext) IsZero() bool {
	var zero NoisePQCCiphertext
	return subtle.ConstantTimeCompare(key[:], zero[:]) == 1
}

func (key NoisePQCSharedSecret) IsZero() bool {
	var zero NoisePQCSharedSecret
	return subtle.ConstantTimeCompare(key[:], zero[:]) == 1
}
