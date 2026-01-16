/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"errors"

	"github.com/katzenpost/circl/kem/kyber/kyber512"
	"github.com/katzenpost/circl/kem/mceliece/mceliece6688128"
	"github.com/katzenpost/hpqc/kem"
	"golang.org/x/crypto/blake2s"
)

// PQC: Compact hybrid handshake using McEliece6688128 (static) + Kyber512 (ephemeral)
// This design fits the entire PQC handshake in a single IPv6 MTU frame (1280 bytes)
//
// Design rationale:
// - McEliece6688128 provides NIST Level 5 (256-bit) security for static keys
// - Kyber512 provides NIST Level 1 (128-bit) security for ephemeral keys (forward secrecy)
// - McEliece public keys (~1MB) are pre-provisioned out-of-band
// - Only McEliece ciphertexts (208 bytes) are transmitted in handshake
// - Kyber512 public keys (800 bytes) and ciphertexts (768 bytes) are transmitted
//
// Message sizes (fit in single IPv6 MTU of 1280 bytes):
// - PQC Initiation: 1204 bytes
// - PQC Response: 1068 bytes

var (
	mcElieceScheme = mceliece6688128.Scheme()
	kyberScheme    = kyber512.Scheme()
)

var (
	errMcElieceKeyGenFailed   = errors.New("McEliece key generation failed")
	errMcElieceEncapFailed    = errors.New("McEliece encapsulation failed")
	errMcElieceDecapFailed    = errors.New("McEliece decapsulation failed")
	errKyberKeyGenFailed      = errors.New("Kyber key generation failed")
	errKyberEncapFailed       = errors.New("Kyber encapsulation failed")
	errKyberDecapFailed       = errors.New("Kyber decapsulation failed")
	errInvalidMcElieceKeySize = errors.New("invalid McEliece key size")
	errInvalidKyberKeySize    = errors.New("invalid Kyber key size")
	errInvalidCiphertextSize  = errors.New("invalid ciphertext size")
)

// McElieceKeyPair holds a McEliece6688128 key pair
// The public key is large (~1MB) and should be pre-provisioned
type McElieceKeyPair struct {
	PublicKey  kem.PublicKey
	PrivateKey kem.PrivateKey
}

// KyberKeyPair holds a Kyber512 key pair for ephemeral use
type KyberKeyPair struct {
	PublicKey  kem.PublicKey
	PrivateKey kem.PrivateKey
}

// McElieceGenerateKeyPair generates a new McEliece6688128 key pair
// WARNING: This is slow and the public key is ~1MB
func McElieceGenerateKeyPair() (*McElieceKeyPair, error) {
	pk, sk, err := mcElieceScheme.GenerateKeyPair()
	if err != nil {
		return nil, errMcElieceKeyGenFailed
	}
	return &McElieceKeyPair{
		PublicKey:  pk,
		PrivateKey: sk,
	}, nil
}

// McEliecePublicKeyFromBytes reconstructs a McEliece public key from bytes
func McEliecePublicKeyFromBytes(data []byte) (kem.PublicKey, error) {
	if len(data) != mcElieceScheme.PublicKeySize() {
		return nil, errInvalidMcElieceKeySize
	}
	pk, err := mcElieceScheme.UnmarshalBinaryPublicKey(data)
	if err != nil {
		return nil, err
	}
	return pk, nil
}

// McEliecePrivateKeyFromBytes reconstructs a McEliece private key from bytes
func McEliecePrivateKeyFromBytes(data []byte) (kem.PrivateKey, error) {
	if len(data) != mcElieceScheme.PrivateKeySize() {
		return nil, errInvalidMcElieceKeySize
	}
	sk, err := mcElieceScheme.UnmarshalBinaryPrivateKey(data)
	if err != nil {
		return nil, err
	}
	return sk, nil
}

// McElieceEncapsulate encapsulates to a McEliece public key
// Returns the shared secret and ciphertext
func McElieceEncapsulate(pk kem.PublicKey) (sharedSecret [NoiseMcElieceSharedKeySize]byte, ct NoiseMcElieceCiphertext, err error) {
	ctBytes, ssBytes, err := mcElieceScheme.Encapsulate(pk)
	if err != nil {
		return sharedSecret, ct, errMcElieceEncapFailed
	}
	if len(ctBytes) != NoiseMcElieceCiphertextSize {
		return sharedSecret, ct, errInvalidCiphertextSize
	}
	copy(ct[:], ctBytes)
	copy(sharedSecret[:], ssBytes)
	return sharedSecret, ct, nil
}

// McElieceDecapsulate decapsulates a McEliece ciphertext using the private key
func McElieceDecapsulate(sk kem.PrivateKey, ct NoiseMcElieceCiphertext) (sharedSecret [NoiseMcElieceSharedKeySize]byte, err error) {
	ssBytes, err := mcElieceScheme.Decapsulate(sk, ct[:])
	if err != nil {
		return sharedSecret, errMcElieceDecapFailed
	}
	copy(sharedSecret[:], ssBytes)
	return sharedSecret, nil
}

// McElieceKeyID computes a 32-byte identifier (BLAKE2s hash) of the full public key
// This is used in the handshake to identify which McEliece key is being used
func McElieceKeyID(pk kem.PublicKey) NoisePQCKeyID {
	pkBytes, _ := pk.MarshalBinary()
	return blake2s.Sum256(pkBytes)
}

// McElieceKeyIDFromBytes computes a key ID from raw public key bytes
func McElieceKeyIDFromBytes(pkBytes []byte) NoisePQCKeyID {
	return blake2s.Sum256(pkBytes)
}

// KyberGenerateKeyPair generates a new Kyber512 key pair
func KyberGenerateKeyPair() (*KyberKeyPair, error) {
	pk, sk, err := kyberScheme.GenerateKeyPair()
	if err != nil {
		return nil, errKyberKeyGenFailed
	}
	return &KyberKeyPair{
		PublicKey:  pk,
		PrivateKey: sk,
	}, nil
}

// KyberPublicKeyFromBytes reconstructs a Kyber512 public key from bytes
func KyberPublicKeyFromBytes(data []byte) (kem.PublicKey, error) {
	if len(data) != kyberScheme.PublicKeySize() {
		return nil, errInvalidKyberKeySize
	}
	pk, err := kyberScheme.UnmarshalBinaryPublicKey(data)
	if err != nil {
		return nil, err
	}
	return pk, nil
}

// KyberPrivateKeyFromBytes reconstructs a Kyber512 private key from bytes
func KyberPrivateKeyFromBytes(data []byte) (kem.PrivateKey, error) {
	if len(data) != kyberScheme.PrivateKeySize() {
		return nil, errInvalidKyberKeySize
	}
	sk, err := kyberScheme.UnmarshalBinaryPrivateKey(data)
	if err != nil {
		return nil, err
	}
	return sk, nil
}

// KyberEncapsulate encapsulates to a Kyber512 public key
func KyberEncapsulate(pk kem.PublicKey) (sharedSecret [NoiseKyberSharedKeySize]byte, ct NoiseKyberCiphertext, err error) {
	ctBytes, ssBytes, err := kyberScheme.Encapsulate(pk)
	if err != nil {
		return sharedSecret, ct, errKyberEncapFailed
	}
	if len(ctBytes) != NoiseKyberCiphertextSize {
		return sharedSecret, ct, errInvalidCiphertextSize
	}
	copy(ct[:], ctBytes)
	copy(sharedSecret[:], ssBytes)
	return sharedSecret, ct, nil
}

// KyberDecapsulate decapsulates a Kyber512 ciphertext using the private key
func KyberDecapsulate(sk kem.PrivateKey, ct NoiseKyberCiphertext) (sharedSecret [NoiseKyberSharedKeySize]byte, err error) {
	ssBytes, err := kyberScheme.Decapsulate(sk, ct[:])
	if err != nil {
		return sharedSecret, errKyberDecapFailed
	}
	copy(sharedSecret[:], ssBytes)
	return sharedSecret, nil
}

// KyberPublicKeyToBytes serializes a Kyber512 public key to the wire format
func KyberPublicKeyToBytes(pk kem.PublicKey) (NoiseKyberPublicKey, error) {
	var result NoiseKyberPublicKey
	pkBytes, err := pk.MarshalBinary()
	if err != nil {
		return result, err
	}
	if len(pkBytes) != NoiseKyberPublicKeySize {
		return result, errInvalidKyberKeySize
	}
	copy(result[:], pkBytes)
	return result, nil
}

// KyberPrivateKeyToBytes serializes a Kyber512 private key
func KyberPrivateKeyToBytes(sk kem.PrivateKey) ([]byte, error) {
	return sk.MarshalBinary()
}

// GeneratePQCStaticKeypair generates a new McEliece6688128 keypair and returns
// the full public key bytes and private key bytes
// WARNING: Key generation is slow and public key is ~1MB
func GeneratePQCStaticKeypair() (publicKey []byte, privateKey []byte, err error) {
	kp, err := McElieceGenerateKeyPair()
	if err != nil {
		return nil, nil, err
	}

	publicKey, err = kp.PublicKey.MarshalBinary()
	if err != nil {
		return nil, nil, err
	}

	privateKey, err = kp.PrivateKey.MarshalBinary()
	if err != nil {
		return nil, nil, err
	}

	return publicKey, privateKey, nil
}

// GenerateKyberEphemeralKeypair generates a new Kyber512 ephemeral keypair
func GenerateKyberEphemeralKeypair() (pk NoiseKyberPublicKey, skBytes []byte, err error) {
	kp, err := KyberGenerateKeyPair()
	if err != nil {
		return pk, nil, err
	}

	pk, err = KyberPublicKeyToBytes(kp.PublicKey)
	if err != nil {
		return pk, nil, err
	}

	skBytes, err = KyberPrivateKeyToBytes(kp.PrivateKey)
	if err != nil {
		return pk, nil, err
	}

	return pk, skBytes, nil
}
