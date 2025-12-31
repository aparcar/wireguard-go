/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"crypto/hmac"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"

	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/curve25519"
)

/* KDF related functions.
 * HMAC-based Key Derivation Function (HKDF)
 * https://tools.ietf.org/html/rfc5869
 */

func HMAC1(sum *[blake2s.Size]byte, key, in0 []byte) {
	mac := hmac.New(func() hash.Hash {
		h, _ := blake2s.New256(nil)
		return h
	}, key)
	mac.Write(in0)
	mac.Sum(sum[:0])
}

func HMAC2(sum *[blake2s.Size]byte, key, in0, in1 []byte) {
	mac := hmac.New(func() hash.Hash {
		h, _ := blake2s.New256(nil)
		return h
	}, key)
	mac.Write(in0)
	mac.Write(in1)
	mac.Sum(sum[:0])
}

func KDF1(t0 *[blake2s.Size]byte, key, input []byte) {
	HMAC1(t0, key, input)
	HMAC1(t0, t0[:], []byte{0x1})
}

func KDF2(t0, t1 *[blake2s.Size]byte, key, input []byte) {
	var prk [blake2s.Size]byte
	HMAC1(&prk, key, input)
	HMAC1(t0, prk[:], []byte{0x1})
	HMAC2(t1, prk[:], t0[:], []byte{0x2})
	setZero(prk[:])
}

func KDF3(t0, t1, t2 *[blake2s.Size]byte, key, input []byte) {
	var prk [blake2s.Size]byte
	HMAC1(&prk, key, input)
	HMAC1(t0, prk[:], []byte{0x1})
	HMAC2(t1, prk[:], t0[:], []byte{0x2})
	HMAC2(t2, prk[:], t1[:], []byte{0x3})
	setZero(prk[:])
}

func isZero(val []byte) bool {
	acc := 1
	for _, b := range val {
		acc &= subtle.ConstantTimeByteEq(b, 0)
	}
	return acc == 1
}

/* This function is not used as pervasively as it should because this is mostly impossible in Go at the moment */
func setZero(arr []byte) {
	for i := range arr {
		arr[i] = 0
	}
}

func (sk *NoisePrivateKey) clamp() {
	sk[0] &= 248
	sk[31] = (sk[31] & 127) | 64
}

func newPrivateKey() (sk NoisePrivateKey, err error) {
	_, err = rand.Read(sk[:])
	sk.clamp()
	return
}

func (sk *NoisePrivateKey) publicKey() (pk NoisePublicKey) {
	apk := (*[NoisePublicKeySize]byte)(&pk)
	ask := (*[NoisePrivateKeySize]byte)(sk)
	curve25519.ScalarBaseMult(apk, ask)
	return
}

var errInvalidPublicKey = errors.New("invalid public key")

func (sk *NoisePrivateKey) sharedSecret(pk NoisePublicKey) (ss [NoisePublicKeySize]byte, err error) {
	apk := (*[NoisePublicKeySize]byte)(&pk)
	ask := (*[NoisePrivateKeySize]byte)(sk)
	curve25519.ScalarMult(&ss, ask, apk)
	if isZero(ss[:]) {
		return ss, errInvalidPublicKey
	}
	return ss, nil
}

/* PQC key generation functions */

// GeneratePQCKeypair generates a new ML-KEM-768 keypair from a random seed.
// Returns the seed (64 bytes) and public key (1184 bytes) as hex strings.
func GeneratePQCKeypair() (seedHex, publicKeyHex string, err error) {
	var seed NoisePQCSeed
	if _, err := io.ReadFull(rand.Reader, seed[:]); err != nil {
		return "", "", fmt.Errorf("failed to generate random seed: %w", err)
	}

	publicKey, err := PQCPublicKeyFromSeed(seed)
	if err != nil {
		return "", "", fmt.Errorf("failed to derive public key: %w", err)
	}

	seedHex = hex.EncodeToString(seed[:])
	publicKeyHex = hex.EncodeToString(publicKey[:])

	return seedHex, publicKeyHex, nil
}

// PQCPublicKeyFromSeed derives a PQC public key from a seed.
func PQCPublicKeyFromSeed(seed NoisePQCSeed) (NoisePQCPublicKey, error) {
	publicKey, _, err := PQCGenerateKeyPairFromSeed(seed)
	if err != nil {
		return NoisePQCPublicKey{}, err
	}
	return publicKey, nil
}

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
