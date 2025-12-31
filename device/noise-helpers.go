/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"crypto/hmac"
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
