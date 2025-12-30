// SPDX-License-Identifier: MIT
//
// Pure PQC handshake implementation (pqIK pattern from quantshake)
// This runs independently of the WireGuard Noise protocol

package device

import (
	"crypto/hmac"
	"crypto/sha256"
	"fmt"

	"github.com/tailscale/wireguard-go/tai64n"
	"golang.org/x/crypto/chacha20poly1305"
)

// pqKeySchedule maintains the hash chain and chaining key for PQC handshake
type pqKeySchedule struct {
	h  []byte // transcript hash
	ck []byte // chaining key
}

func newPQKeySchedule(prologue string) *pqKeySchedule {
	ph := sha256.Sum256([]byte(prologue))
	return &pqKeySchedule{
		h:  ph[:],
		ck: ph[:],
	}
}

func (ks *pqKeySchedule) mixHash(data []byte) {
	h := sha256.New()
	h.Write(ks.h)
	h.Write(data)
	ks.h = h.Sum(nil)
}

func (ks *pqKeySchedule) mixKey(ikm []byte) {
	prk := hkdfExtractSHA256(ks.ck, ikm)
	ks.ck = hkdfExpandSHA256(prk, []byte("MixKey"), 32)
}

func (ks *pqKeySchedule) encryptAndHash(plaintext []byte) ([]byte, error) {
	prk := hkdfExtractSHA256(ks.ck, nil)
	key := hkdfExpandSHA256(prk, []byte("encrypt"), 32)
	defer zeroBytes(key)

	nonce, err := deriveAckNonce(key, ks.h)
	if err != nil {
		return nil, err
	}

	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}

	ciphertext := aead.Seal(nil, nonce[:], plaintext, ks.h)
	ks.mixHash(ciphertext)
	return ciphertext, nil
}

func (ks *pqKeySchedule) decryptAndHash(ciphertext []byte) ([]byte, error) {
	prk := hkdfExtractSHA256(ks.ck, nil)
	key := hkdfExpandSHA256(prk, []byte("encrypt"), 32)
	defer zeroBytes(key)

	nonce, err := deriveAckNonce(key, ks.h)
	if err != nil {
		return nil, err
	}

	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}

	plaintext, err := aead.Open(nil, nonce[:], ciphertext, ks.h)
	if err != nil {
		return nil, fmt.Errorf("decrypt failed: %w", err)
	}

	ks.mixHash(ciphertext)
	return plaintext, nil
}

func hkdfExtractSHA256(salt, ikm []byte) []byte {
	m := hmac.New(sha256.New, salt)
	m.Write(ikm)
	return m.Sum(nil)
}

func hkdfExpandSHA256(prk, info []byte, l int) []byte {
	var res, t []byte
	for i := byte(1); len(res) < l; i++ {
		h := hmac.New(sha256.New, prk)
		h.Write(t)
		h.Write(info)
		h.Write([]byte{i})
		t = h.Sum(nil)
		res = append(res, t...)
	}
	return res[:l]
}

func deriveAckNonce(key, hash []byte) ([chacha20poly1305.NonceSize]byte, error) {
	var nonce [chacha20poly1305.NonceSize]byte
	h := sha256.New()
	h.Write(key)
	h.Write(hash)
	derived := h.Sum(nil)
	copy(nonce[:], derived[:chacha20poly1305.NonceSize])
	return nonce, nil
}

func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// BuildPQCMsg1 builds the PQC portion of the initiation message (quantshake Msg1)
// Returns: CTss, EI, EncSI
// The timestamp parameter binds the classical handshake timestamp to the PQC transcript,
// providing hybrid (classical + PQC) protection against timestamp forgery.
func BuildPQCMsg1(localStaticPub NoisePQCPublicKey, remoteStaticPub NoisePQCPublicKey, timestamp tai64n.Timestamp) (
	ctss NoisePQCCiphertext,
	ei NoisePQCPublicKey,
	encSI []byte,
	eiPriv NoisePQCSeed,
	ks *pqKeySchedule,
	err error,
) {
	// Initialize with pqIK prologue
	ks = newPQKeySchedule("pqIK_PQKEM_ChaChaPoly_SHA256")
	ks.mixHash([]byte("wireguard-pqc-v1")) // Additional context

	// Pre-message: <- s (responder's static key is known)
	ks.mixHash(remoteStaticPub[:])

	// Bind timestamp to PQC transcript for hybrid protection
	// This ensures an attacker must break both X25519 AND ML-KEM-768 to forge timestamps
	ks.mixHash(timestamp[:])

	// -> skem (encapsulate to responder's static key)
	ssSS, ctSS, err := PQCEncapsulate(remoteStaticPub)
	if err != nil {
		return ctss, ei, nil, eiPriv, nil, fmt.Errorf("ss encapsulation failed: %w", err)
	}
	copy(ctss[:], ctSS[:])

	ks.mixHash(ctss[:])
	ks.mixKey(ssSS[:])

	// Generate ephemeral key
	eiPub, eiSk, err := PQCGenerateKeyPair()
	if err != nil {
		return ctss, ei, nil, eiPriv, nil, fmt.Errorf("ephemeral key generation failed: %w", err)
	}
	copy(ei[:], eiPub[:])
	copy(eiPriv[:], eiSk[:])

	// -> e
	ks.mixHash(ei[:])

	// -> s (encrypt initiator static public key)
	encSI, err = ks.encryptAndHash(localStaticPub[:])
	if err != nil {
		return ctss, ei, nil, eiPriv, nil, fmt.Errorf("failed to encrypt static key: %w", err)
	}

	return ctss, ei, encSI, eiPriv, ks, nil
}

// ProcessPQCMsg1 processes the PQC portion of the initiation message
// Returns the derived key schedule state
// The timestamp parameter must match the timestamp used by the initiator in BuildPQCMsg1,
// providing hybrid (classical + PQC) protection against timestamp forgery.
func ProcessPQCMsg1(
	localStaticPub NoisePQCPublicKey,
	localStaticPriv NoisePQCSeed,
	ctss NoisePQCCiphertext,
	ei NoisePQCPublicKey,
	encSI []byte,
	timestamp tai64n.Timestamp,
) (initiatorStaticPub NoisePQCPublicKey, ks *pqKeySchedule, err error) {
	// Initialize with same prologue
	ks = newPQKeySchedule("pqIK_PQKEM_ChaChaPoly_SHA256")
	ks.mixHash([]byte("wireguard-pqc-v1"))

	// Pre-message: <- s
	ks.mixHash(localStaticPub[:])

	// Bind timestamp to PQC transcript for hybrid protection
	// Must match the timestamp mixed in by the initiator
	ks.mixHash(timestamp[:])

	// <- skem (decapsulate with our static key)
	ssSS, err := PQCDecapsulate(localStaticPriv, ctss)
	if err != nil {
		return initiatorStaticPub, nil, fmt.Errorf("ss decapsulation failed: %w", err)
	}
	ks.mixHash(ctss[:])
	ks.mixKey(ssSS[:])

	// <- e
	ks.mixHash(ei[:])

	// <- s (decrypt initiator static public key)

	siBytes, err := ks.decryptAndHash(encSI)
	if err != nil {
		return initiatorStaticPub, nil, fmt.Errorf("failed to decrypt initiator static key: %w", err)
	}
	copy(initiatorStaticPub[:], siBytes)

	return initiatorStaticPub, ks, nil
}

// BuildPQCMsg2 builds the PQC portion of the response message (quantshake Msg2)
func BuildPQCMsg2(
	initiatorEphemeralPub NoisePQCPublicKey,
	initiatorStaticPub NoisePQCPublicKey,
	ks *pqKeySchedule,
) (ctee NoisePQCCiphertext, ctse NoisePQCCiphertext, psk [32]byte, err error) {
	// <- ekem (encapsulate to initiator's ephemeral key)
	ssEE, ctEE, err := PQCEncapsulate(initiatorEphemeralPub)
	if err != nil {
		return ctee, ctse, psk, fmt.Errorf("ee encapsulation failed: %w", err)
	}
	copy(ctee[:], ctEE[:])
	ks.mixHash(ctee[:])
	ks.mixKey(ssEE[:])

	// <- skem (encapsulate to initiator's static key)
	ssSE, ctSE, err := PQCEncapsulate(initiatorStaticPub)
	if err != nil {
		return ctee, ctse, psk, fmt.Errorf("se encapsulation failed: %w", err)
	}
	copy(ctse[:], ctSE[:])
	ks.mixHash(ctse[:])
	ks.mixKey(ssSE[:])

	// Derive PSK from final chaining key
	pskBytes := hkdfExpandSHA256(ks.ck, []byte("shared"), 32)
	copy(psk[:], pskBytes)

	return ctee, ctse, psk, nil
}

// ProcessPQCMsg2 processes the PQC portion of the response message
func ProcessPQCMsg2(
	localEphemeralPriv NoisePQCSeed,
	localStaticPriv NoisePQCSeed,
	ctee NoisePQCCiphertext,
	ctse NoisePQCCiphertext,
	ks *pqKeySchedule,
) (psk [32]byte, err error) {
	// <- ekem (decapsulate with our ephemeral key)
	ks.mixHash(ctee[:])
	ssEE, err := PQCDecapsulate(localEphemeralPriv, ctee)
	if err != nil {
		return psk, fmt.Errorf("ee decapsulation failed: %w", err)
	}
	ks.mixKey(ssEE[:])

	// <- skem (decapsulate with our static key)
	ks.mixHash(ctse[:])
	ssSE, err := PQCDecapsulate(localStaticPriv, ctse)
	if err != nil {
		return psk, fmt.Errorf("se decapsulation failed: %w", err)
	}
	ks.mixKey(ssSE[:])

	// Derive PSK from final chaining key
	pskBytes := hkdfExpandSHA256(ks.ck, []byte("shared"), 32)
	copy(psk[:], pskBytes)

	return psk, nil
}
