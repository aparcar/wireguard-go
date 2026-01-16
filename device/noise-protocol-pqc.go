/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"errors"
	"fmt"
	"time"

	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/chacha20poly1305"

	"github.com/tailscale/wireguard-go/conn"
	"github.com/tailscale/wireguard-go/tai64n"
)

// CreateMessagePQCInitiation creates a compact hybrid PQC initiation message
// using McEliece6688128 for static keys and Kyber512 for ephemeral keys.
// The message fits in a single IPv6 MTU frame (1204 bytes).
func (device *Device) CreateMessagePQCInitiation(peer *Peer) (*MessagePQCInitiation, error) {
	device.staticIdentity.RLock()
	defer device.staticIdentity.RUnlock()

	// Check that we have PQC keys configured
	if len(device.staticIdentity.pqcPublicKey) == 0 {
		return nil, errors.New("device PQC keys not configured")
	}

	handshake := &peer.handshake
	handshake.mutex.Lock()
	defer handshake.mutex.Unlock()

	// Check that peer has PQC public key configured
	if len(handshake.remotePQCPublicKey) == 0 {
		return nil, errors.New("peer PQC public key not configured")
	}

	// === PART 1: Standard X25519 handshake initiation ===

	var err error
	handshake.hash = InitialHash
	handshake.chainKey = InitialChainKey
	handshake.localEphemeral, err = newPrivateKey()
	if err != nil {
		return nil, err
	}

	handshake.mixHash(handshake.remoteStatic[:])

	msg := &MessagePQCInitiation{
		Type:      MessagePQCInitiationType,
		Ephemeral: handshake.localEphemeral.publicKey(),
	}

	handshake.mixKey(msg.Ephemeral[:])
	handshake.mixHash(msg.Ephemeral[:])

	// encrypt static key
	ss, err := handshake.localEphemeral.sharedSecret(handshake.remoteStatic)
	if err != nil {
		return nil, err
	}
	var key [chacha20poly1305.KeySize]byte
	KDF2(
		&handshake.chainKey,
		&key,
		handshake.chainKey[:],
		ss[:],
	)
	aead, _ := chacha20poly1305.New(key[:])
	aead.Seal(msg.Static[:0], ZeroNonce[:], device.staticIdentity.publicKey[:], handshake.hash[:])
	handshake.mixHash(msg.Static[:])

	// encrypt timestamp
	if isZero(handshake.precomputedStaticStatic[:]) {
		return nil, errInvalidPublicKey
	}
	KDF2(
		&handshake.chainKey,
		&key,
		handshake.chainKey[:],
		handshake.precomputedStaticStatic[:],
	)
	timestamp := tai64n.Now()
	aead, _ = chacha20poly1305.New(key[:])
	aead.Seal(msg.Timestamp[:0], ZeroNonce[:], timestamp[:], handshake.hash[:])
	handshake.mixHash(msg.Timestamp[:])

	// === PART 2: PQC extension fields ===

	// Initialize PQC transcript
	handshake.hashPQC = InitialPQCHash
	handshake.chainKeyPQC = InitialPQCChainKey

	// Pre-message: mix in responder's PQC key ID (known out-of-band)
	handshake.mixPQCHash(handshake.remotePQCKeyID[:])

	// Bind timestamp to PQC transcript for hybrid protection
	handshake.mixPQCHash(timestamp[:])

	// Encapsulate to responder's McEliece static key
	remotePQCPubKey, err := McEliecePublicKeyFromBytes(handshake.remotePQCPublicKey)
	if err != nil {
		return nil, fmt.Errorf("invalid remote PQC public key: %w", err)
	}
	ssMcEliece, ctMcEliece, err := McElieceEncapsulate(remotePQCPubKey)
	if err != nil {
		return nil, fmt.Errorf("McEliece encapsulation failed: %w", err)
	}
	msg.CTss = ctMcEliece
	handshake.mixPQCHash(ctMcEliece[:])
	handshake.mixPQCKey(ssMcEliece[:])

	// Generate Kyber512 ephemeral keypair
	kyberPubKey, kyberPrivKey, err := GenerateKyberEphemeralKeypair()
	if err != nil {
		return nil, fmt.Errorf("Kyber key generation failed: %w", err)
	}
	handshake.localKyberEphemeral = kyberPrivKey
	msg.EI = kyberPubKey
	handshake.mixPQCHash(kyberPubKey[:])

	// Encrypt our PQC key ID
	var encKey [chacha20poly1305.KeySize]byte
	KDF2(&handshake.chainKeyPQC, &encKey, handshake.chainKeyPQC[:], ssMcEliece[:])
	aead, _ = chacha20poly1305.New(encKey[:])
	aead.Seal(msg.EncSIid[:0], ZeroNonce[:], device.staticIdentity.pqcKeyID[:], handshake.hashPQC[:])
	handshake.mixPQCHash(msg.EncSIid[:])

	// Assign index
	device.indexTable.Delete(handshake.localIndex)
	msg.Sender, err = device.indexTable.NewIndexForHandshake(peer, handshake)
	if err != nil {
		return nil, err
	}
	handshake.localIndex = msg.Sender

	handshake.state = handshakeInitiationCreated
	return msg, nil
}

// ConsumeMessagePQCInitiation processes a PQC initiation message
func (device *Device) ConsumeMessagePQCInitiation(msg *MessagePQCInitiation, endpoint conn.Endpoint) *Peer {
	var (
		hash     [blake2s.Size]byte
		chainKey [blake2s.Size]byte
	)

	if msg.Type != MessagePQCInitiationType {
		return nil
	}

	device.staticIdentity.RLock()
	defer device.staticIdentity.RUnlock()

	// Check that we have PQC keys configured
	if len(device.staticIdentity.pqcPrivateKey) == 0 {
		device.log.Errorf("ConsumeMessagePQCInitiation: device PQC keys not configured")
		return nil
	}

	// === PART 1: Process standard X25519 handshake ===

	mixHash(&hash, &InitialHash, device.staticIdentity.publicKey[:])
	mixHash(&hash, &hash, msg.Ephemeral[:])
	mixKey(&chainKey, &InitialChainKey, msg.Ephemeral[:])

	// decrypt static key
	var peerPK NoisePublicKey
	var key [chacha20poly1305.KeySize]byte
	ss, err := device.staticIdentity.privateKey.sharedSecret(msg.Ephemeral)
	if err != nil {
		return nil
	}
	KDF2(&chainKey, &key, chainKey[:], ss[:])
	aead, _ := chacha20poly1305.New(key[:])
	_, err = aead.Open(peerPK[:0], ZeroNonce[:], msg.Static[:], hash[:])
	if err != nil {
		return nil
	}
	mixHash(&hash, &hash, msg.Static[:])

	// lookup peer by X25519 key
	initEP, ok := endpoint.(conn.InitiationAwareEndpoint)
	if ok {
		initEP.InitiationMessagePublicKey(peerPK)
	}

	peer := device.LookupPeer(peerPK)
	if peer == nil || !peer.isRunning.Load() {
		return nil
	}

	handshake := &peer.handshake

	// verify identity and decrypt timestamp
	var timestamp tai64n.Timestamp

	handshake.mutex.RLock()

	if isZero(handshake.precomputedStaticStatic[:]) {
		handshake.mutex.RUnlock()
		return nil
	}
	KDF2(&chainKey, &key, chainKey[:], handshake.precomputedStaticStatic[:])
	aead, _ = chacha20poly1305.New(key[:])
	_, err = aead.Open(timestamp[:0], ZeroNonce[:], msg.Timestamp[:], hash[:])
	if err != nil {
		handshake.mutex.RUnlock()
		return nil
	}
	mixHash(&hash, &hash, msg.Timestamp[:])

	// protect against replay & flood
	replay := !timestamp.After(handshake.lastTimestamp)
	flood := time.Since(handshake.lastInitiationConsumption) <= HandshakeInitationRate
	handshake.mutex.RUnlock()

	if replay {
		device.log.Verbosef("%v - ConsumeMessagePQCInitiation: handshake replay @ %v", peer, timestamp)
		return nil
	}
	if flood {
		device.log.Verbosef("%v - ConsumeMessagePQCInitiation: handshake flood", peer)
		return nil
	}

	// === PART 2: Process PQC extension fields ===

	handshake.mutex.Lock()

	// Initialize PQC transcript
	handshake.hashPQC = InitialPQCHash
	handshake.chainKeyPQC = InitialPQCChainKey

	// Pre-message: mix in our PQC key ID
	handshake.mixPQCHash(device.staticIdentity.pqcKeyID[:])

	// Bind timestamp to PQC transcript
	handshake.mixPQCHash(timestamp[:])

	// Decapsulate McEliece ciphertext
	mcEliecePrivKey, err := McEliecePrivateKeyFromBytes(device.staticIdentity.pqcPrivateKey)
	if err != nil {
		handshake.mutex.Unlock()
		device.log.Errorf("ConsumeMessagePQCInitiation: invalid McEliece private key: %v", err)
		return nil
	}
	ssMcEliece, err := McElieceDecapsulate(mcEliecePrivKey, msg.CTss)
	if err != nil {
		handshake.mutex.Unlock()
		device.log.Errorf("ConsumeMessagePQCInitiation: McEliece decapsulation failed: %v", err)
		return nil
	}
	handshake.mixPQCHash(msg.CTss[:])
	handshake.mixPQCKey(ssMcEliece[:])

	// Process initiator's Kyber ephemeral public key
	handshake.remoteKyberEphemeral = msg.EI
	handshake.mixPQCHash(msg.EI[:])

	// Decrypt initiator's PQC key ID
	var encKey [chacha20poly1305.KeySize]byte
	KDF2(&handshake.chainKeyPQC, &encKey, handshake.chainKeyPQC[:], ssMcEliece[:])
	aead, _ = chacha20poly1305.New(encKey[:])
	var initiatorKeyID NoisePQCKeyID
	_, err = aead.Open(initiatorKeyID[:0], ZeroNonce[:], msg.EncSIid[:], handshake.hashPQC[:])
	if err != nil {
		handshake.mutex.Unlock()
		device.log.Errorf("ConsumeMessagePQCInitiation: failed to decrypt initiator key ID: %v", err)
		return nil
	}
	handshake.mixPQCHash(msg.EncSIid[:])

	// Verify initiator's PQC key ID matches the peer we found via X25519
	if !initiatorKeyID.Equals(handshake.remotePQCKeyID) {
		handshake.mutex.Unlock()
		device.log.Errorf("%v - ConsumeMessagePQCInitiation: PQC key ID mismatch", peer)
		return nil
	}

	// Update X25519 handshake state
	handshake.hash = hash
	handshake.chainKey = chainKey
	handshake.remoteIndex = msg.Sender
	handshake.remoteEphemeral = msg.Ephemeral
	if timestamp.After(handshake.lastTimestamp) {
		handshake.lastTimestamp = timestamp
	}
	now := time.Now()
	if now.After(handshake.lastInitiationConsumption) {
		handshake.lastInitiationConsumption = now
	}
	handshake.state = handshakeInitiationConsumed

	handshake.mutex.Unlock()

	setZero(hash[:])
	setZero(chainKey[:])

	return peer
}

// CreateMessagePQCResponse creates a compact hybrid PQC response message
func (device *Device) CreateMessagePQCResponse(peer *Peer) (*MessagePQCResponse, error) {
	handshake := &peer.handshake
	handshake.mutex.Lock()
	defer handshake.mutex.Unlock()

	if handshake.state != handshakeInitiationConsumed {
		return nil, errors.New("handshake initiation must be consumed first")
	}

	// Check that peer has PQC public key configured (for encapsulation)
	if len(handshake.remotePQCPublicKey) == 0 {
		return nil, errors.New("peer PQC public key not configured")
	}

	// === PART 1: Standard X25519 response ===

	var err error
	device.indexTable.Delete(handshake.localIndex)
	handshake.localIndex, err = device.indexTable.NewIndexForHandshake(peer, handshake)
	if err != nil {
		return nil, err
	}

	msg := &MessagePQCResponse{
		Type:     MessagePQCResponseType,
		Sender:   handshake.localIndex,
		Receiver: handshake.remoteIndex,
	}

	// create ephemeral key
	handshake.localEphemeral, err = newPrivateKey()
	if err != nil {
		return nil, err
	}
	msg.Ephemeral = handshake.localEphemeral.publicKey()
	handshake.mixHash(msg.Ephemeral[:])
	handshake.mixKey(msg.Ephemeral[:])

	ss, err := handshake.localEphemeral.sharedSecret(handshake.remoteEphemeral)
	if err != nil {
		return nil, err
	}
	handshake.mixKey(ss[:])
	ss, err = handshake.localEphemeral.sharedSecret(handshake.remoteStatic)
	if err != nil {
		return nil, err
	}
	handshake.mixKey(ss[:])

	// === PART 2: PQC extension fields ===

	// Encapsulate to initiator's McEliece static key
	remotePQCPubKey, err := McEliecePublicKeyFromBytes(handshake.remotePQCPublicKey)
	if err != nil {
		return nil, fmt.Errorf("invalid remote PQC public key: %w", err)
	}
	ssMcEliece, ctMcEliece, err := McElieceEncapsulate(remotePQCPubKey)
	if err != nil {
		return nil, fmt.Errorf("McEliece encapsulation failed: %w", err)
	}
	msg.CTee = ctMcEliece
	handshake.mixPQCHash(ctMcEliece[:])
	handshake.mixPQCKey(ssMcEliece[:])

	// Encapsulate to initiator's Kyber ephemeral key
	kyberPubKey, err := KyberPublicKeyFromBytes(handshake.remoteKyberEphemeral[:])
	if err != nil {
		return nil, fmt.Errorf("invalid Kyber public key: %w", err)
	}
	ssKyber, ctKyber, err := KyberEncapsulate(kyberPubKey)
	if err != nil {
		return nil, fmt.Errorf("Kyber encapsulation failed: %w", err)
	}
	msg.CTse = ctKyber
	handshake.mixPQCHash(ctKyber[:])
	handshake.mixPQCKey(ssKyber[:])

	// Derive PQC key from final PQC chain key
	var pqcKeyDerived [blake2s.Size]byte
	KDF1(&pqcKeyDerived, handshake.chainKeyPQC[:], nil)
	copy(handshake.pqcKey[:], pqcKeyDerived[:])

	// === PART 3: Mix in preshared key and PQC key ===

	var tau [blake2s.Size]byte
	var key [chacha20poly1305.KeySize]byte

	// Add preshared key (standard WireGuard PSK mixing)
	KDF3(
		&handshake.chainKey,
		&tau,
		&key,
		handshake.chainKey[:],
		handshake.presharedKey[:],
	)
	handshake.mixHash(tau[:])

	// Add PQC key (additional post-quantum protection)
	KDF3(
		&handshake.chainKey,
		&tau,
		&key,
		handshake.chainKey[:],
		handshake.pqcKey[:],
	)
	handshake.mixHash(tau[:])

	aead, _ := chacha20poly1305.New(key[:])
	aead.Seal(msg.Empty[:0], ZeroNonce[:], nil, handshake.hash[:])
	handshake.mixHash(msg.Empty[:])

	handshake.state = handshakeResponseCreated
	return msg, nil
}

// ConsumeMessagePQCResponse processes a PQC response message
func (device *Device) ConsumeMessagePQCResponse(msg *MessagePQCResponse) *Peer {
	if msg.Type != MessagePQCResponseType {
		return nil
	}

	// Lookup handshake by receiver
	lookup := device.indexTable.Lookup(msg.Receiver)
	handshake := lookup.handshake
	if handshake == nil {
		return nil
	}

	var (
		hash     [blake2s.Size]byte
		chainKey [blake2s.Size]byte
		pqcKey   [blake2s.Size]byte
	)

	ok := func() bool {
		handshake.mutex.RLock()
		defer handshake.mutex.RUnlock()

		if handshake.state != handshakeInitiationCreated {
			return false
		}

		device.staticIdentity.RLock()
		defer device.staticIdentity.RUnlock()

		// === PART 1: Process standard X25519 response ===

		mixHash(&hash, &handshake.hash, msg.Ephemeral[:])
		mixKey(&chainKey, &handshake.chainKey, msg.Ephemeral[:])

		ss, err := handshake.localEphemeral.sharedSecret(msg.Ephemeral)
		if err != nil {
			return false
		}
		mixKey(&chainKey, &chainKey, ss[:])
		setZero(ss[:])

		ss, err = device.staticIdentity.privateKey.sharedSecret(msg.Ephemeral)
		if err != nil {
			return false
		}
		mixKey(&chainKey, &chainKey, ss[:])
		setZero(ss[:])

		// === PART 2: Process PQC extension fields ===

		// Copy PQC state for local processing (we have RLock)
		hashPQC := handshake.hashPQC
		chainKeyPQC := handshake.chainKeyPQC

		// Decapsulate McEliece ciphertext using our static key
		mcEliecePrivKey, err := McEliecePrivateKeyFromBytes(device.staticIdentity.pqcPrivateKey)
		if err != nil {
			return false
		}
		ssMcEliece, err := McElieceDecapsulate(mcEliecePrivKey, msg.CTee)
		if err != nil {
			return false
		}
		mixHash(&hashPQC, &hashPQC, msg.CTee[:])
		mixKey(&chainKeyPQC, &chainKeyPQC, ssMcEliece[:])

		// Decapsulate Kyber ciphertext using our ephemeral key
		kyberPrivKey, err := KyberPrivateKeyFromBytes(handshake.localKyberEphemeral)
		if err != nil {
			return false
		}
		ssKyber, err := KyberDecapsulate(kyberPrivKey, msg.CTse)
		if err != nil {
			return false
		}
		mixHash(&hashPQC, &hashPQC, msg.CTse[:])
		mixKey(&chainKeyPQC, &chainKeyPQC, ssKyber[:])

		// Derive PQC key from final PQC chain key
		KDF1(&pqcKey, chainKeyPQC[:], nil)

		// === PART 3: Mix in preshared key and PQC key ===

		var tau [blake2s.Size]byte
		var key [chacha20poly1305.KeySize]byte

		// Add preshared key
		KDF3(&chainKey, &tau, &key, chainKey[:], handshake.presharedKey[:])
		mixHash(&hash, &hash, tau[:])

		// Add PQC key
		KDF3(&chainKey, &tau, &key, chainKey[:], pqcKey[:])
		mixHash(&hash, &hash, tau[:])

		// Authenticate transcript
		aead, _ := chacha20poly1305.New(key[:])
		_, err = aead.Open(nil, ZeroNonce[:], msg.Empty[:], hash[:])
		if err != nil {
			return false
		}
		mixHash(&hash, &hash, msg.Empty[:])
		return true
	}()

	if !ok {
		return nil
	}

	// Update handshake state
	handshake.mutex.Lock()

	handshake.hash = hash
	handshake.chainKey = chainKey
	copy(handshake.pqcKey[:], pqcKey[:])
	handshake.remoteIndex = msg.Sender
	handshake.state = handshakeResponseConsumed

	handshake.mutex.Unlock()

	setZero(hash[:])
	setZero(chainKey[:])
	setZero(pqcKey[:])

	return lookup.peer
}
