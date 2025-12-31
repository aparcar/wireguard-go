/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"time"

	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/poly1305"

	"github.com/tailscale/wireguard-go/conn"
	"github.com/tailscale/wireguard-go/tai64n"
)

type handshakeState int

const (
	handshakeZeroed = handshakeState(iota)
	handshakeInitiationCreated
	handshakeInitiationConsumed
	handshakeResponseCreated
	handshakeResponseConsumed
)

func (hs handshakeState) String() string {
	switch hs {
	case handshakeZeroed:
		return "handshakeZeroed"
	case handshakeInitiationCreated:
		return "handshakeInitiationCreated"
	case handshakeInitiationConsumed:
		return "handshakeInitiationConsumed"
	case handshakeResponseCreated:
		return "handshakeResponseCreated"
	case handshakeResponseConsumed:
		return "handshakeResponseConsumed"
	default:
		return fmt.Sprintf("Handshake(UNKNOWN:%d)", int(hs))
	}
}

const (
	NoiseConstruction    = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s"
	PQCNoiseConstruction = "pqIK_PQKEM_ChaChaPoly_BLAKE2s"
	WGIdentifier         = "WireGuard v1 zx2c4 Jason@zx2c4.com"
	PQCWGIdentifier      = "tbd"
	WGLabelMAC1          = "mac1----"
	WGLabelCookie        = "cookie--"
)

const (
	MessageInitiationType    = 1
	MessageResponseType      = 2
	MessageCookieReplyType   = 3
	MessageTransportType     = 4
	MessagePQCInitiationType = 5
	MessagePQCResponseType   = 6
)

const (
	MessageInitiationSize             = 148                                                                                                                 // size of handshake initiation message
	MessageResponseSize               = 92                                                                                                                  // size of response message
	MessageCookieReplySize            = 64                                                                                                                  // size of cookie reply message
	MessageTransportHeaderSize        = 16                                                                                                                  // size of data preceding content in transport message
	MessageEncapsulatingTransportSize = 8                                                                                                                   // size of optional, free (for use by conn.Bind.Send()) space preceding the transport header
	MessageTransportSize              = MessageTransportHeaderSize + poly1305.TagSize                                                                       // size of empty transport
	MessageKeepaliveSize              = MessageTransportSize                                                                                                // size of keepalive
	MessageHandshakeSize              = MessageInitiationSize                                                                                               // size of largest handshake related message
	MessagePQCInitiationSize          = MessageInitiationSize + NoisePQCCiphertextSize + NoisePQCPublicKeySize + (NoisePQCPublicKeySize + poly1305.TagSize) // Standard initiation (148) + CTss(1088) + EI(1184) + EncSI(1200) = 3620 bytes
	MessagePQCResponseSize            = MessageResponseSize + NoisePQCCiphertextSize + NoisePQCCiphertextSize                                               // Standard response (92) + ER(1184) + CTee(1088) + CTse(1088) = 2268 bytes
)

const (
	MessageTransportOffsetReceiver = 4
	MessageTransportOffsetCounter  = 8
	MessageTransportOffsetContent  = 16
)

/* Type is an 8-bit field, followed by 3 nul bytes,
 * by marshalling the messages in little-endian byteorder
 * we can treat these as a 32-bit unsigned int (for now)
 *
 */

type MessageInitiation struct {
	Type      uint32
	Sender    uint32
	Ephemeral NoisePublicKey
	Static    [NoisePublicKeySize + poly1305.TagSize]byte
	Timestamp [tai64n.TimestampSize + poly1305.TagSize]byte
	MAC1      [blake2s.Size128]byte
	MAC2      [blake2s.Size128]byte
}

type MessageResponse struct {
	Type      uint32
	Sender    uint32
	Receiver  uint32
	Ephemeral NoisePublicKey
	Empty     [poly1305.TagSize]byte
	MAC1      [blake2s.Size128]byte
	MAC2      [blake2s.Size128]byte
}

type MessageTransport struct {
	Type     uint32
	Receiver uint32
	Counter  uint64
	Content  []byte
}

type MessageCookieReply struct {
	Type     uint32
	Receiver uint32
	Nonce    [chacha20poly1305.NonceSizeX]byte
	Cookie   [blake2s.Size128 + poly1305.TagSize]byte
}

// MessagePQCInitiation extends the standard MessageInitiation with PQC fields
// Structure: [Standard Initiation Fields] + [PQC Extension Fields]
// This allows hybrid X25519+ML-KEM-768 security
type MessagePQCInitiation struct {
	// Standard WireGuard initiation fields (reused for X25519 handshake)
	Type      uint32
	Sender    uint32
	Ephemeral NoisePublicKey                                // X25519 ephemeral public key (32 bytes)
	Static    [NoisePublicKeySize + poly1305.TagSize]byte   // Encrypted X25519 static key (32 + 16 bytes)
	Timestamp [tai64n.TimestampSize + poly1305.TagSize]byte // Encrypted timestamp (12 + 16 bytes)
	MAC1      [blake2s.Size128]byte                         // MAC1 for standard part (16 bytes)
	MAC2      [blake2s.Size128]byte                         // MAC2 for standard part (16 bytes)

	// PQC extension fields (appended after standard message)
	CTss  NoisePQCCiphertext                             // ML-KEM-768 ciphertext from skem (1088 bytes)
	EI    NoisePQCPublicKey                              // ML-KEM-768 ephemeral public key (1184 bytes)
	EncSI [NoisePQCPublicKeySize + poly1305.TagSize]byte // Encrypted ML-KEM-768 static key (1184 + 16 bytes)
}

// MessagePQCResponse extends the standard MessageResponse with PQC fields
// Structure: [Standard Response Fields] + [PQC Extension Fields]
// This allows hybrid X25519+ML-KEM-768 security
type MessagePQCResponse struct {
	// Standard WireGuard response fields (reused for X25519 handshake)
	Type      uint32
	Sender    uint32
	Receiver  uint32
	Ephemeral NoisePublicKey         // X25519 ephemeral public key (32 bytes)
	Empty     [poly1305.TagSize]byte // Encrypted empty (16 bytes)
	MAC1      [blake2s.Size128]byte  // MAC1 for standard part (16 bytes)
	MAC2      [blake2s.Size128]byte  // MAC2 for standard part (16 bytes)

	// PQC extension fields (appended after standard message)
	CTee NoisePQCCiphertext // ML-KEM-768 ciphertext from ekem (1088 bytes)
	CTse NoisePQCCiphertext // ML-KEM-768 ciphertext from skem (1088 bytes)
}

var errMessageLengthMismatch = errors.New("message length mismatch")

func (msg *MessageInitiation) unmarshal(b []byte) error {
	if len(b) != MessageInitiationSize {
		return errMessageLengthMismatch
	}

	msg.Type = binary.LittleEndian.Uint32(b)
	msg.Sender = binary.LittleEndian.Uint32(b[4:])
	copy(msg.Ephemeral[:], b[8:])
	copy(msg.Static[:], b[8+len(msg.Ephemeral):])
	copy(msg.Timestamp[:], b[8+len(msg.Ephemeral)+len(msg.Static):])
	copy(msg.MAC1[:], b[8+len(msg.Ephemeral)+len(msg.Static)+len(msg.Timestamp):])
	copy(msg.MAC2[:], b[8+len(msg.Ephemeral)+len(msg.Static)+len(msg.Timestamp)+len(msg.MAC1):])

	return nil
}

func (msg *MessageInitiation) marshal(b []byte) error {
	if len(b) != MessageInitiationSize {
		return errMessageLengthMismatch
	}

	binary.LittleEndian.PutUint32(b, msg.Type)
	binary.LittleEndian.PutUint32(b[4:], msg.Sender)
	copy(b[8:], msg.Ephemeral[:])
	copy(b[8+len(msg.Ephemeral):], msg.Static[:])
	copy(b[8+len(msg.Ephemeral)+len(msg.Static):], msg.Timestamp[:])
	copy(b[8+len(msg.Ephemeral)+len(msg.Static)+len(msg.Timestamp):], msg.MAC1[:])
	copy(b[8+len(msg.Ephemeral)+len(msg.Static)+len(msg.Timestamp)+len(msg.MAC1):], msg.MAC2[:])

	return nil
}

func (msg *MessageResponse) unmarshal(b []byte) error {
	if len(b) != MessageResponseSize {
		return errMessageLengthMismatch
	}

	msg.Type = binary.LittleEndian.Uint32(b)
	msg.Sender = binary.LittleEndian.Uint32(b[4:])
	msg.Receiver = binary.LittleEndian.Uint32(b[8:])
	copy(msg.Ephemeral[:], b[12:])
	copy(msg.Empty[:], b[12+len(msg.Ephemeral):])
	copy(msg.MAC1[:], b[12+len(msg.Ephemeral)+len(msg.Empty):])
	copy(msg.MAC2[:], b[12+len(msg.Ephemeral)+len(msg.Empty)+len(msg.MAC1):])

	return nil
}

func (msg *MessageResponse) marshal(b []byte) error {
	if len(b) != MessageResponseSize {
		return errMessageLengthMismatch
	}

	binary.LittleEndian.PutUint32(b, msg.Type)
	binary.LittleEndian.PutUint32(b[4:], msg.Sender)
	binary.LittleEndian.PutUint32(b[8:], msg.Receiver)
	copy(b[12:], msg.Ephemeral[:])
	copy(b[12+len(msg.Ephemeral):], msg.Empty[:])
	copy(b[12+len(msg.Ephemeral)+len(msg.Empty):], msg.MAC1[:])
	copy(b[12+len(msg.Ephemeral)+len(msg.Empty)+len(msg.MAC1):], msg.MAC2[:])

	return nil
}

func (msg *MessageCookieReply) unmarshal(b []byte) error {
	if len(b) != MessageCookieReplySize {
		return errMessageLengthMismatch
	}

	msg.Type = binary.LittleEndian.Uint32(b)
	msg.Receiver = binary.LittleEndian.Uint32(b[4:])
	copy(msg.Nonce[:], b[8:])
	copy(msg.Cookie[:], b[8+len(msg.Nonce):])

	return nil
}

func (msg *MessageCookieReply) marshal(b []byte) error {
	if len(b) != MessageCookieReplySize {
		return errMessageLengthMismatch
	}

	binary.LittleEndian.PutUint32(b, msg.Type)
	binary.LittleEndian.PutUint32(b[4:], msg.Receiver)
	copy(b[8:], msg.Nonce[:])
	copy(b[8+len(msg.Nonce):], msg.Cookie[:])

	return nil
}

func (msg *MessagePQCInitiation) unmarshal(b []byte) error {
	if len(b) != MessagePQCInitiationSize {
		return errMessageLengthMismatch
	}

	// Unmarshal standard WireGuard initiation fields (first 148 bytes)
	msg.Type = binary.LittleEndian.Uint32(b)
	msg.Sender = binary.LittleEndian.Uint32(b[4:])
	copy(msg.Ephemeral[:], b[8:])
	copy(msg.Static[:], b[40:])
	copy(msg.Timestamp[:], b[88:])

	// Unmarshal PQC extension fields (after standard 148 bytes)
	offset := 116
	copy(msg.CTss[:], b[offset:])
	offset += len(msg.CTss)
	copy(msg.EI[:], b[offset:])
	offset += len(msg.EI)
	copy(msg.EncSI[:], b[offset:])

	offset += len(msg.EncSI)

	copy(msg.MAC1[:], b[offset:])
	copy(msg.MAC2[:], b[offset+16:])

	return nil
}

func (msg *MessagePQCInitiation) marshal(b []byte) error {
	if len(b) != MessagePQCInitiationSize {
		return errMessageLengthMismatch
	}

	// Marshal standard WireGuard initiation fields (first 148 bytes)
	binary.LittleEndian.PutUint32(b, msg.Type)
	binary.LittleEndian.PutUint32(b[4:], msg.Sender)
	copy(b[8:], msg.Ephemeral[:])
	copy(b[40:], msg.Static[:])
	copy(b[88:], msg.Timestamp[:])

	// Marshal PQC extension fields (after standard 148 bytes)
	offset := 116
	copy(b[offset:], msg.CTss[:])
	offset += len(msg.CTss)
	copy(b[offset:], msg.EI[:])
	offset += len(msg.EI)
	copy(b[offset:], msg.EncSI[:])
	offset += len(msg.EncSI)

	copy(b[offset:], msg.MAC1[:])
	copy(b[offset+16:], msg.MAC2[:])

	return nil
}

func (msg *MessagePQCResponse) unmarshal(b []byte) error {
	if len(b) != MessagePQCResponseSize {
		return errMessageLengthMismatch
	}

	// Unmarshal standard WireGuard response fields (first 92 bytes)
	msg.Type = binary.LittleEndian.Uint32(b)
	msg.Sender = binary.LittleEndian.Uint32(b[4:])
	msg.Receiver = binary.LittleEndian.Uint32(b[8:])
	copy(msg.Ephemeral[:], b[12:])
	copy(msg.Empty[:], b[44:])

	// Unmarshal PQC extension fields (after standard 92 bytes)
	offset := 60
	copy(msg.CTee[:], b[offset:])
	offset += len(msg.CTee)
	copy(msg.CTse[:], b[offset:])
	offset += len(msg.CTse)

	copy(msg.MAC1[:], b[offset:])
	copy(msg.MAC2[:], b[offset+16:])

	return nil
}

func (msg *MessagePQCResponse) marshal(b []byte) error {
	if len(b) != MessagePQCResponseSize {
		return errMessageLengthMismatch
	}

	// Marshal standard WireGuard response fields (first 92 bytes)
	binary.LittleEndian.PutUint32(b, msg.Type)
	binary.LittleEndian.PutUint32(b[4:], msg.Sender)
	binary.LittleEndian.PutUint32(b[8:], msg.Receiver)
	copy(b[12:], msg.Ephemeral[:])
	copy(b[44:], msg.Empty[:])

	// Marshal PQC extension fields (after standard 92 bytes)
	offset := 60
	copy(b[offset:], msg.CTee[:])
	offset += len(msg.CTee)
	copy(b[offset:], msg.CTse[:])
	offset += len(msg.CTse)

	copy(b[offset:], msg.MAC1[:])
	copy(b[offset+16:], msg.MAC2[:])

	return nil
}

type Handshake struct {
	state                     handshakeState
	mutex                     sync.RWMutex
	hash                      [blake2s.Size]byte       // hash value
	chainKey                  [blake2s.Size]byte       // chain key
	presharedKey              NoisePresharedKey        // psk
	pqcKey                    NoisePresharedKey        // PQC-derived key (or PQC ⊕ PSK if both set)
	localEphemeral            NoisePrivateKey          // ephemeral secret key
	localIndex                uint32                   // used to clear hash-table
	remoteIndex               uint32                   // index for sending
	remoteStatic              NoisePublicKey           // long term key, never changes, can be accessed without mutex
	remoteEphemeral           NoisePublicKey           // ephemeral public key
	precomputedStaticStatic   [NoisePublicKeySize]byte // precomputed shared secret
	lastTimestamp             tai64n.Timestamp
	lastInitiationConsumption time.Time
	lastSentHandshake         time.Time

	// PQC state
	hashPQC            [blake2s.Size]byte // hash value
	chainKeyPQC        [blake2s.Size]byte // chain key
	remotePQCStatic    NoisePQCPublicKey  // remote PQC public key
	localPQCEphemeral  NoisePQCSeed       // PQC ephemeral private key (for initiation)
	remotePQCEphemeral NoisePQCPublicKey  // remote PQC ephemeral key (stored during initiation consumption)
}

var (
	InitialChainKey   [blake2s.Size]byte
	InitialPQChainKey [blake2s.Size]byte
	InitialHash       [blake2s.Size]byte
	InitialPQCHash    [blake2s.Size]byte
	ZeroNonce         [chacha20poly1305.NonceSize]byte
)

func mixKey(dst, c *[blake2s.Size]byte, data []byte) {
	KDF1(dst, c[:], data)
}

func mixHash(dst, h *[blake2s.Size]byte, data []byte) {
	hash, _ := blake2s.New256(nil)
	hash.Write(h[:])
	hash.Write(data)
	hash.Sum(dst[:0])
	hash.Reset()
}

func (h *Handshake) Clear() {
	setZero(h.localEphemeral[:])
	setZero(h.remoteEphemeral[:])
	setZero(h.chainKey[:])
	setZero(h.hash[:])
	h.localIndex = 0
	h.state = handshakeZeroed
}

func (h *Handshake) mixHash(data []byte) {
	mixHash(&h.hash, &h.hash, data)
}

func (h *Handshake) mixKey(data []byte) {
	mixKey(&h.chainKey, &h.chainKey, data)
}

func (h *Handshake) mixPQCHash(data []byte) {
	mixHash(&h.hashPQC, &h.hashPQC, data)
}

func (h *Handshake) mixPQCKey(data []byte) {
	mixKey(&h.chainKeyPQC, &h.chainKeyPQC, data)
}

/* Do basic precomputations
 */
func init() {
	InitialChainKey = blake2s.Sum256([]byte(NoiseConstruction))
	InitialPQChainKey = blake2s.Sum256([]byte(PQCNoiseConstruction))
	mixHash(&InitialHash, &InitialChainKey, []byte(WGIdentifier))
	mixHash(&InitialPQCHash, &InitialPQChainKey, []byte(PQCWGIdentifier))
}

func (device *Device) CreateMessageInitiation(peer *Peer) (*MessageInitiation, error) {
	device.staticIdentity.RLock()
	defer device.staticIdentity.RUnlock()

	handshake := &peer.handshake
	handshake.mutex.Lock()
	defer handshake.mutex.Unlock()

	// create ephemeral key
	var err error
	handshake.hash = InitialHash
	handshake.chainKey = InitialChainKey
	handshake.localEphemeral, err = newPrivateKey()
	if err != nil {
		return nil, err
	}

	handshake.mixHash(handshake.remoteStatic[:])

	msg := MessageInitiation{
		Type:      MessageInitiationType,
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

	// assign index
	device.indexTable.Delete(handshake.localIndex)
	msg.Sender, err = device.indexTable.NewIndexForHandshake(peer, handshake)
	if err != nil {
		return nil, err
	}
	handshake.localIndex = msg.Sender

	handshake.mixHash(msg.Timestamp[:])
	handshake.state = handshakeInitiationCreated
	return &msg, nil
}

func (device *Device) ConsumeMessageInitiation(msg *MessageInitiation, endpoint conn.Endpoint) *Peer {
	var (
		hash     [blake2s.Size]byte
		chainKey [blake2s.Size]byte
	)

	if msg.Type != MessageInitiationType {
		return nil
	}

	device.staticIdentity.RLock()
	defer device.staticIdentity.RUnlock()

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

	// lookup peer

	initEP, ok := endpoint.(conn.InitiationAwareEndpoint)
	if ok {
		initEP.InitiationMessagePublicKey(peerPK)
	}

	peer := device.LookupPeer(peerPK)
	if peer == nil || !peer.isRunning.Load() {
		return nil
	}

	handshake := &peer.handshake

	// verify identity

	var timestamp tai64n.Timestamp

	handshake.mutex.RLock()

	if isZero(handshake.precomputedStaticStatic[:]) {
		handshake.mutex.RUnlock()
		return nil
	}
	KDF2(
		&chainKey,
		&key,
		chainKey[:],
		handshake.precomputedStaticStatic[:],
	)
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
		device.log.Verbosef("%v - ConsumeMessageInitiation: handshake replay @ %v", peer, timestamp)
		return nil
	}
	if flood {
		device.log.Verbosef("%v - ConsumeMessageInitiation: handshake flood", peer)
		return nil
	}

	// update handshake state

	handshake.mutex.Lock()

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

func (device *Device) CreateMessageResponse(peer *Peer) (*MessageResponse, error) {
	handshake := &peer.handshake
	handshake.mutex.Lock()
	defer handshake.mutex.Unlock()

	if handshake.state != handshakeInitiationConsumed {
		return nil, errors.New("handshake initiation must be consumed first")
	}

	// assign index

	var err error
	device.indexTable.Delete(handshake.localIndex)
	handshake.localIndex, err = device.indexTable.NewIndexForHandshake(peer, handshake)
	if err != nil {
		return nil, err
	}

	var msg MessageResponse
	msg.Type = MessageResponseType
	msg.Sender = handshake.localIndex
	msg.Receiver = handshake.remoteIndex

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

	// add preshared key

	var tau [blake2s.Size]byte
	var key [chacha20poly1305.KeySize]byte

	// If either is unset (all zeros), XOR with zeros is a no-op
	var combinedKey NoisePresharedKey
	for i := range combinedKey {
		combinedKey[i] = handshake.presharedKey[i] ^ handshake.pqcKey[i]
	}

	KDF3(
		&handshake.chainKey,
		&tau,
		&key,
		handshake.chainKey[:],
		combinedKey[:],
	)

	handshake.mixHash(tau[:])

	aead, _ := chacha20poly1305.New(key[:])
	aead.Seal(msg.Empty[:0], ZeroNonce[:], nil, handshake.hash[:])
	handshake.mixHash(msg.Empty[:])

	handshake.state = handshakeResponseCreated

	return &msg, nil
}

func (device *Device) ConsumeMessageResponse(msg *MessageResponse) *Peer {
	if msg.Type != MessageResponseType {
		return nil
	}

	// lookup handshake by receiver

	lookup := device.indexTable.Lookup(msg.Receiver)
	handshake := lookup.handshake
	if handshake == nil {
		return nil
	}

	var (
		hash     [blake2s.Size]byte
		chainKey [blake2s.Size]byte
	)

	ok := func() bool {
		// lock handshake state

		handshake.mutex.RLock()
		defer handshake.mutex.RUnlock()

		if handshake.state != handshakeInitiationCreated {
			return false
		}

		// lock private key for reading

		device.staticIdentity.RLock()
		defer device.staticIdentity.RUnlock()

		// finish 3-way DH

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

		// add preshared key (psk)
		// If either is unset (all zeros), XOR with zeros is a no-op
		var combinedKey NoisePresharedKey
		for i := range combinedKey {
			combinedKey[i] = handshake.presharedKey[i] ^ handshake.pqcKey[i]
		}

		var tau [blake2s.Size]byte
		var key [chacha20poly1305.KeySize]byte
		KDF3(
			&chainKey,
			&tau,
			&key,
			chainKey[:],
			combinedKey[:], // TODO aparcar zero
		)
		mixHash(&hash, &hash, tau[:])

		// authenticate transcript

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

	// update handshake state

	handshake.mutex.Lock()

	handshake.hash = hash
	handshake.chainKey = chainKey
	handshake.remoteIndex = msg.Sender
	handshake.state = handshakeResponseConsumed

	handshake.mutex.Unlock()

	setZero(hash[:])
	setZero(chainKey[:])

	return lookup.peer
}

func (device *Device) CreateMessagePQCInitiation(peer *Peer) (*MessagePQCInitiation, error) {
	device.staticIdentity.RLock()
	defer device.staticIdentity.RUnlock()

	handshake := &peer.handshake
	handshake.mutex.Lock()
	defer handshake.mutex.Unlock()

	// === PART 1: Standard X25519 handshake initiation ===
	// This creates the standard WireGuard fields (Ephemeral, Static, Timestamp)

	// create ephemeral key
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
	// Append ML-KEM-768 fields for hybrid security using BLAKE2s

	handshake.chainKeyPQC = InitialPQChainKey
	handshake.hashPQC = InitialPQCHash

	localPQCStatic := device.staticIdentity.pqcPublicKey

	// Pre-message: <- s (responder's static key is known)
	handshake.mixPQCHash(handshake.remotePQCStatic[:])

	// Bind timestamp to PQC transcript for hybrid protection
	// This ensures an attacker must break both X25519 AND ML-KEM-768 to forge timestamps
	handshake.mixPQCHash(timestamp[:])

	// -> skem (encapsulate to responder's static key)
	ssSS, ctSS, err := PQCEncapsulate(handshake.remotePQCStatic)
	if err != nil {
		return nil, fmt.Errorf("ss encapsulation failed: %w", err)
	}
	msg.CTss = ctSS
	handshake.mixPQCHash(ctSS[:])

	// Generate PQC ephemeral key
	eiPub, eiSk, err := PQCGenerateKeyPair()
	if err != nil {
		return nil, fmt.Errorf("ephemeral key generation failed: %w", err)
	}
	handshake.localPQCEphemeral = eiSk
	msg.EI = eiPub

	// -> e
	handshake.mixPQCHash(eiPub[:])

	// -> s (encrypt initiator static public key)
	// Use KDF2 to update chain key with shared secret AND derive encryption key
	var encKey [chacha20poly1305.KeySize]byte
	KDF2(
		&handshake.chainKeyPQC,
		&encKey,
		handshake.chainKeyPQC[:],
		ssSS[:],
	)
	aead, _ = chacha20poly1305.New(encKey[:])
	aead.Seal(msg.EncSI[:0], ZeroNonce[:], localPQCStatic[:], handshake.hashPQC[:])
	handshake.mixPQCHash(msg.EncSI[:])

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

	// === PART 1: Process standard X25519 handshake initiation ===
	// This validates the standard WireGuard fields

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
	KDF2(
		&chainKey,
		&key,
		chainKey[:],
		handshake.precomputedStaticStatic[:],
	)
	aead, _ = chacha20poly1305.New(key[:])
	_, err = aead.Open(timestamp[:0], ZeroNonce[:], msg.Timestamp[:], hash[:])
	if err != nil {
		handshake.mutex.RUnlock()
		return nil
	}
	mixHash(&hash, &hash, msg.Timestamp[:])

	// TODO aparcar move after PQC validation
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
	// This validates the ML-KEM-768 fields for hybrid security using BLAKE2s

	localPQCStatic := device.staticIdentity.pqcPublicKey
	localPQCPrivateSeed := device.staticIdentity.pqcSeed

	// Update handshake state - we need the lock for PQC processing
	handshake.mutex.Lock()

	// Standard X25519 state
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

	// Initialize PQC state
	handshake.hashPQC = InitialPQCHash
	handshake.chainKeyPQC = InitialPQChainKey

	// Pre-message: <- s (our static key)
	handshake.mixPQCHash(localPQCStatic[:])

	// Bind timestamp to PQC transcript for hybrid protection
	handshake.mixPQCHash(timestamp[:])

	// <- skem (decapsulate with our static key)
	ssSS, err := PQCDecapsulate(localPQCPrivateSeed, msg.CTss)
	if err != nil {
		handshake.mutex.Unlock()
		device.log.Errorf("PQC ss decapsulation failed: %v", err)
		return nil
	}
	handshake.mixPQCHash(msg.CTss[:])

	// <- e (initiator's ephemeral)
	handshake.mixPQCHash(msg.EI[:])

	// <- s (decrypt initiator static public key)
	// Use KDF2 to update chain key with shared secret AND derive decryption key
	var encKey [chacha20poly1305.KeySize]byte
	KDF2(&handshake.chainKeyPQC, &encKey, handshake.chainKeyPQC[:], ssSS[:])
	aead, _ = chacha20poly1305.New(encKey[:])
	var initiatorStaticPub NoisePQCPublicKey
	_, err = aead.Open(initiatorStaticPub[:0], ZeroNonce[:], msg.EncSI[:], handshake.hashPQC[:])
	if err != nil {
		handshake.mutex.Unlock()
		device.log.Errorf("PQC failed to decrypt initiator static key: %v", err)
		return nil
	}
	handshake.mixPQCHash(msg.EncSI[:])

	// Verify PQC key matches the peer we found via X25519
	if !bytes.Equal(initiatorStaticPub[:], handshake.remotePQCStatic[:]) {
		handshake.mutex.Unlock()
		device.log.Errorf("%v - ConsumeMessagePQCInitiation: PQC key mismatch!", peer)
		return nil
	}

	handshake.remotePQCEphemeral = msg.EI

	handshake.state = handshakeInitiationConsumed
	handshake.mutex.Unlock()

	setZero(hash[:])
	setZero(chainKey[:])

	return peer
}

func (device *Device) CreateMessagePQCResponse(peer *Peer) (*MessagePQCResponse, error) {
	handshake := &peer.handshake
	handshake.mutex.Lock()
	defer handshake.mutex.Unlock()

	if handshake.state != handshakeInitiationConsumed {
		return nil, errors.New("handshake initiation must be consumed first")
	}

	// === PART 1: Standard X25519 response ===

	// assign index
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

	// === PART 2: PQC extension fields using BLAKE2s ===

	// <- ekem (encapsulate to initiator's ephemeral key)
	ssEE, ctEE, err := PQCEncapsulate(handshake.remotePQCEphemeral)
	if err != nil {
		return nil, fmt.Errorf("ee encapsulation failed: %w", err)
	}
	msg.CTee = ctEE
	handshake.mixPQCHash(ctEE[:])
	handshake.mixPQCKey(ssEE[:])

	// <- skem (encapsulate to initiator's static key)
	ssSE, ctSE, err := PQCEncapsulate(handshake.remotePQCStatic)
	if err != nil {
		return nil, fmt.Errorf("se encapsulation failed: %w", err)
	}
	msg.CTse = ctSE
	handshake.mixPQCHash(ctSE[:])
	handshake.mixPQCKey(ssSE[:])

	// Derive PQC key from final PQC chain key
	var pqcKey [blake2s.Size]byte
	KDF1(&pqcKey, handshake.chainKeyPQC[:], nil)
	copy(handshake.pqcKey[:], pqcKey[:])

	// === PART 3: Combine with preshared key ===
	// Add combined preshared key (user PSK XOR PQC key)

	var tau [blake2s.Size]byte
	var key [chacha20poly1305.KeySize]byte

	// Combine PSK and PQC key via XOR
	var combinedKey NoisePresharedKey
	for i := range combinedKey {
		combinedKey[i] = handshake.presharedKey[i] ^ handshake.pqcKey[i]
	}

	KDF3(
		&handshake.chainKey,
		&tau,
		&key,
		handshake.chainKey[:],
		combinedKey[:],
	)

	handshake.mixHash(tau[:])

	aead, _ := chacha20poly1305.New(key[:])
	aead.Seal(msg.Empty[:0], ZeroNonce[:], nil, handshake.hash[:])
	handshake.mixHash(msg.Empty[:])

	handshake.state = handshakeResponseCreated
	return msg, nil
}

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
		// lock handshake state
		handshake.mutex.RLock()
		defer handshake.mutex.RUnlock()

		if handshake.state != handshakeInitiationCreated {
			return false
		}

		// lock private key for reading
		device.staticIdentity.RLock()
		defer device.staticIdentity.RUnlock()

		// === PART 1: Process standard X25519 response ===

		// finish 3-way DH
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

		// === PART 2: Process PQC extension fields using BLAKE2s ===

		localPQCPrivateSeed := device.staticIdentity.pqcSeed

		// Copy PQC state for local processing (we have RLock, can't modify handshake directly)
		hashPQC := handshake.hashPQC
		chainKeyPQC := handshake.chainKeyPQC

		// <- ekem (decapsulate with our ephemeral key)
		mixHash(&hashPQC, &hashPQC, msg.CTee[:])
		ssEE, err := PQCDecapsulate(handshake.localPQCEphemeral, msg.CTee)
		if err != nil {
			return false
		}
		mixKey(&chainKeyPQC, &chainKeyPQC, ssEE[:])

		// <- skem (decapsulate with our static key)
		mixHash(&hashPQC, &hashPQC, msg.CTse[:])
		ssSE, err := PQCDecapsulate(localPQCPrivateSeed, msg.CTse)
		if err != nil {
			return false
		}
		mixKey(&chainKeyPQC, &chainKeyPQC, ssSE[:])

		// Derive PQC key from final PQC chain key
		KDF1(&pqcKey, chainKeyPQC[:], nil)

		// === PART 3: Validate with combined preshared key ===
		// Combine preshared key (user PSK XOR PQC key)

		// Always XOR both keys to avoid timing attacks
		var combinedKey NoisePresharedKey
		for i := range combinedKey {
			combinedKey[i] = handshake.presharedKey[i] ^ pqcKey[i]
		}

		var tau [blake2s.Size]byte
		var key [chacha20poly1305.KeySize]byte
		KDF3(
			&chainKey,
			&tau,
			&key,
			chainKey[:],
			combinedKey[:],
		)
		mixHash(&hash, &hash, tau[:])

		// authenticate transcript
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

	// update handshake state
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

/* Derives a new keypair from the current handshake state
 *
 */
func (peer *Peer) BeginSymmetricSession() error {
	device := peer.device
	handshake := &peer.handshake
	handshake.mutex.Lock()
	defer handshake.mutex.Unlock()

	// derive keys

	var isInitiator bool
	var sendKey [chacha20poly1305.KeySize]byte
	var recvKey [chacha20poly1305.KeySize]byte

	if handshake.state == handshakeResponseConsumed {
		KDF2(
			&sendKey,
			&recvKey,
			handshake.chainKey[:],
			nil,
		)
		isInitiator = true
	} else if handshake.state == handshakeResponseCreated {
		KDF2(
			&recvKey,
			&sendKey,
			handshake.chainKey[:],
			nil,
		)
		isInitiator = false
	} else {
		return fmt.Errorf("invalid state for keypair derivation: %v", handshake.state)
	}

	// zero handshake

	setZero(handshake.chainKey[:])
	setZero(handshake.hash[:]) // Doesn't necessarily need to be zeroed. Could be used for something interesting down the line.
	setZero(handshake.localEphemeral[:])
	peer.handshake.state = handshakeZeroed

	// create AEAD instances

	keypair := new(Keypair)
	keypair.send, _ = chacha20poly1305.New(sendKey[:])
	keypair.receive, _ = chacha20poly1305.New(recvKey[:])

	setZero(sendKey[:])
	setZero(recvKey[:])

	keypair.created = time.Now()
	keypair.replayFilter.Reset()
	keypair.isInitiator = isInitiator
	keypair.localIndex = peer.handshake.localIndex
	keypair.remoteIndex = peer.handshake.remoteIndex

	// remap index

	device.indexTable.SwapIndexForKeypair(handshake.localIndex, keypair)
	handshake.localIndex = 0

	// rotate key pairs

	keypairs := &peer.keypairs
	keypairs.Lock()
	defer keypairs.Unlock()

	previous := keypairs.previous
	next := keypairs.next.Load()
	current := keypairs.current

	if isInitiator {
		if next != nil {
			keypairs.next.Store(nil)
			keypairs.previous = next
			device.DeleteKeypair(current)
		} else {
			keypairs.previous = current
		}
		device.DeleteKeypair(previous)
		keypairs.current = keypair
	} else {
		keypairs.next.Store(keypair)
		device.DeleteKeypair(next)
		keypairs.previous = nil
		device.DeleteKeypair(previous)
	}

	return nil
}

func (peer *Peer) ReceivedWithKeypair(receivedKeypair *Keypair) bool {
	keypairs := &peer.keypairs

	if keypairs.next.Load() != receivedKeypair {
		return false
	}
	keypairs.Lock()
	defer keypairs.Unlock()
	if keypairs.next.Load() != receivedKeypair {
		return false
	}
	old := keypairs.previous
	keypairs.previous = keypairs.current
	peer.device.DeleteKeypair(old)
	keypairs.current = keypairs.next.Load()
	keypairs.next.Store(nil)
	return true
}
