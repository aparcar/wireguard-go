/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"testing"

	"github.com/tailscale/wireguard-go/conn"
	"github.com/tailscale/wireguard-go/tun/tuntest"
)

func TestCurveWrappers(t *testing.T) {
	sk1, err := newPrivateKey()
	assertNil(t, err)

	sk2, err := newPrivateKey()
	assertNil(t, err)

	pk1 := sk1.publicKey()
	pk2 := sk2.publicKey()

	ss1, err1 := sk1.sharedSecret(pk2)
	ss2, err2 := sk2.sharedSecret(pk1)

	if ss1 != ss2 || err1 != nil || err2 != nil {
		t.Fatal("Failed to compute shared secet")
	}
}

func randDevice(t *testing.T) *Device {
	sk, err := newPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	tun := tuntest.NewChannelTUN()
	logger := NewLogger(LogLevelError, "")
	device := NewDevice(tun.TUN(), conn.NewDefaultBind(), logger)
	device.SetPrivateKey(sk)
	return device
}

func assertNil(t *testing.T, err error) {
	if err != nil {
		t.Fatal(err)
	}
}

func assertEqual(t *testing.T, a, b []byte) {
	if !bytes.Equal(a, b) {
		t.Fatal(a, "!=", b)
	}
}

type initAwareEP struct {
	calledWith *[32]byte
}

var _ conn.Endpoint = (*initAwareEP)(nil)
var _ conn.InitiationAwareEndpoint = (*initAwareEP)(nil)

func (i *initAwareEP) ClearSrc()           {}
func (i *initAwareEP) SrcToString() string { return "" }
func (i *initAwareEP) DstToString() string { return "" }
func (i *initAwareEP) DstToBytes() []byte  { return nil }
func (i *initAwareEP) DstIP() netip.Addr   { return netip.Addr{} }
func (i *initAwareEP) SrcIP() netip.Addr   { return netip.Addr{} }

func (i *initAwareEP) InitiationMessagePublicKey(peerPublicKey [32]byte) {
	calledWith := [32]byte{}
	copy(calledWith[:], peerPublicKey[:])
	i.calledWith = &calledWith
}

func randPQCDevice(t *testing.T) *Device {
	device := randDevice(t)
	// Generate and set PQC keys
	_, seed, err := PQCGenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	err = device.SetPQCSeed(seed)
	if err != nil {
		t.Fatal(err)
	}
	return device
}

func TestNoisePQCHandshake(t *testing.T) {
	dev1 := randPQCDevice(t)
	dev2 := randPQCDevice(t)

	defer dev1.Close()
	defer dev2.Close()

	// peer1 is on dev2, representing dev1
	// peer2 is on dev1, representing dev2
	peer1, err := dev2.NewPeer(dev1.staticIdentity.privateKey.publicKey())
	if err != nil {
		t.Fatal(err)
	}
	peer2, err := dev1.NewPeer(dev2.staticIdentity.privateKey.publicKey())
	if err != nil {
		t.Fatal(err)
	}

	// Set PQC public keys for peers
	// peer1 (on dev2) needs dev1's PQC public key
	peer1.handshake.mutex.Lock()
	peer1.handshake.remotePQCStatic = dev1.staticIdentity.pqcPublicKey
	peer1.handshake.mutex.Unlock()

	// peer2 (on dev1) needs dev2's PQC public key
	peer2.handshake.mutex.Lock()
	peer2.handshake.remotePQCStatic = dev2.staticIdentity.pqcPublicKey
	peer2.handshake.mutex.Unlock()

	peer1.Start()
	peer2.Start()

	/* simulate PQC handshake */
	// dev1 initiates to dev2 via peer2

	// PQC initiation message
	t.Log("exchange PQC initiation message")

	msg1, err := dev1.CreateMessagePQCInitiation(peer2)
	if err != nil {
		t.Fatal("failed to create PQC initiation:", err)
	}

	if msg1.Type != MessagePQCInitiationType {
		t.Fatalf("wrong message type: got %d, want %d", msg1.Type, MessagePQCInitiationType)
	}

	initEP := &initAwareEP{}
	peerFromInit := dev2.ConsumeMessagePQCInitiation(msg1, initEP)
	if peerFromInit == nil {
		t.Fatal("PQC handshake failed at initiation message")
	}

	// ConsumeMessagePQCInitiation should return peer1 (the peer on dev2 that represents dev1)
	if peerFromInit != peer1 {
		t.Fatalf("ConsumeMessagePQCInitiation returned wrong peer: got %p, want %p", peerFromInit, peer1)
	}

	// After initiation, PQC chain keys should match between initiator and responder
	assertEqual(
		t,
		peer1.handshake.chainKeyPQC[:],
		peer2.handshake.chainKeyPQC[:],
	)

	assertEqual(
		t,
		peer1.handshake.hashPQC[:],
		peer2.handshake.hashPQC[:],
	)

	// PQC response message
	t.Log("exchange PQC response message")

	msg2, err := dev2.CreateMessagePQCResponse(peer1)
	if err != nil {
		t.Fatal("failed to create PQC response:", err)
	}

	if msg2.Type != MessagePQCResponseType {
		t.Fatalf("wrong message type: got %d, want %d", msg2.Type, MessagePQCResponseType)
	}

	peerFromResp := dev1.ConsumeMessagePQCResponse(msg2)
	if peerFromResp == nil {
		t.Fatal("PQC handshake failed at response message")
	}

	// After response, the derived PQC keys should match
	assertEqual(
		t,
		peer1.handshake.pqcKey[:],
		peer2.handshake.pqcKey[:],
	)

	// Also verify the final chain keys match (for session derivation)
	assertEqual(
		t,
		peer1.handshake.chainKey[:],
		peer2.handshake.chainKey[:],
	)

	// Derive key pairs
	t.Log("deriving keys")

	err = peer1.BeginSymmetricSession()
	if err != nil {
		t.Fatal("failed to derive keypair for peer 1:", err)
	}

	err = peer2.BeginSymmetricSession()
	if err != nil {
		t.Fatal("failed to derive keypair for peer 2:", err)
	}

	key1 := peer1.keypairs.next.Load()
	key2 := peer2.keypairs.current

	if key1 == nil {
		t.Fatal("peer1 keypairs.next is nil")
	}
	if key2 == nil {
		t.Fatal("peer2 keypairs.current is nil")
	}

	// Test encryption/decryption to verify keys match
	t.Log("test key pairs")

	func() {
		testMsg := []byte("pqc wireguard test message 1")
		var err error
		var out []byte
		var nonce [12]byte
		out = key1.send.Seal(out, nonce[:], testMsg, nil)
		out, err = key2.receive.Open(out[:0], nonce[:], out, nil)
		assertNil(t, err)
		assertEqual(t, out, testMsg)
	}()

	func() {
		testMsg := []byte("pqc wireguard test message 2")
		var err error
		var out []byte
		var nonce [12]byte
		out = key2.send.Seal(out, nonce[:], testMsg, nil)
		out, err = key1.receive.Open(out[:0], nonce[:], out, nil)
		assertNil(t, err)
		assertEqual(t, out, testMsg)
	}()

	t.Log("PQC handshake completed successfully - keys match!")
}

func TestNoiseHandshake(t *testing.T) {
	dev1 := randDevice(t)
	dev2 := randDevice(t)

	defer dev1.Close()
	defer dev2.Close()

	peer1, err := dev2.NewPeer(dev1.staticIdentity.privateKey.publicKey())
	if err != nil {
		t.Fatal(err)
	}
	peer2, err := dev1.NewPeer(dev2.staticIdentity.privateKey.publicKey())
	if err != nil {
		t.Fatal(err)
	}
	peer1.Start()
	peer2.Start()

	assertEqual(
		t,
		peer1.handshake.precomputedStaticStatic[:],
		peer2.handshake.precomputedStaticStatic[:],
	)

	/* simulate handshake */

	// initiation message

	t.Log("exchange initiation message")

	msg1, err := dev1.CreateMessageInitiation(peer2)
	assertNil(t, err)

	packet := make([]byte, 0, 256)
	writer := bytes.NewBuffer(packet)
	err = binary.Write(writer, binary.LittleEndian, msg1)
	assertNil(t, err)
	initEP := &initAwareEP{}
	peer := dev2.ConsumeMessageInitiation(msg1, initEP)
	if peer == nil {
		t.Fatal("handshake failed at initiation message")
	}
	if initEP.calledWith == nil {
		t.Fatal("initAwareEP never called")
	}
	if *initEP.calledWith != dev1.staticIdentity.publicKey {
		t.Fatal("initAwareEP called with unexpected public key")
	}

	assertEqual(
		t,
		peer1.handshake.chainKey[:],
		peer2.handshake.chainKey[:],
	)

	assertEqual(
		t,
		peer1.handshake.hash[:],
		peer2.handshake.hash[:],
	)

	// response message

	t.Log("exchange response message")

	msg2, err := dev2.CreateMessageResponse(peer1)
	assertNil(t, err)

	peer = dev1.ConsumeMessageResponse(msg2)
	if peer == nil {
		t.Fatal("handshake failed at response message")
	}

	assertEqual(
		t,
		peer1.handshake.chainKey[:],
		peer2.handshake.chainKey[:],
	)

	assertEqual(
		t,
		peer1.handshake.hash[:],
		peer2.handshake.hash[:],
	)

	// key pairs

	t.Log("deriving keys")

	err = peer1.BeginSymmetricSession()
	if err != nil {
		t.Fatal("failed to derive keypair for peer 1", err)
	}

	err = peer2.BeginSymmetricSession()
	if err != nil {
		t.Fatal("failed to derive keypair for peer 2", err)
	}

	key1 := peer1.keypairs.next.Load()
	key2 := peer2.keypairs.current

	// encrypting / decryption test

	t.Log("test key pairs")

	func() {
		testMsg := []byte("wireguard test message 1")
		var err error
		var out []byte
		var nonce [12]byte
		out = key1.send.Seal(out, nonce[:], testMsg, nil)
		out, err = key2.receive.Open(out[:0], nonce[:], out, nil)
		assertNil(t, err)
		assertEqual(t, out, testMsg)
	}()

	func() {
		testMsg := []byte("wireguard test message 2")
		var err error
		var out []byte
		var nonce [12]byte
		out = key2.send.Seal(out, nonce[:], testMsg, nil)
		out, err = key1.receive.Open(out[:0], nonce[:], out, nil)
		assertNil(t, err)
		assertEqual(t, out, testMsg)
	}()
}
