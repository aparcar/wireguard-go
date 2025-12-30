// SPDX-License-Identifier: MIT

package device

import (
	"bytes"
	"testing"

	"github.com/tailscale/wireguard-go/tai64n"
)

func TestPQCHandshakeMsg1Build(t *testing.T) {
	// Generate keys for initiator and responder
	initiatorPub, _, err := PQCGenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate initiator key: %v", err)
	}

	responderPub, _, err := PQCGenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate responder key: %v", err)
	}

	// Build Msg1
	timestamp := tai64n.Now()
	ctss, ei, encSI, eiPriv, ks, err := BuildPQCMsg1(initiatorPub, responderPub, timestamp)
	if err != nil {
		t.Fatalf("BuildPQCMsg1 failed: %v", err)
	}

	// Verify outputs
	if len(ctss) != NoisePQCCiphertextSize {
		t.Errorf("Expected ctss size %d, got %d", NoisePQCCiphertextSize, len(ctss))
	}

	if len(ei) != NoisePQCPublicKeySize {
		t.Errorf("Expected ei size %d, got %d", NoisePQCPublicKeySize, len(ei))
	}

	// encSI should be static key + poly1305 tag
	expectedEncSILen := NoisePQCPublicKeySize + 16
	if len(encSI) != expectedEncSILen {
		t.Errorf("Expected encSI size %d, got %d", expectedEncSILen, len(encSI))
	}

	if len(eiPriv) != NoisePQCSeedSize {
		t.Errorf("Expected eiPriv size %d, got %d", NoisePQCSeedSize, len(eiPriv))
	}

	if ks == nil {
		t.Errorf("Key schedule should not be nil")
	}
}

func TestPQCHandshakeMsg1ProcessAndMsg2Build(t *testing.T) {
	// Generate seeds and derive keys
	var initiatorSeed NoisePQCSeed
	for i := range initiatorSeed {
		initiatorSeed[i] = byte(i)
	}
	initiatorPub, _, err := PQCGenerateKeyPairFromSeed(initiatorSeed)
	if err != nil {
		t.Fatalf("Failed to generate initiator key: %v", err)
	}

	var responderSeed NoisePQCSeed
	for i := range responderSeed {
		responderSeed[i] = byte(i + 100)
	}
	responderPub, _, err := PQCGenerateKeyPairFromSeed(responderSeed)
	if err != nil {
		t.Fatalf("Failed to generate responder key: %v", err)
	}

	// Initiator builds Msg1
	timestamp := tai64n.Now()

	ctss, ei, encSI, _, _, err := BuildPQCMsg1(initiatorPub, responderPub, timestamp)
	if err != nil {
		t.Fatalf("BuildPQCMsg1 failed: %v", err)
	}

	// Responder processes Msg1
	recoveredInitiatorPub, ks2, err := ProcessPQCMsg1(responderPub, responderSeed, ctss, ei, encSI, timestamp)
	if err != nil {
		t.Fatalf("ProcessPQCMsg1 failed: %v", err)
	}

	// Verify the recovered initiator public key matches
	if recoveredInitiatorPub != initiatorPub {
		t.Errorf("Recovered initiator public key doesn't match original")
	}

	// Responder builds Msg2
	ctee, ctse, psk2, err := BuildPQCMsg2(ei, initiatorPub, ks2)
	if err != nil {
		t.Fatalf("BuildPQCMsg2 failed: %v", err)
	}

	// Verify outputs
	if len(ctee) != NoisePQCCiphertextSize {
		t.Errorf("Expected ctee size %d, got %d", NoisePQCCiphertextSize, len(ctee))
	}

	if len(ctse) != NoisePQCCiphertextSize {
		t.Errorf("Expected ctse size %d, got %d", NoisePQCCiphertextSize, len(ctse))
	}

	// Check PSK is not zero
	var zeroPSK [32]byte
	if psk2 == zeroPSK {
		t.Errorf("PSK should not be zero")
	}

	// Note: We can't easily test ProcessPQCMsg2 here because we don't have access to
	// the ephemeral private key from BuildPQCMsg1. This is tested in the complete handshake test.
	_ = psk2
}

func TestPQCHandshakeCompleteness(t *testing.T) {
	// Generate seeds and derive keys
	var initiatorSeed NoisePQCSeed
	for i := range initiatorSeed {
		initiatorSeed[i] = byte(i)
	}
	initiatorPub, _, err := PQCGenerateKeyPairFromSeed(initiatorSeed)
	if err != nil {
		t.Fatalf("Failed to generate initiator key: %v", err)
	}

	var responderSeed NoisePQCSeed
	for i := range responderSeed {
		responderSeed[i] = byte(i + 100)
	}
	responderPub, _, err := PQCGenerateKeyPairFromSeed(responderSeed)
	if err != nil {
		t.Fatalf("Failed to generate responder key: %v", err)
	}

	// Initiator: Build Msg1
	timestamp := tai64n.Now()
	ctss, ei, encSI, eiPriv, ks1, err := BuildPQCMsg1(initiatorPub, responderPub, timestamp)
	if err != nil {
		t.Fatalf("Initiator BuildPQCMsg1 failed: %v", err)
	}

	// Responder: Process Msg1
	recoveredInitiatorPub, ks2, err := ProcessPQCMsg1(responderPub, responderSeed, ctss, ei, encSI, timestamp)
	if err != nil {
		t.Fatalf("Responder ProcessPQCMsg1 failed: %v", err)
	}

	if recoveredInitiatorPub != initiatorPub {
		t.Errorf("Recovered initiator public key doesn't match")
	}

	// Responder: Build Msg2
	ctee, ctse, psk2, err := BuildPQCMsg2(ei, recoveredInitiatorPub, ks2)
	if err != nil {
		t.Fatalf("Responder BuildPQCMsg2 failed: %v", err)
	}

	// Initiator: Process Msg2
	psk1, err := ProcessPQCMsg2(eiPriv, initiatorSeed, ctee, ctse, ks1)
	if err != nil {
		t.Fatalf("Initiator ProcessPQCMsg2 failed: %v", err)
	}

	// Both parties should have the same PSK
	if !bytes.Equal(psk1[:], psk2[:]) {
		t.Errorf("PSKs don't match!\nInitiator PSK: %x\nResponder PSK: %x", psk1, psk2)
	}

	// PSK should not be zero
	var zeroPSK [32]byte
	if psk1 == zeroPSK {
		t.Errorf("PSK should not be zero")
	}

	t.Logf("✓ PQC handshake completed successfully, both parties derived same PSK: %x...", psk1[:8])
}
