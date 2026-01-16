// SPDX-License-Identifier: MIT

package device

import (
	"testing"
)

func TestMessagePQCInitiationMarshalUnmarshal(t *testing.T) {
	// Create a message with test data
	msg := &MessagePQCInitiation{
		Type:   MessagePQCInitiationType,
		Sender: 12345,
	}

	// Fill with test data
	for i := range msg.Ephemeral {
		msg.Ephemeral[i] = byte(i % 256)
	}
	for i := range msg.Static {
		msg.Static[i] = byte((i + 10) % 256)
	}
	for i := range msg.Timestamp {
		msg.Timestamp[i] = byte((i + 20) % 256)
	}
	for i := range msg.CTss {
		msg.CTss[i] = byte((i + 30) % 256)
	}
	for i := range msg.EI {
		msg.EI[i] = byte((i + 50) % 256)
	}
	for i := range msg.EncSIid {
		msg.EncSIid[i] = byte((i + 100) % 256)
	}
	for i := range msg.MAC1 {
		msg.MAC1[i] = byte(i)
	}
	for i := range msg.MAC2 {
		msg.MAC2[i] = byte(i + 1)
	}

	// Marshal
	buf := make([]byte, MessagePQCInitiationSize)
	err := msg.marshal(buf)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	// Unmarshal
	var msg2 MessagePQCInitiation
	err = msg2.unmarshal(buf)
	if err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	// Verify
	if msg2.Type != msg.Type {
		t.Errorf("Type mismatch: got %d, want %d", msg2.Type, msg.Type)
	}
	if msg2.Sender != msg.Sender {
		t.Errorf("Sender mismatch: got %d, want %d", msg2.Sender, msg.Sender)
	}
	if msg2.Ephemeral != msg.Ephemeral {
		t.Errorf("Ephemeral mismatch")
	}
	if msg2.Static != msg.Static {
		t.Errorf("Static mismatch")
	}
	if msg2.Timestamp != msg.Timestamp {
		t.Errorf("Timestamp mismatch")
	}
	if msg2.CTss != msg.CTss {
		t.Errorf("CTss mismatch")
	}
	if msg2.EI != msg.EI {
		t.Errorf("EI mismatch")
	}
	if msg2.EncSIid != msg.EncSIid {
		t.Errorf("EncSIid mismatch")
	}
	if msg2.MAC1 != msg.MAC1 {
		t.Errorf("MAC1 mismatch")
	}
	if msg2.MAC2 != msg.MAC2 {
		t.Errorf("MAC2 mismatch")
	}
}

func TestMessagePQCResponseMarshalUnmarshal(t *testing.T) {
	// Create a message with test data
	msg := &MessagePQCResponse{
		Type:     MessagePQCResponseType,
		Sender:   12345,
		Receiver: 67890,
	}

	// Fill with test data
	for i := range msg.Ephemeral {
		msg.Ephemeral[i] = byte(i % 256)
	}
	for i := range msg.Empty {
		msg.Empty[i] = byte((i + 10) % 256)
	}
	for i := range msg.CTee {
		msg.CTee[i] = byte((i + 50) % 256)
	}
	for i := range msg.CTse {
		msg.CTse[i] = byte((i + 100) % 256)
	}
	for i := range msg.MAC1 {
		msg.MAC1[i] = byte(i)
	}
	for i := range msg.MAC2 {
		msg.MAC2[i] = byte(i + 1)
	}

	// Marshal
	buf := make([]byte, MessagePQCResponseSize)
	err := msg.marshal(buf)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	// Unmarshal
	var msg2 MessagePQCResponse
	err = msg2.unmarshal(buf)
	if err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	// Verify
	if msg2.Type != msg.Type {
		t.Errorf("Type mismatch: got %d, want %d", msg2.Type, msg.Type)
	}
	if msg2.Sender != msg.Sender {
		t.Errorf("Sender mismatch: got %d, want %d", msg2.Sender, msg.Sender)
	}
	if msg2.Receiver != msg.Receiver {
		t.Errorf("Receiver mismatch: got %d, want %d", msg2.Receiver, msg.Receiver)
	}
	if msg2.Ephemeral != msg.Ephemeral {
		t.Errorf("Ephemeral mismatch")
	}
	if msg2.Empty != msg.Empty {
		t.Errorf("Empty mismatch")
	}
	if msg2.CTee != msg.CTee {
		t.Errorf("CTee mismatch")
	}
	if msg2.CTse != msg.CTse {
		t.Errorf("CTse mismatch")
	}
	if msg2.MAC1 != msg.MAC1 {
		t.Errorf("MAC1 mismatch")
	}
	if msg2.MAC2 != msg.MAC2 {
		t.Errorf("MAC2 mismatch")
	}
}

func TestMessagePQCInitiationSizeCalculation(t *testing.T) {
	// Verify the size constant matches the expected IPv6 MTU constraint
	// IPv6 minimum MTU: 1280 bytes
	// IPv6 header: 40 bytes
	// UDP header: 8 bytes
	// Available for payload: 1232 bytes
	maxPayload := 1232

	if MessagePQCInitiationSize > maxPayload {
		t.Errorf("MessagePQCInitiationSize (%d) exceeds IPv6 MTU payload limit (%d)",
			MessagePQCInitiationSize, maxPayload)
	}

	t.Logf("MessagePQCInitiation size: %d bytes (fits in IPv6 MTU with %d bytes headroom)",
		MessagePQCInitiationSize, maxPayload-MessagePQCInitiationSize)
}

func TestMessagePQCResponseSizeCalculation(t *testing.T) {
	// Verify the size constant fits in IPv6 MTU
	maxPayload := 1232

	if MessagePQCResponseSize > maxPayload {
		t.Errorf("MessagePQCResponseSize (%d) exceeds IPv6 MTU payload limit (%d)",
			MessagePQCResponseSize, maxPayload)
	}

	t.Logf("MessagePQCResponse size: %d bytes (fits in IPv6 MTU with %d bytes headroom)",
		MessagePQCResponseSize, maxPayload-MessagePQCResponseSize)
}

func TestMessagePQCInitiationWrongSize(t *testing.T) {
	msg := &MessagePQCInitiation{Type: MessagePQCInitiationType}

	// Try to marshal with wrong size buffer
	buf := make([]byte, 100)
	err := msg.marshal(buf)
	if err == nil {
		t.Errorf("Expected error when marshaling with wrong size buffer")
	}

	// Try to unmarshal with wrong size buffer
	err = msg.unmarshal(buf)
	if err == nil {
		t.Errorf("Expected error when unmarshaling with wrong size buffer")
	}
}

func TestMessagePQCResponseWrongSize(t *testing.T) {
	msg := &MessagePQCResponse{Type: MessagePQCResponseType}

	// Try to marshal with wrong size buffer
	buf := make([]byte, 100)
	err := msg.marshal(buf)
	if err == nil {
		t.Errorf("Expected error when marshaling with wrong size buffer")
	}

	// Try to unmarshal with wrong size buffer
	err = msg.unmarshal(buf)
	if err == nil {
		t.Errorf("Expected error when unmarshaling with wrong size buffer")
	}
}

func TestMessagePQCFitsIPv6MTU(t *testing.T) {
	// This is the critical test: both messages must fit in a single IPv6 frame

	// IPv6 minimum MTU
	ipv6MinMTU := 1280
	// IPv6 header
	ipv6Header := 40
	// UDP header
	udpHeader := 8
	// Available payload
	maxPayload := ipv6MinMTU - ipv6Header - udpHeader

	t.Logf("IPv6 minimum MTU: %d bytes", ipv6MinMTU)
	t.Logf("  - IPv6 header: %d bytes", ipv6Header)
	t.Logf("  - UDP header: %d bytes", udpHeader)
	t.Logf("  = Available payload: %d bytes", maxPayload)
	t.Logf("")
	t.Logf("PQC Initiation message: %d bytes (headroom: %d bytes)",
		MessagePQCInitiationSize, maxPayload-MessagePQCInitiationSize)
	t.Logf("PQC Response message: %d bytes (headroom: %d bytes)",
		MessagePQCResponseSize, maxPayload-MessagePQCResponseSize)

	if MessagePQCInitiationSize > maxPayload {
		t.Errorf("PQC Initiation message (%d bytes) exceeds IPv6 MTU payload (%d bytes)",
			MessagePQCInitiationSize, maxPayload)
	}

	if MessagePQCResponseSize > maxPayload {
		t.Errorf("PQC Response message (%d bytes) exceeds IPv6 MTU payload (%d bytes)",
			MessagePQCResponseSize, maxPayload)
	}
}

func TestMessagePQCAlgorithmSizes(t *testing.T) {
	// Document the algorithm sizes used in the compact PQC handshake
	t.Logf("Algorithm sizes for compact hybrid PQC handshake:")
	t.Logf("")
	t.Logf("McEliece6688128 (NIST Level 5, 256-bit security):")
	t.Logf("  Public key:  %d bytes (~1MB, pre-provisioned)", NoiseMcEliecePublicKeySize)
	t.Logf("  Private key: %d bytes", NoiseMcEliecePrivateKeySize)
	t.Logf("  Ciphertext:  %d bytes (transmitted in handshake)", NoiseMcElieceCiphertextSize)
	t.Logf("  Shared key:  %d bytes", NoiseMcElieceSharedKeySize)
	t.Logf("")
	t.Logf("Kyber512 (NIST Level 1, 128-bit security, forward secrecy):")
	t.Logf("  Public key:  %d bytes", NoiseKyberPublicKeySize)
	t.Logf("  Private key: %d bytes", NoiseKyberPrivateKeySize)
	t.Logf("  Ciphertext:  %d bytes", NoiseKyberCiphertextSize)
	t.Logf("  Shared key:  %d bytes", NoiseKyberSharedKeySize)
	t.Logf("")
	t.Logf("Key ID (BLAKE2s hash of McEliece public key):")
	t.Logf("  Size: %d bytes", NoisePQCKeyIDSize)

	// Verify sizes match expected values
	if NoiseMcElieceCiphertextSize != 208 {
		t.Errorf("Expected McEliece ciphertext size 208, got %d", NoiseMcElieceCiphertextSize)
	}
	if NoiseKyberPublicKeySize != 800 {
		t.Errorf("Expected Kyber public key size 800, got %d", NoiseKyberPublicKeySize)
	}
	if NoiseKyberCiphertextSize != 768 {
		t.Errorf("Expected Kyber ciphertext size 768, got %d", NoiseKyberCiphertextSize)
	}
}
