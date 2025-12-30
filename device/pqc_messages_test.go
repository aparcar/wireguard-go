// SPDX-License-Identifier: MIT

package device

import (
	"testing"

	"golang.org/x/crypto/poly1305"
)

func TestMessagePQCInitiationMarshalUnmarshal(t *testing.T) {
	// Create a message with test data
	msg := &MessagePQCInitiation{
		Type:   MessagePQCInitiationType,
		Sender: 12345,
	}

	// Fill with test data
	for i := range msg.CTss {
		msg.CTss[i] = byte(i % 256)
	}
	for i := range msg.EI {
		msg.EI[i] = byte((i + 100) % 256)
	}
	for i := range msg.EncSI {
		msg.EncSI[i] = byte((i + 200) % 256)
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
	if msg2.CTss != msg.CTss {
		t.Errorf("CTss mismatch")
	}
	if msg2.EI != msg.EI {
		t.Errorf("EI mismatch")
	}
	if msg2.EncSI != msg.EncSI {
		t.Errorf("EncSI mismatch")
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
	// Verify the size constant matches the actual struct
	// Hybrid message = Standard Initiation (148 bytes) + PQC extension
	expectedSize := MessageInitiationSize + // Standard WireGuard initiation (148 bytes)
		NoisePQCCiphertextSize + // CTss (1088 bytes)
		NoisePQCPublicKeySize + // EI (1184 bytes)
		(NoisePQCPublicKeySize + poly1305.TagSize) // EncSI (1200 bytes)
	// Total: 148 + 1088 + 1184 + 1200 = 3620 bytes

	if MessagePQCInitiationSize != expectedSize {
		t.Errorf("MessagePQCInitiationSize constant (%d) doesn't match calculated size (%d)",
			MessagePQCInitiationSize, expectedSize)
	}

	t.Logf("MessagePQCInitiation size: %d bytes (Standard: %d + PQC: %d)",
		MessagePQCInitiationSize, MessageInitiationSize, MessagePQCInitiationSize-MessageInitiationSize)
}

func TestMessagePQCResponseSizeCalculation(t *testing.T) {
	// Verify the size constant matches the actual struct
	// Hybrid message = Standard Response (92 bytes) + PQC extension
	expectedSize := MessageResponseSize + // Standard WireGuard response (92 bytes)
		NoisePQCCiphertextSize + // CTee (1088 bytes)
		NoisePQCCiphertextSize // CTse (1088 bytes)
	// Total: 92 + 1088 + 1088 = 2268 bytes

	if MessagePQCResponseSize != expectedSize {
		t.Errorf("MessagePQCResponseSize constant (%d) doesn't match calculated size (%d)",
			MessagePQCResponseSize, expectedSize)
	}

	t.Logf("MessagePQCResponse size: %d bytes (Standard: %d + PQC: %d)",
		MessagePQCResponseSize, MessageResponseSize, MessagePQCResponseSize-MessageResponseSize)
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
