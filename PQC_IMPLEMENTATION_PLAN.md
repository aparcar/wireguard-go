# PQC Implementation Plan for WireGuard-go
## Piggyback PQC on 2-Message WireGuard Handshake

## Overview
Implement post-quantum cryptography (ML-KEM-768) by piggybacking PQC data onto WireGuard's existing 2-message handshake. The PQC handshake runs independently and derives a PSK that gets mixed into WireGuard's standard handshake.

## Architecture

### Two Separate Key Schedules:
1. **WireGuard classical key schedule** - Uses Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s
2. **PQC key schedule** - Uses pqIK_PQKEM_ChaChaPoly_SHA256 (quantshake-style)

### Integration Point:
- PQC handshake completes → derives 32-byte PSK
- PSK is set in `handshake.presharedKey`
- WireGuard mixes it with `KDF3` (existing code)
- Final keys contain both classical ECDH and PQC entropy

### Message Flow:
```
Message 1 (Initiation):
  [Standard WireGuard Initiation Fields]
  + CTss  (1088 bytes) - KEM ciphertext to responder's static PQC key
  + EI    (1184 bytes) - Initiator's ephemeral PQC public key  
  + EncSI (1200 bytes) - Encrypted initiator's static PQC public key

Message 2 (Response):
  [Standard WireGuard Response Fields]
  + ER    (1184 bytes) - Responder's ephemeral PQC public key
  + CTee  (1088 bytes) - KEM ciphertext to initiator's ephemeral PQC key
  + CTse  (1088 bytes) - KEM ciphertext to initiator's static PQC key
  
After Message 2: Both sides derive PSK = HKDF-Expand(pqc_chainKey, "shared", 32)
```

## Files Already Created ✅

1. `/Users/user/src/tailscale/wireguard-go/device/pqc_keygen.go`
   - `GeneratePQCKeypair()` - Generate ML-KEM-768 keys
   - `PQCPublicKeyFromSeed()` - Derive public key from seed
   
2. `/Users/user/src/tailscale/wireguard-go/cmd/wg-pqc-keygen/main.go`
   - CLI tool: `./wg-pqc-keygen` outputs seed and public key
   
3. `/Users/user/src/tailscale/wireguard-go/device/pqc_handshake.go`
   - `BuildPQCMsg1()` - Build PQC portion of Message 1
   - `ProcessPQCMsg1()` - Process PQC portion of Message 1
   - `BuildPQCMsg2()` - Build PQC portion of Message 2, derive PSK
   - `ProcessPQCMsg2()` - Process PQC portion of Message 2, derive PSK
   
4. `/Users/user/src/tailscale/wireguard-go/test-pqc-handshake.sh`
   - macOS-compatible test script
   - Builds keys, sets up interfaces, tests handshake

## Implementation Steps

### Step 1: Add PQC Message Types to `noise-protocol.go`

Add after existing message type constants:
```go
const (
    MessageInitiationType     = 1
    MessageResponseType       = 2
    MessageCookieReplyType    = 3
    MessageTransportType      = 4
    MessagePQCInitiationType  = 5  // NEW
    MessagePQCResponseType    = 6  // NEW
)
```

Add message size constants:
```go
const (
    // ... existing constants ...
    
    // PQC message sizes
    MessagePQCInitiationSize = MessageInitiationSize + NoisePQCCiphertextSize + NoisePQCPublicKeySize + (NoisePQCPublicKeySize + poly1305.TagSize)
    // 148 + 1088 + 1184 + 1200 = 3620 bytes
    
    MessagePQCResponseSize = MessageResponseSize + NoisePQCCiphertextSize + NoisePQCCiphertextSize
    // 92 + 1088 + 1088 = 2268 bytes
)
```

### Step 2: Define PQC Message Structures in `noise-protocol.go`

Add after existing message structures:
```go
type MessagePQCInitiation struct {
    // Standard WireGuard initiation fields (same as MessageInitiation)
    Type      uint32
    Sender    uint32
    Ephemeral NoisePublicKey
    Static    [NoisePublicKeySize + poly1305.TagSize]byte
    Timestamp [tai64n.TimestampSize + poly1305.TagSize]byte
    MAC1      [blake2s.Size128]byte
    MAC2      [blake2s.Size128]byte
    
    // PQC extension fields
    CTss  NoisePQCCiphertext                             // 1088 bytes
    EI    NoisePQCPublicKey                              // 1184 bytes
    EncSI [NoisePQCPublicKeySize + poly1305.TagSize]byte // 1200 bytes
}

type MessagePQCResponse struct {
    // Standard WireGuard response fields (same as MessageResponse)
    Type      uint32
    Sender    uint32
    Receiver  uint32
    Ephemeral NoisePublicKey
    Empty     [poly1305.TagSize]byte
    MAC1      [blake2s.Size128]byte
    MAC2      [blake2s.Size128]byte
    
    // PQC extension fields
    ER   NoisePQCPublicKey  // 1184 bytes
    CTee NoisePQCCiphertext // 1088 bytes
    CTse NoisePQCCiphertext // 1088 bytes
}
```

### Step 3: Add Marshal/Unmarshal for PQC Messages

Add to `noise-protocol.go` after existing marshal/unmarshal functions:

```go
func (msg *MessagePQCInitiation) unmarshal(b []byte) error {
    if len(b) != MessagePQCInitiationSize {
        return errMessageLengthMismatch
    }
    
    // Standard fields (first 148 bytes, same layout as MessageInitiation)
    msg.Type = binary.LittleEndian.Uint32(b)
    msg.Sender = binary.LittleEndian.Uint32(b[4:])
    copy(msg.Ephemeral[:], b[8:])
    copy(msg.Static[:], b[8+NoisePublicKeySize:])
    copy(msg.Timestamp[:], b[8+NoisePublicKeySize+len(msg.Static):])
    copy(msg.MAC1[:], b[8+NoisePublicKeySize+len(msg.Static)+len(msg.Timestamp):])
    copy(msg.MAC2[:], b[8+NoisePublicKeySize+len(msg.Static)+len(msg.Timestamp)+blake2s.Size128:])
    
    // PQC fields (appended after standard message)
    offset := MessageInitiationSize
    copy(msg.CTss[:], b[offset:])
    offset += NoisePQCCiphertextSize
    copy(msg.EI[:], b[offset:])
    offset += NoisePQCPublicKeySize
    copy(msg.EncSI[:], b[offset:])
    
    return nil
}

func (msg *MessagePQCInitiation) marshal(b []byte) error {
    if len(b) != MessagePQCInitiationSize {
        return errMessageLengthMismatch
    }
    
    // Standard fields
    binary.LittleEndian.PutUint32(b, msg.Type)
    binary.LittleEndian.PutUint32(b[4:], msg.Sender)
    copy(b[8:], msg.Ephemeral[:])
    copy(b[8+NoisePublicKeySize:], msg.Static[:])
    copy(b[8+NoisePublicKeySize+len(msg.Static):], msg.Timestamp[:])
    copy(b[8+NoisePublicKeySize+len(msg.Static)+len(msg.Timestamp):], msg.MAC1[:])
    copy(b[8+NoisePublicKeySize+len(msg.Static)+len(msg.Timestamp)+blake2s.Size128:], msg.MAC2[:])
    
    // PQC fields
    offset := MessageInitiationSize
    copy(b[offset:], msg.CTss[:])
    offset += NoisePQCCiphertextSize
    copy(b[offset:], msg.EI[:])
    offset += NoisePQCPublicKeySize
    copy(b[offset:], msg.EncSI[:])
    
    return nil
}

// Similar for MessagePQCResponse...
func (msg *MessagePQCResponse) unmarshal(b []byte) error {
    if len(b) != MessagePQCResponseSize {
        return errMessageLengthMismatch
    }
    
    // Standard fields
    msg.Type = binary.LittleEndian.Uint32(b)
    msg.Sender = binary.LittleEndian.Uint32(b[4:])
    msg.Receiver = binary.LittleEndian.Uint32(b[8:])
    copy(msg.Ephemeral[:], b[12:])
    copy(msg.Empty[:], b[12+NoisePublicKeySize:])
    copy(msg.MAC1[:], b[12+NoisePublicKeySize+poly1305.TagSize:])
    copy(msg.MAC2[:], b[12+NoisePublicKeySize+poly1305.TagSize+blake2s.Size128:])
    
    // PQC fields
    offset := MessageResponseSize
    copy(msg.ER[:], b[offset:])
    offset += NoisePQCPublicKeySize
    copy(msg.CTee[:], b[offset:])
    offset += NoisePQCCiphertextSize
    copy(msg.CTse[:], b[offset:])
    
    return nil
}

func (msg *MessagePQCResponse) marshal(b []byte) error {
    if len(b) != MessagePQCResponseSize {
        return errMessageLengthMismatch
    }
    
    // Standard fields
    binary.LittleEndian.PutUint32(b, msg.Type)
    binary.LittleEndian.PutUint32(b[4:], msg.Sender)
    binary.LittleEndian.PutUint32(b[8:], msg.Receiver)
    copy(b[12:], msg.Ephemeral[:])
    copy(b[12+NoisePublicKeySize:], msg.Empty[:])
    copy(b[12+NoisePublicKeySize+poly1305.TagSize:], msg.MAC1[:])
    copy(b[12+NoisePublicKeySize+poly1305.TagSize+blake2s.Size128:], msg.MAC2[:])
    
    // PQC fields
    offset := MessageResponseSize
    copy(b[offset:], msg.ER[:])
    offset += NoisePQCPublicKeySize
    copy(b[offset:], msg.CTee[:])
    offset += NoisePQCCiphertextSize
    copy(b[offset:], msg.CTse[:])
    
    return nil
}
```

### Step 4: Add PQC State to Handshake Struct

In `noise-protocol.go`, add to the `Handshake` struct:

```go
type Handshake struct {
    // ... existing fields ...
    
    // PQC handshake state (independent from classical WireGuard)
    pqcKeySchedule *pqKeySchedule // From pqc_handshake.go
    pqcDerivedPSK  [32]byte        // PSK derived from PQC handshake
    pqcEphemeralPriv NoisePQCSeed  // Our ephemeral PQC private key
    remotePQCEphemeral NoisePQCPublicKey // Peer's ephemeral PQC public key
}
```

### Step 5: Create PQC Initiation Message

Add new function to `noise-protocol.go`:

```go
func (device *Device) CreateMessagePQCInitiation(peer *Peer) (*MessagePQCInitiation, error) {
    device.staticIdentity.RLock()
    defer device.staticIdentity.RUnlock()

    handshake := &peer.handshake
    handshake.mutex.Lock()
    defer handshake.mutex.Unlock()

    // Check if PQC is enabled for this peer
    if handshake.remotePQCStatic.IsZero() {
        return nil, errors.New("peer does not have a PQC public key configured")
    }
    if device.staticIdentity.pqcSeed.IsZero() {
        return nil, errors.New("device does not have a PQC private key configured")
    }

    // === Build standard WireGuard initiation ===
    // Use existing CreateMessageInitiation logic
    standardMsg, err := device.createStandardInitiation(peer, handshake)
    if err != nil {
        return nil, err
    }

    // === Build PQC portion (independent handshake) ===
    ctss, ei, encSI, eiPriv, pqKS, err := BuildPQCMsg1(
        device.staticIdentity.pqcPublicKey,
        handshake.remotePQCStatic,
    )
    if err != nil {
        return nil, fmt.Errorf("PQC Msg1 failed: %w", err)
    }

    // Store PQC state for Msg2
    handshake.pqcKeySchedule = pqKS
    handshake.pqcEphemeralPriv = eiPriv

    // Combine into PQC message
    msg := &MessagePQCInitiation{
        Type: MessagePQCInitiationType,
        Sender: standardMsg.Sender,
        Ephemeral: standardMsg.Ephemeral,
        Static: standardMsg.Static,
        Timestamp: standardMsg.Timestamp,
        MAC1: standardMsg.MAC1,
        MAC2: standardMsg.MAC2,
        CTss: ctss,
        EI: ei,
    }
    copy(msg.EncSI[:], encSI)

    device.log.Verbosef("%v - Created PQC initiation message", peer)
    return msg, nil
}
```

### Step 6: Consume PQC Initiation Message

Add to `noise-protocol.go`:

```go
func (device *Device) ConsumeMessagePQCInitiation(msg *MessagePQCInitiation, endpoint conn.Endpoint) *Peer {
    if msg.Type != MessagePQCInitiationType {
        return nil
    }

    // === Process standard WireGuard portion ===
    // Convert to standard message and process
    standardMsg := &MessageInitiation{
        Type: MessageInitiationType,
        Sender: msg.Sender,
        Ephemeral: msg.Ephemeral,
        Static: msg.Static,
        Timestamp: msg.Timestamp,
        MAC1: msg.MAC1,
        MAC2: msg.MAC2,
    }
    
    peer := device.consumeStandardInitiation(standardMsg, endpoint)
    if peer == nil {
        return nil
    }

    // === Process PQC portion (independent handshake) ===
    handshake := &peer.handshake
    handshake.mutex.Lock()
    defer handshake.mutex.Unlock()

    peerPQCStatic, pqKS, err := ProcessPQCMsg1(
        device.staticIdentity.pqcPublicKey,
        device.staticIdentity.pqcSeed,
        msg.CTss,
        msg.EI,
        msg.EncSI[:],
    )
    if err != nil {
        device.log.Errorf("%v - PQC Msg1 processing failed: %v", peer, err)
        return nil
    }

    // Validate peer's PQC static key matches configured
    if !handshake.remotePQCStatic.IsZero() && !bytes.Equal(peerPQCStatic[:], handshake.remotePQCStatic[:]) {
        device.log.Errorf("%v - PQC static key mismatch", peer)
        return nil
    }

    // Store PQC state for building Msg2
    handshake.remotePQCEphemeral = msg.EI
    handshake.pqcKeySchedule = pqKS

    device.log.Verbosef("%v - Consumed PQC initiation message", peer)
    return peer
}
```

### Step 7: Create PQC Response Message

Add to `noise-protocol.go`:

```go
func (device *Device) CreateMessagePQCResponse(peer *Peer) (*MessagePQCResponse, error) {
    device.staticIdentity.RLock()
    defer device.staticIdentity.RUnlock()

    handshake := &peer.handshake
    handshake.mutex.Lock()
    defer handshake.mutex.Unlock()

    if handshake.pqcKeySchedule == nil {
        return nil, errors.New("PQC handshake not initiated")
    }

    // === Build standard WireGuard response ===
    standardMsg, err := device.createStandardResponse(peer, handshake)
    if err != nil {
        return nil, err
    }

    // === Build PQC Msg2 and derive PSK ===
    er, ctee, ctse, psk, err := BuildPQCMsg2(
        handshake.remotePQCEphemeral,
        handshake.remotePQCStatic,
        handshake.pqcKeySchedule,
    )
    if err != nil {
        return nil, fmt.Errorf("PQC Msg2 failed: %w", err)
    }

    // **KEY STEP: Inject PQC-derived PSK into WireGuard handshake**
    copy(handshake.presharedKey[:], psk[:])
    device.log.Verbosef("%v - Injected PQC-derived PSK into handshake", peer)

    // Now rebuild the standard response with the PSK mixed in
    // (WireGuard will mix it via KDF3 in the existing code)
    standardMsg, err = device.createStandardResponse(peer, handshake)
    if err != nil {
        return nil, err
    }

    // Combine into PQC message
    msg := &MessagePQCResponse{
        Type: MessagePQCResponseType,
        Sender: standardMsg.Sender,
        Receiver: standardMsg.Receiver,
        Ephemeral: standardMsg.Ephemeral,
        Empty: standardMsg.Empty,
        MAC1: standardMsg.MAC1,
        MAC2: standardMsg.MAC2,
        ER: er,
        CTee: ctee,
        CTse: ctse,
    }

    device.log.Verbosef("%v - Created PQC response message with PSK", peer)
    return msg, nil
}
```

### Step 8: Consume PQC Response Message

Add to `noise-protocol.go`:

```go
func (device *Device) ConsumeMessagePQCResponse(msg *MessagePQCResponse) *Peer {
    if msg.Type != MessagePQCResponseType {
        return nil
    }

    // === Process standard WireGuard portion ===
    standardMsg := &MessageResponse{
        Type: MessageResponseType,
        Sender: msg.Sender,
        Receiver: msg.Receiver,
        Ephemeral: msg.Ephemeral,
        Empty: msg.Empty,
        MAC1: msg.MAC1,
        MAC2: msg.MAC2,
    }

    // We need to derive PSK BEFORE consuming standard response
    // because WireGuard will verify the Empty field which includes PSK
    
    peer := device.lookupPeerByHandshake(msg.Receiver)
    if peer == nil {
        return nil
    }

    handshake := &peer.handshake
    handshake.mutex.Lock()

    if handshake.pqcKeySchedule == nil {
        handshake.mutex.Unlock()
        return nil
    }

    // === Process PQC Msg2 and derive PSK ===
    psk, err := ProcessPQCMsg2(
        handshake.pqcEphemeralPriv,
        device.staticIdentity.pqcSeed,
        msg.ER,
        msg.CTee,
        msg.CTse,
        handshake.pqcKeySchedule,
    )
    if err != nil {
        handshake.mutex.Unlock()
        device.log.Errorf("%v - PQC Msg2 processing failed: %v", peer, err)
        return nil
    }

    // **KEY STEP: Inject PQC-derived PSK before verifying response**
    copy(handshake.presharedKey[:], psk[:])
    handshake.mutex.Unlock()

    device.log.Verbosef("%v - Derived PSK from PQC handshake", peer)

    // Now consume standard response (which will verify Empty with PSK)
    return device.consumeStandardResponse(standardMsg)
}
```

### Step 9: Update send.go to Use PQC Messages

In `send.go`, modify `SendHandshakeInitiation`:

```go
func (peer *Peer) SendHandshakeInitiation() error {
    // ... existing rate limiting ...

    peer.device.log.Verbosef("%v - Sending handshake initiation", peer)

    // Check if PQC is configured for this peer
    peer.handshake.mutex.RLock()
    usePQC := !peer.handshake.remotePQCStatic.IsZero() && !peer.device.staticIdentity.pqcSeed.IsZero()
    peer.handshake.mutex.RUnlock()

    if usePQC {
        // Use PQC-extended message
        msg, err := peer.device.CreateMessagePQCInitiation(peer)
        if err != nil {
            peer.device.log.Errorf("%v - Failed to create PQC initiation: %v", peer, err)
            return err
        }

        buf := make([]byte, MessageEncapsulatingTransportSize+MessagePQCInitiationSize)
        packet := buf[MessageEncapsulatingTransportSize:]
        _ = msg.marshal(packet)
        peer.cookieGenerator.AddMacs(packet)

        err = peer.SendBuffers([][]byte{buf})
        if err != nil {
            peer.device.log.Errorf("%v - Failed to send PQC initiation: %v", peer, err)
        }
        peer.timersHandshakeInitiated()
        return err
    } else {
        // Use standard WireGuard message (existing code)
        // ... existing CreateMessageInitiation code ...
    }
}
```

Similar for `SendHandshakeResponse`:

```go
func (peer *Peer) SendHandshakeResponse() error {
    peer.handshake.mutex.Lock()
    usePQC := peer.handshake.pqcKeySchedule != nil
    peer.handshake.mutex.Unlock()

    if usePQC {
        // Use PQC-extended response
        response, err := peer.device.CreateMessagePQCResponse(peer)
        if err != nil {
            peer.device.log.Errorf("%v - Failed to create PQC response: %v", peer, err)
            return err
        }

        buf := make([]byte, MessageEncapsulatingTransportSize+MessagePQCResponseSize)
        packet := buf[MessageEncapsulatingTransportSize:]
        _ = response.marshal(packet)
        peer.cookieGenerator.AddMacs(packet)

        err = peer.SendBuffers([][]byte{buf})
        // ... rest of response handling ...
    } else {
        // Standard response (existing code)
        // ...
    }
}
```

### Step 10: Update receive.go to Handle PQC Message Types

In `receive.go`, in the packet size validation switch:

```go
switch msgType {
case MessageInitiationType:
    if len(packet) != MessageInitiationSize {
        continue
    }

case MessageResponseType:
    if len(packet) != MessageResponseSize {
        continue
    }

case MessageCookieReplyType:
    if len(packet) != MessageCookieReplySize {
        continue
    }

case MessagePQCInitiationType:  // NEW
    if len(packet) != MessagePQCInitiationSize {
        device.log.Errorf("PQC initiation wrong size: got %d, expected %d", len(packet), MessagePQCInitiationSize)
        continue
    }

case MessagePQCResponseType:  // NEW
    if len(packet) != MessagePQCResponseSize {
        device.log.Errorf("PQC response wrong size: got %d, expected %d", len(packet), MessagePQCResponseSize)
        continue
    }

default:
    device.log.Errorf("Unknown message type: %d", msgType)
    continue
}
```

In the MAC checking section:

```go
case MessageInitiationType, MessageResponseType, MessagePQCInitiationType, MessagePQCResponseType:
    // check mac fields and maybe ratelimit
    // ... existing MAC1/MAC2 validation ...
```

In the handshake processing section:

```go
switch elem.msgType {
case MessageInitiationType:
    // ... existing code ...

case MessageResponseType:
    // ... existing code ...

case MessagePQCInitiationType:  // NEW
    device.log.Verbosef("Processing PQC initiation message")
    
    var msg MessagePQCInitiation
    err := msg.unmarshal(elem.packet)
    if err != nil {
        device.log.Errorf("Failed to decode PQC initiation: %v", err)
        goto skip
    }

    peer := device.ConsumeMessagePQCInitiation(&msg, elem.endpoint)
    if peer == nil {
        device.log.Verbosef("Invalid PQC initiation from %s", elem.endpoint.DstToString())
        goto skip
    }

    peer.timersAnyAuthenticatedPacketTraversal()
    peer.timersAnyAuthenticatedPacketReceived()
    peer.SetEndpointFromPacket(elem.endpoint)
    peer.rxBytes.Add(uint64(len(elem.packet)))

    peer.SendHandshakeResponse()

case MessagePQCResponseType:  // NEW
    device.log.Verbosef("Processing PQC response message")
    
    var msg MessagePQCResponse
    err := msg.unmarshal(elem.packet)
    if err != nil {
        device.log.Errorf("Failed to decode PQC response: %v", err)
        goto skip
    }

    peer := device.ConsumeMessagePQCResponse(&msg)
    if peer == nil {
        device.log.Verbosef("Invalid PQC response from %s", elem.endpoint.DstToString())
        goto skip
    }

    peer.SetEndpointFromPacket(elem.endpoint)
    peer.rxBytes.Add(uint64(len(elem.packet)))
    peer.timersAnyAuthenticatedPacketTraversal()
    peer.timersAnyAuthenticatedPacketReceived()

    err = peer.BeginSymmetricSession()
    if err != nil {
        device.log.Errorf("%v - Failed to derive keypair: %v", peer, err)
        goto skip
    }

    peer.timersSessionDerived()
    peer.timersHandshakeComplete()
    peer.SendKeepalive()
}
```

## Testing

Run the test script:
```bash
cd /Users/user/src/tailscale/wireguard-go
go build -o wireguard-go
sudo ./test-pqc-handshake.sh
```

Look for in logs:
- "Created PQC initiation message"
- "Consumed PQC initiation message"
- "Injected PQC-derived PSK into handshake"
- "Created PQC response message with PSK"
- "Derived PSK from PQC handshake"
- Successful ping between peers

## Key Points to Remember

1. **Two separate key schedules** - WireGuard's and PQC's run independently
2. **PSK is the integration point** - PQC derives PSK, WireGuard mixes it
3. **2 messages total** - Same as standard WireGuard, just bigger
4. **No Msg3** - We skip quantshake's third message (optional ack)
5. **PSK injection timing** - Must happen BEFORE creating/verifying Empty field
6. **Backward compatible** - Standard WireGuard still works if PQC not configured

## Files Modified Summary

- `device/noise-protocol.go` - Message types, structures, create/consume functions
- `device/send.go` - Use PQC messages when available
- `device/receive.go` - Handle PQC message types
- `device/pqc_handshake.go` - Already created ✅
- `device/pqc_keygen.go` - Already created ✅

## Critical Implementation Note

The `pqc_handshake.go` file uses **SHA256** for HKDF (matching quantshake's "pqIK_PQKEM_ChaChaPoly_SHA256"), while WireGuard uses **BLAKE2s**. This is correct and intentional - they're separate handshakes with separate key schedules that meet at the PSK injection point.
