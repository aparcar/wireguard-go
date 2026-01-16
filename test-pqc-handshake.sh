#!/bin/bash
# Direct WireGuard-go PQC Handshake Test
# Tests PQC handshakes between two wireguard-go instances
# Uses wg-pqc tool for PQC key management

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_section() {
    echo ""
    echo -e "${YELLOW}========================================${NC}"
    echo -e "${YELLOW}$1${NC}"
    echo -e "${YELLOW}========================================${NC}"
}

# Paths
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WG_GO="$SCRIPT_DIR/wireguard-go"
WG_PQC="$SCRIPT_DIR/wg-pqc"

# Test directories
TEST_DIR="/tmp/wg-pqc-test"
PEER1_DIR="$TEST_DIR/peer1"
PEER2_DIR="$TEST_DIR/peer2"

# Interface names
PEER1_IFACE="wgtest0"
PEER2_IFACE="wgtest1"

# Process tracking
PEER1_PID=""
PEER2_PID=""

cleanup() {
    log_section "Cleaning up"

    # Kill wireguard-go processes
    if [ -n "$PEER1_PID" ]; then
        log_info "Stopping peer1 (PID: $PEER1_PID)..."
        sudo kill -TERM $PEER1_PID 2>/dev/null || true
        sleep 1
    fi

    if [ -n "$PEER2_PID" ]; then
        log_info "Stopping peer2 (PID: $PEER2_PID)..."
        sudo kill -TERM $PEER2_PID 2>/dev/null || true
        sleep 1
    fi

    # Remove interfaces
    sudo ip link del $PEER1_IFACE 2>/dev/null || true
    sudo ip link del $PEER2_IFACE 2>/dev/null || true

    # Remove test directory
    rm -rf "$TEST_DIR"

    log_success "Cleanup complete"
}

trap cleanup EXIT

log_section "WireGuard-go PQC Handshake Test (Linux)"

# Build tools if needed
log_info "Building wireguard-go and wg-pqc..."
cd "$SCRIPT_DIR"
if [ ! -f "$WG_GO" ] || [ "$SCRIPT_DIR/device" -nt "$WG_GO" ]; then
    go build -o wireguard-go .
fi
if [ ! -f "$WG_PQC" ] || [ "$SCRIPT_DIR/cmd/wg-pqc" -nt "$WG_PQC" ]; then
    go build -o wg-pqc ./cmd/wg-pqc
fi
log_success "Tools built"

# Clean up any previous test
rm -rf "$TEST_DIR"
mkdir -p "$PEER1_DIR" "$PEER2_DIR"

# Clean up any existing interfaces
sudo ip link del $PEER1_IFACE 2>/dev/null || true
sudo ip link del $PEER2_IFACE 2>/dev/null || true

log_section "Step 1: Generate Keys"

# Generate WireGuard keys for peer1
log_info "Generating peer1 WireGuard keys..."
PEER1_WG_PRIVATE=$(wg genkey)
PEER1_WG_PUBLIC=$(echo "$PEER1_WG_PRIVATE" | wg pubkey)
echo "$PEER1_WG_PRIVATE" > "$PEER1_DIR/wg-private.key"
echo "$PEER1_WG_PUBLIC" > "$PEER1_DIR/wg-public.key"

# Generate WireGuard keys for peer2
log_info "Generating peer2 WireGuard keys..."
PEER2_WG_PRIVATE=$(wg genkey)
PEER2_WG_PUBLIC=$(echo "$PEER2_WG_PRIVATE" | wg pubkey)
echo "$PEER2_WG_PRIVATE" > "$PEER2_DIR/wg-private.key"
echo "$PEER2_WG_PUBLIC" > "$PEER2_DIR/wg-public.key"

log_success "WireGuard keys generated"

# Generate PQC keys using seed-based approach (recommended)
log_info "Generating peer1 PQC seed and deriving keys..."
"$WG_PQC" genseed > "$PEER1_DIR/pqc.seed"
"$WG_PQC" pubkey < "$PEER1_DIR/pqc.seed" > "$PEER1_DIR/pqc-public.key"

log_info "Generating peer2 PQC seed and deriving keys..."
"$WG_PQC" genseed > "$PEER2_DIR/pqc.seed"
"$WG_PQC" pubkey < "$PEER2_DIR/pqc.seed" > "$PEER2_DIR/pqc-public.key"

log_success "PQC seeds and public keys generated"
log_info "Peer1 WG public: $PEER1_WG_PUBLIC"
log_info "Peer2 WG public: $PEER2_WG_PUBLIC"

log_section "Step 2: Start WireGuard Interfaces"

log_info "Starting wireguard-go for peer1 ($PEER1_IFACE)..."
sudo -E LOG_LEVEL=verbose "$WG_GO" -f $PEER1_IFACE > "$PEER1_DIR/wg.log" 2>&1 &
PEER1_PID=$!
sleep 2

# Check if peer1 started successfully
if ! kill -0 $PEER1_PID 2>/dev/null; then
    log_error "Peer1 wireguard-go failed to start. Log:"
    cat "$PEER1_DIR/wg.log" 2>/dev/null || echo "No log available"
    exit 1
fi

# Check if interface exists
if ! ip link show $PEER1_IFACE >/dev/null 2>&1; then
    log_error "Peer1 interface $PEER1_IFACE not created. Log:"
    cat "$PEER1_DIR/wg.log" 2>/dev/null || echo "No log available"
    exit 1
fi

log_info "Starting wireguard-go for peer2 ($PEER2_IFACE)..."
sudo -E LOG_LEVEL=verbose "$WG_GO" -f $PEER2_IFACE > "$PEER2_DIR/wg.log" 2>&1 &
PEER2_PID=$!
sleep 2

# Check if peer2 started successfully
if ! kill -0 $PEER2_PID 2>/dev/null; then
    log_error "Peer2 wireguard-go failed to start. Log:"
    cat "$PEER2_DIR/wg.log" 2>/dev/null || echo "No log available"
    exit 1
fi

# Check if interface exists
if ! ip link show $PEER2_IFACE >/dev/null 2>&1; then
    log_error "Peer2 interface $PEER2_IFACE not created. Log:"
    cat "$PEER2_DIR/wg.log" 2>/dev/null || echo "No log available"
    exit 1
fi

log_info "Peer1 interface: $PEER1_IFACE (PID: $PEER1_PID)"
log_info "Peer2 interface: $PEER2_IFACE (PID: $PEER2_PID)"

log_success "WireGuard interfaces started"

log_section "Step 3: Configure WireGuard Interfaces"

log_info "Configuring peer1 ($PEER1_IFACE)..."
sudo ip addr add 10.0.0.1/24 dev $PEER1_IFACE
sudo ip link set $PEER1_IFACE up

log_info "Setting private key for peer1..."
echo "$PEER1_WG_PRIVATE" | sudo wg set $PEER1_IFACE private-key /dev/stdin

log_info "Setting listen port for peer1..."
sudo wg set $PEER1_IFACE listen-port 55820

log_info "Configuring peer2 ($PEER2_IFACE)..."
sudo ip addr add 10.0.0.2/24 dev $PEER2_IFACE
sudo ip link set $PEER2_IFACE up

log_info "Setting private key for peer2..."
echo "$PEER2_WG_PRIVATE" | sudo wg set $PEER2_IFACE private-key /dev/stdin

log_info "Setting listen port for peer2..."
sudo wg set $PEER2_IFACE listen-port 55821

log_success "Basic WireGuard interfaces configured"

log_section "Step 4: Set PQC Device Keys (using seeds)"

log_info "Setting PQC keys for peer1 from seed..."
sudo "$WG_PQC" set $PEER1_IFACE pqc-seed "$PEER1_DIR/pqc.seed"

log_info "Setting PQC keys for peer2 from seed..."
sudo "$WG_PQC" set $PEER2_IFACE pqc-seed "$PEER2_DIR/pqc.seed"

log_success "PQC device keys configured from seeds"

log_section "Step 5: Add Peers with PQC Public Keys (before endpoints)"

# IMPORTANT: We add peers and set PQC keys BEFORE adding endpoints
# to prevent a non-PQC handshake from being initiated

log_info "Adding peer2 to peer1 (without endpoint yet)..."
sudo wg set $PEER1_IFACE peer "$PEER2_WG_PUBLIC" \
    persistent-keepalive 25 \
    allowed-ips 10.0.0.2/32

log_info "Setting peer2's PQC public key on peer1..."
sudo "$WG_PQC" set $PEER1_IFACE peer "$PEER2_WG_PUBLIC" pqc-public-key "$PEER2_DIR/pqc-public.key"

log_info "Adding peer1 to peer2 (without endpoint yet)..."
sudo wg set $PEER2_IFACE peer "$PEER1_WG_PUBLIC" \
    persistent-keepalive 25 \
    allowed-ips 10.0.0.1/32

log_info "Setting peer1's PQC public key on peer2..."
sudo "$WG_PQC" set $PEER2_IFACE peer "$PEER1_WG_PUBLIC" pqc-public-key "$PEER1_DIR/pqc-public.key"

log_success "Peers configured with PQC public keys"

log_section "Step 6: Add Endpoints (triggers PQC handshake)"

log_info "Adding endpoint for peer2 on peer1 (will trigger handshake)..."
sudo wg set $PEER1_IFACE peer "$PEER2_WG_PUBLIC" endpoint 127.0.0.1:55821

log_info "Adding endpoint for peer1 on peer2..."
sudo wg set $PEER2_IFACE peer "$PEER1_WG_PUBLIC" endpoint 127.0.0.1:55820

log_success "Endpoints configured - handshake should now use PQC"

log_section "Step 7: Verify Configuration"

log_info "Peer1 ($PEER1_IFACE) WireGuard status:"
sudo wg show $PEER1_IFACE

echo ""
log_info "Peer1 ($PEER1_IFACE) PQC status:"
sudo "$WG_PQC" show $PEER1_IFACE

echo ""
log_info "Peer2 ($PEER2_IFACE) WireGuard status:"
sudo wg show $PEER2_IFACE

echo ""
log_info "Peer2 ($PEER2_IFACE) PQC status:"
sudo "$WG_PQC" show $PEER2_IFACE

log_section "Step 8: Test Connectivity"

log_info "Waiting for handshake to establish..."
sleep 5

log_info "Attempting ping from peer1 to peer2..."
if ping -c 3 -W 5 10.0.0.2; then
    log_success "Ping successful!"
else
    log_error "Ping failed"
    log_info "Checking if handshake occurred..."
    sudo wg show $PEER1_IFACE dump
fi

log_section "Step 9: Check Handshake Status"

log_info "Checking for handshake completion..."
PEER1_HANDSHAKE=$(sudo wg show $PEER1_IFACE latest-handshakes 2>/dev/null | awk '{print $2}')
PEER2_HANDSHAKE=$(sudo wg show $PEER2_IFACE latest-handshakes 2>/dev/null | awk '{print $2}')

if [ -n "$PEER1_HANDSHAKE" ] && [ "$PEER1_HANDSHAKE" != "0" ]; then
    log_success "Peer1 completed handshake at $(date -d @$PEER1_HANDSHAKE)"
else
    log_error "Peer1 has not completed handshake"
fi

if [ -n "$PEER2_HANDSHAKE" ] && [ "$PEER2_HANDSHAKE" != "0" ]; then
    log_success "Peer2 completed handshake at $(date -d @$PEER2_HANDSHAKE)"
else
    log_error "Peer2 has not completed handshake"
fi

log_section "Step 10: Verify PQC Handshake via UAPI"

log_info "Getting raw UAPI dump from peer1..."
echo "--- Peer1 UAPI ---"
sudo "$WG_PQC" get $PEER1_IFACE

echo ""
log_info "Getting raw UAPI dump from peer2..."
echo "--- Peer2 UAPI ---"
sudo "$WG_PQC" get $PEER2_IFACE

log_section "Step 11: Check Logs for PQC Activity"

log_info "Checking peer1 logs for PQC activity..."
echo "=== PQC Handshake Activity ==="
grep -i "pqc\|CreateMessagePQC\|ConsumePQC" "$PEER1_DIR/wg.log" 2>/dev/null | tail -20 || echo "No PQC handshake logs found"

echo ""
log_info "Checking peer2 logs for PQC activity..."
echo "=== PQC Handshake Activity ==="
grep -i "pqc\|CreateMessagePQC\|ConsumePQC" "$PEER2_DIR/wg.log" 2>/dev/null | tail -20 || echo "No PQC handshake logs found"

log_section "Test Complete"

log_info "Full peer1 status:"
sudo wg show $PEER1_IFACE

echo ""
log_info "Full peer2 status:"
sudo wg show $PEER2_IFACE

echo ""
log_info "Peer1 log (last 30 lines):"
tail -30 "$PEER1_DIR/wg.log"

echo ""
log_info "Peer2 log (last 30 lines):"
tail -30 "$PEER2_DIR/wg.log"

sudo wg show

log_info ""
log_info "Test will cleanup and exit in 30 seconds..."
log_info "Press Ctrl+C to cleanup immediately"
sleep 30
