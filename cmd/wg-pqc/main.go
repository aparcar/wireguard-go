// SPDX-License-Identifier: MIT

package main

import (
	"bufio"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"strings"

	"github.com/tailscale/wireguard-go/device"
)

func printUsage() {
	fmt.Fprintf(os.Stderr, "Usage: %s <command> [arguments]\n", os.Args[0])
	fmt.Fprintf(os.Stderr, "\nCompact hybrid PQC handshake using:\n")
	fmt.Fprintf(os.Stderr, "  - McEliece6688128 for static keys (NIST Level 5, 256-bit security)\n")
	fmt.Fprintf(os.Stderr, "  - Kyber512 for ephemeral keys (NIST Level 1, forward secrecy)\n")
	fmt.Fprintf(os.Stderr, "\nCommands:\n")
	fmt.Fprintf(os.Stderr, "  genseed                             Generate a new PQC seed (32 bytes)\n")
	fmt.Fprintf(os.Stderr, "  pubkey                              Derive public key from seed (reads seed from stdin)\n")
	fmt.Fprintf(os.Stderr, "  set <interface> [options]           Configure PQC keys for an interface\n")
	fmt.Fprintf(os.Stderr, "  show <interface> [peer]             Show PQC configuration for an interface\n")
	fmt.Fprintf(os.Stderr, "  get <interface>                     Get raw UAPI configuration (for debugging)\n")
	fmt.Fprintf(os.Stderr, "\nSet command options:\n")
	fmt.Fprintf(os.Stderr, "  pqc-seed <file>                     Set device PQC keys from seed file (hex, 32 bytes)\n")
	fmt.Fprintf(os.Stderr, "  peer <public-key>                   Specify peer by WireGuard public key (base64)\n")
	fmt.Fprintf(os.Stderr, "  pqc-public-key <file>               Set peer's PQC public key (must follow peer)\n")
	fmt.Fprintf(os.Stderr, "\nExamples:\n")
	fmt.Fprintf(os.Stderr, "  # Generate a seed (32 bytes)\n")
	fmt.Fprintf(os.Stderr, "  %s genseed > pqc.seed\n", os.Args[0])
	fmt.Fprintf(os.Stderr, "\n  # Derive public key from seed (for sharing with peers)\n")
	fmt.Fprintf(os.Stderr, "  %s pubkey < pqc.seed > pqc-public.key\n", os.Args[0])
	fmt.Fprintf(os.Stderr, "\n  # Set device PQC keys from seed\n")
	fmt.Fprintf(os.Stderr, "  %s set wg0 pqc-seed pqc.seed\n", os.Args[0])
	fmt.Fprintf(os.Stderr, "\n  # Set peer's PQC public key\n")
	fmt.Fprintf(os.Stderr, "  %s set wg0 peer <base64-wg-pubkey> pqc-public-key peer-pqc-public.key\n", os.Args[0])
	fmt.Fprintf(os.Stderr, "\n  # Show PQC status\n")
	fmt.Fprintf(os.Stderr, "  %s show wg0\n", os.Args[0])
	fmt.Fprintf(os.Stderr, "\nKey Sizes:\n")
	fmt.Fprintf(os.Stderr, "  Seed:        %d bytes\n", device.NoisePQCSeedSize)
	fmt.Fprintf(os.Stderr, "  Private key: %d bytes\n", device.NoiseMcEliecePrivateKeySize)
	fmt.Fprintf(os.Stderr, "  Public key:  %d bytes (~1MB, pre-provision out-of-band)\n", device.NoiseMcEliecePublicKeySize)
}

func genseed() error {
	seed := make([]byte, device.NoisePQCSeedSize)
	if _, err := rand.Read(seed); err != nil {
		return fmt.Errorf("failed to generate random seed: %w", err)
	}
	fmt.Println(hex.EncodeToString(seed))
	return nil
}

func pubkey() error {
	// Read seed from stdin
	reader := bufio.NewReader(os.Stdin)
	line, err := reader.ReadString('\n')
	if err != nil && err != io.EOF {
		return fmt.Errorf("failed to read seed from stdin: %w", err)
	}
	seedHex := strings.TrimSpace(line)

	seed, err := hex.DecodeString(seedHex)
	if err != nil {
		return fmt.Errorf("invalid hex seed: %w", err)
	}
	if len(seed) != device.NoisePQCSeedSize {
		return fmt.Errorf("seed must be %d bytes, got %d", device.NoisePQCSeedSize, len(seed))
	}

	fmt.Fprintf(os.Stderr, "Deriving public key from seed (this may take a moment)...\n")
	publicKey, _, err := device.DeriveKeyPairFromSeed(seed)
	if err != nil {
		return fmt.Errorf("failed to derive keypair: %w", err)
	}

	fmt.Println(hex.EncodeToString(publicKey))
	return nil
}

func sendUAPICommand(sockPath, command string) error {
	// Connect to UAPI socket
	conn, err := net.Dial("unix", sockPath)
	if err != nil {
		return fmt.Errorf("failed to connect to UAPI socket: %w", err)
	}
	defer conn.Close()

	// Send command
	_, err = conn.Write([]byte(command))
	if err != nil {
		return fmt.Errorf("failed to send UAPI command: %w", err)
	}

	// Read response
	reader := bufio.NewReader(conn)
	response, err := reader.ReadString('\n')
	if err != nil && err != io.EOF {
		return fmt.Errorf("failed to read UAPI response: %w", err)
	}

	// Check for errors
	if strings.HasPrefix(response, "errno=") && !strings.HasPrefix(response, "errno=0") {
		return fmt.Errorf("UAPI error: %s", strings.TrimSpace(response))
	}

	return nil
}

func setCommand(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("missing interface name")
	}

	iface := args[0]
	args = args[1:]

	// Build UAPI socket path
	sockPath := fmt.Sprintf("/var/run/wireguard/%s.sock", iface)

	// Parse arguments
	var commands []string
	commands = append(commands, "set=1")

	inPeerContext := false

	for i := 0; i < len(args); i++ {
		arg := args[i]

		switch arg {
		case "pqc-seed":
			if i+1 >= len(args) {
				return fmt.Errorf("missing value for pqc-seed")
			}
			i++
			seedFile := args[i]

			// Read seed from file
			data, err := os.ReadFile(seedFile)
			if err != nil {
				return fmt.Errorf("failed to read PQC seed file: %w", err)
			}

			seedHex := strings.TrimSpace(string(data))

			// Validate it's valid hex
			seedBytes, err := hex.DecodeString(seedHex)
			if err != nil {
				return fmt.Errorf("failed to decode hex seed: %w", err)
			}

			if len(seedBytes) != device.NoisePQCSeedSize {
				return fmt.Errorf("invalid PQC seed length: expected %d bytes, got %d",
					device.NoisePQCSeedSize, len(seedBytes))
			}

			commands = append(commands, fmt.Sprintf("pqc_seed=%s", seedHex))

		case "peer":
			if i+1 >= len(args) {
				return fmt.Errorf("missing value for peer")
			}
			i++
			peerKey := args[i]

			// Convert base64 WireGuard public key to hex
			var noiseKey device.NoisePublicKey
			if err := noiseKey.FromHex(peerKey); err != nil {
				// Try base64 decode and convert to hex
				pubKeyBytes, err := base64.StdEncoding.DecodeString(peerKey)
				if err != nil {
					return fmt.Errorf("invalid peer public key: %w", err)
				}
				if len(pubKeyBytes) != 32 {
					return fmt.Errorf("invalid peer public key length: expected 32 bytes")
				}
				peerKey = hex.EncodeToString(pubKeyBytes)
			} else {
				peerKey = hex.EncodeToString(noiseKey[:])
			}

			inPeerContext = true
			commands = append(commands, fmt.Sprintf("public_key=%s", peerKey))

		case "pqc-public-key":
			if !inPeerContext {
				return fmt.Errorf("pqc-public-key must be used after peer (use pqc-seed for device keys)")
			}
			if i+1 >= len(args) {
				return fmt.Errorf("missing value for pqc-public-key")
			}
			i++
			pqcPubKeyFile := args[i]

			// Read public key from file
			data, err := os.ReadFile(pqcPubKeyFile)
			if err != nil {
				return fmt.Errorf("failed to read PQC public key file: %w", err)
			}

			pqcPubKeyHex := strings.TrimSpace(string(data))

			// Validate it's valid hex
			pqcPubKeyBytes, err := hex.DecodeString(pqcPubKeyHex)
			if err != nil {
				return fmt.Errorf("failed to decode hex PQC public key: %w", err)
			}

			// Validate PQC public key length
			if len(pqcPubKeyBytes) != device.NoiseMcEliecePublicKeySize {
				return fmt.Errorf("invalid PQC public key length: expected %d bytes, got %d",
					device.NoiseMcEliecePublicKeySize, len(pqcPubKeyBytes))
			}

			commands = append(commands, fmt.Sprintf("pqc_public_key=%s", pqcPubKeyHex))

		default:
			return fmt.Errorf("unknown option: %s", arg)
		}
	}

	// Build final command
	command := strings.Join(commands, "\n") + "\n\n"

	// Send to UAPI
	if err := sendUAPICommand(sockPath, command); err != nil {
		return err
	}

	fmt.Printf("Successfully configured PQC keys for interface %s\n", iface)
	return nil
}

func getCommand(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("missing interface name")
	}

	iface := args[0]

	// Build UAPI socket path
	sockPath := fmt.Sprintf("/var/run/wireguard/%s.sock", iface)

	// Connect to UAPI socket
	conn, err := net.Dial("unix", sockPath)
	if err != nil {
		return fmt.Errorf("failed to connect to UAPI socket: %w", err)
	}
	defer conn.Close()

	// Send get command
	_, err = conn.Write([]byte("get=1\n\n"))
	if err != nil {
		return fmt.Errorf("failed to send get command: %w", err)
	}

	// Read full response
	reader := bufio.NewReader(conn)
	var response strings.Builder
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				break
			}
			return fmt.Errorf("failed to read response: %w", err)
		}
		response.WriteString(line)
		// UAPI responses end with an empty line
		if line == "\n" || line == "errno=0\n" {
			break
		}
	}

	// Output the full response
	fmt.Print(response.String())
	return nil
}

func showCommand(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("missing interface name")
	}

	iface := args[0]

	// Build UAPI socket path
	sockPath := fmt.Sprintf("/var/run/wireguard/%s.sock", iface)

	// Connect to UAPI socket
	conn, err := net.Dial("unix", sockPath)
	if err != nil {
		return fmt.Errorf("failed to connect to UAPI socket: %w", err)
	}
	defer conn.Close()

	// Send get command
	_, err = conn.Write([]byte("get=1\n\n"))
	if err != nil {
		return fmt.Errorf("failed to send get command: %w", err)
	}

	// Read and parse UAPI response
	reader := bufio.NewReader(conn)
	var devicePQCKeyID string
	type PeerInfo struct {
		publicKey    string
		pqcPublicKey string
		pqcKeyID     string
	}
	var peers []PeerInfo
	var currentPeer *PeerInfo

	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				break
			}
			return fmt.Errorf("failed to read response: %w", err)
		}

		line = strings.TrimSpace(line)
		if line == "" || line == "errno=0" {
			break
		}

		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}

		key, value := parts[0], parts[1]

		switch key {
		case "pqc_key_id":
			if currentPeer == nil {
				// Device PQC key ID
				devicePQCKeyID = value
			} else {
				// Peer PQC key ID
				currentPeer.pqcKeyID = value
			}
		case "pqc_public_key":
			if currentPeer != nil {
				// Peer PQC public key (we just note it exists, don't print full key)
				currentPeer.pqcPublicKey = value
			}
		case "public_key":
			// New peer
			if currentPeer != nil {
				peers = append(peers, *currentPeer)
			}
			currentPeer = &PeerInfo{publicKey: value}
		}
	}

	// Add last peer if exists
	if currentPeer != nil {
		peers = append(peers, *currentPeer)
	}

	// Display output in wg-like format
	fmt.Printf("interface: %s\n", iface)

	if devicePQCKeyID != "" && devicePQCKeyID != strings.Repeat("0", len(devicePQCKeyID)) {
		fmt.Printf("  pqc key id: %s\n", devicePQCKeyID)
	} else {
		fmt.Printf("  pqc: not configured\n")
	}

	for _, peer := range peers {
		// Convert hex to base64 for display
		pubKeyBytes, _ := hex.DecodeString(peer.publicKey)
		pubKeyB64 := base64.StdEncoding.EncodeToString(pubKeyBytes)

		fmt.Printf("\npeer: %s\n", pubKeyB64)

		if peer.pqcKeyID != "" && peer.pqcKeyID != strings.Repeat("0", len(peer.pqcKeyID)) {
			fmt.Printf("  pqc key id: %s\n", peer.pqcKeyID)
		} else if peer.pqcPublicKey != "" && peer.pqcPublicKey != strings.Repeat("0", 16) {
			fmt.Printf("  pqc: configured (key ID not available)\n")
		} else {
			fmt.Printf("  pqc: not configured\n")
		}
	}

	return nil
}

func main() {
	// Parse command
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	command := os.Args[1]

	// Handle help flags
	if command == "-h" || command == "--help" || command == "help" {
		printUsage()
		os.Exit(0)
	}

	// Execute command
	var err error
	switch command {
	case "genseed":
		err = genseed()
	case "pubkey":
		err = pubkey()
	case "set":
		err = setCommand(os.Args[2:])
	case "show":
		err = showCommand(os.Args[2:])
	case "get":
		err = getCommand(os.Args[2:])
	default:
		fmt.Fprintf(os.Stderr, "Error: unknown command '%s'\n\n", command)
		printUsage()
		os.Exit(1)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
