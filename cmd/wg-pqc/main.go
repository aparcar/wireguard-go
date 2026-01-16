// SPDX-License-Identifier: MIT

package main

import (
	"bufio"
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
	fmt.Fprintf(os.Stderr, "  genkey                              Generate a new PQC keypair (slow, outputs to files)\n")
	fmt.Fprintf(os.Stderr, "  set <interface> [options]           Configure PQC keys for an interface\n")
	fmt.Fprintf(os.Stderr, "  show <interface> [peer]             Show PQC configuration for an interface\n")
	fmt.Fprintf(os.Stderr, "  get <interface>                     Get raw UAPI configuration (for debugging)\n")
	fmt.Fprintf(os.Stderr, "\nSet command options:\n")
	fmt.Fprintf(os.Stderr, "  pqc-private-key <file>              Set device PQC private key from file (hex-encoded)\n")
	fmt.Fprintf(os.Stderr, "  peer <public-key>                   Specify peer by WireGuard public key (base64)\n")
	fmt.Fprintf(os.Stderr, "  pqc-public-key <file>               Set peer's PQC public key from file (hex-encoded)\n")
	fmt.Fprintf(os.Stderr, "\nExamples:\n")
	fmt.Fprintf(os.Stderr, "  # Generate a new keypair (outputs pqc-private.key, pqc-public.key)\n")
	fmt.Fprintf(os.Stderr, "  %s genkey\n", os.Args[0])
	fmt.Fprintf(os.Stderr, "\n  # Set device PQC private key\n")
	fmt.Fprintf(os.Stderr, "  %s set wg0 pqc-private-key pqc-private.key\n", os.Args[0])
	fmt.Fprintf(os.Stderr, "\n  # Set peer's PQC public key\n")
	fmt.Fprintf(os.Stderr, "  %s set wg0 peer <base64-wg-pubkey> pqc-public-key peer-pqc-public.key\n", os.Args[0])
	fmt.Fprintf(os.Stderr, "\n  # Show PQC status\n")
	fmt.Fprintf(os.Stderr, "  %s show wg0\n", os.Args[0])
	fmt.Fprintf(os.Stderr, "\nKey Format:\n")
	fmt.Fprintf(os.Stderr, "  Private key: %d bytes\n", device.NoiseMcEliecePrivateKeySize)
	fmt.Fprintf(os.Stderr, "  Public key:  %d bytes (~1MB, pre-provision out-of-band)\n", device.NoiseMcEliecePublicKeySize)
}

func genkey() error {
	fmt.Fprintf(os.Stderr, "Generating McEliece6688128 keypair (this may take a moment)...\n")

	publicKey, privateKey, err := device.GeneratePQCStaticKeypair()
	if err != nil {
		return fmt.Errorf("failed to generate PQC keypair: %w", err)
	}

	// Write private key (hex-encoded)
	if err := os.WriteFile("pqc-private.key", []byte(hex.EncodeToString(privateKey)+"\n"), 0600); err != nil {
		return fmt.Errorf("failed to write private key: %w", err)
	}

	// Write public key (hex-encoded)
	if err := os.WriteFile("pqc-public.key", []byte(hex.EncodeToString(publicKey)+"\n"), 0644); err != nil {
		return fmt.Errorf("failed to write public key: %w", err)
	}

	fmt.Printf("Generated PQC keypair:\n")
	fmt.Printf("  Private key: pqc-private.key (%d bytes)\n", len(privateKey))
	fmt.Printf("  Public key:  pqc-public.key (%d bytes)\n", len(publicKey))
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

	var currentPeer string

	for i := 0; i < len(args); i++ {
		arg := args[i]

		switch arg {
		case "pqc-private-key":
			if i+1 >= len(args) {
				return fmt.Errorf("missing value for pqc-private-key")
			}
			i++
			keyFile := args[i]

			// Read private key from file
			data, err := os.ReadFile(keyFile)
			if err != nil {
				return fmt.Errorf("failed to read private PQC key file: %w", err)
			}

			privKeyHex := strings.TrimSpace(string(data))

			// Validate it's valid hex
			privKeyBytes, err := hex.DecodeString(privKeyHex)
			if err != nil {
				return fmt.Errorf("failed to decode hex private key: %w", err)
			}

			if len(privKeyBytes) != device.NoiseMcEliecePrivateKeySize {
				return fmt.Errorf("invalid private PQC key length: expected %d bytes, got %d",
					device.NoiseMcEliecePrivateKeySize, len(privKeyBytes))
			}

			commands = append(commands, fmt.Sprintf("pqc_private_key=%s", privKeyHex))

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

			currentPeer = peerKey
			commands = append(commands, fmt.Sprintf("public_key=%s", peerKey))

		case "pqc-public-key":
			if i+1 >= len(args) {
				return fmt.Errorf("missing value for pqc-public-key")
			}
			if currentPeer == "" {
				return fmt.Errorf("pqc-public-key must be used after peer")
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
	case "genkey":
		err = genkey()
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
