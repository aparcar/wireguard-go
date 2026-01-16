# Go Implementation of [WireGuard](https://www.wireguard.com/)

This is an implementation of WireGuard in Go.

## Post-Quantum Cryptography (PQC) Support

This fork includes experimental support for a **compact hybrid post-quantum handshake** that fits within a single IPv6 MTU frame (1280 bytes). The implementation uses:

- **McEliece6688128** for static keys (NIST Level 5, 256-bit security)
- **Kyber512** for ephemeral keys (NIST Level 1, 128-bit forward secrecy)

### How It Works

The PQC handshake extends the standard WireGuard Noise protocol with post-quantum key encapsulation:

1. McEliece public keys (~1MB) are **pre-provisioned out-of-band** (not transmitted in handshake)
2. Only McEliece ciphertexts (208 bytes) are transmitted
3. Kyber512 provides ephemeral forward secrecy with 800-byte public keys and 768-byte ciphertexts
4. Both X25519 and PQC key material are mixed into the final session keys

**Message sizes:**

- PQC Initiation: 1204 bytes (fits in IPv6 MTU with 28 bytes headroom)
- PQC Response: 1068 bytes (fits in IPv6 MTU with 164 bytes headroom)

### Using wg-pqc

The `wg-pqc` tool manages PQC keys using **seed-based key generation**, which allows storing just a 32-byte seed instead of the full ~14KB private key:

```bash
# Generate a new PQC seed (32 bytes)
$ wg-pqc genseed > pqc.seed

# Derive public key from seed (for sharing with peers)
$ wg-pqc pubkey < pqc.seed > pqc-public.key

# Configure device PQC keys from seed
$ wg-pqc set wg0 pqc-seed pqc.seed

# Configure peer's PQC public key
$ wg-pqc set wg0 peer <base64-wg-pubkey> pqc-public-key peer-pqc-public.key

# Show PQC configuration
$ wg-pqc show wg0
```

### Key Sizes

| Key Type    | Size                   | Notes                                 |
| ----------- | ---------------------- | ------------------------------------- |
| Seed        | 32 bytes               | Stored in config files                |
| Private key | 13,932 bytes           | Derived from seed                     |
| Public key  | 1,044,992 bytes (~1MB) | Must be shared with peers out-of-band |

### Key Distribution

Since McEliece public keys are ~1MB, they must be exchanged out-of-band before establishing a connection. Typical approaches:

- Include in configuration management systems
- Distribute via secure file transfer
- Embed in provisioning systems

### Testing PQC Handshake

A test script is provided to verify PQC handshakes between two local wireguard-go instances:

```bash
# Run the PQC handshake test (requires root on Linux)
$ sudo ./test-pqc-handshake.sh
```

The test creates two WireGuard interfaces, configures PQC keys using seeds, and verifies that the handshake uses the PQC protocol (1204-byte initiation, 1068-byte response).

## Usage

Most Linux kernel WireGuard users are used to adding an interface with `ip link add wg0 type wireguard`. With wireguard-go, instead simply run:

```
$ wireguard-go wg0
```

This will create an interface and fork into the background. To remove the interface, use the usual `ip link del wg0`, or if your system does not support removing interfaces directly, you may instead remove the control socket via `rm -f /var/run/wireguard/wg0.sock`, which will result in wireguard-go shutting down.

To run wireguard-go without forking to the background, pass `-f` or `--foreground`:

```
$ wireguard-go -f wg0
```

When an interface is running, you may use [`wg(8)`](https://git.zx2c4.com/wireguard-tools/about/src/man/wg.8) to configure it, as well as the usual `ip(8)` and `ifconfig(8)` commands.

To run with more logging you may set the environment variable `LOG_LEVEL=debug`.

## Platforms

### Linux

This will run on Linux; however you should instead use the kernel module, which is faster and better integrated into the OS. See the [installation page](https://www.wireguard.com/install/) for instructions.

### macOS

This runs on macOS using the utun driver. It does not yet support sticky sockets, and won't support fwmarks because of Darwin limitations. Since the utun driver cannot have arbitrary interface names, you must either use `utun[0-9]+` for an explicit interface name or `utun` to have the kernel select one for you. If you choose `utun` as the interface name, and the environment variable `WG_TUN_NAME_FILE` is defined, then the actual name of the interface chosen by the kernel is written to the file specified by that variable.

### Windows

This runs on Windows, but you should instead use it from the more [fully featured Windows app](https://git.zx2c4.com/wireguard-windows/about/), which uses this as a module.

### FreeBSD

This will run on FreeBSD. It does not yet support sticky sockets. Fwmark is mapped to `SO_USER_COOKIE`.

### OpenBSD

This will run on OpenBSD. It does not yet support sticky sockets. Fwmark is mapped to `SO_RTABLE`. Since the tun driver cannot have arbitrary interface names, you must either use `tun[0-9]+` for an explicit interface name or `tun` to have the program select one for you. If you choose `tun` as the interface name, and the environment variable `WG_TUN_NAME_FILE` is defined, then the actual name of the interface chosen by the kernel is written to the file specified by that variable.

## Building

This requires an installation of the latest version of [Go](https://go.dev/).

```
$ git clone https://git.zx2c4.com/wireguard-go
$ cd wireguard-go
$ make
```

## License

    Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
    
    Permission is hereby granted, free of charge, to any person obtaining a copy of
    this software and associated documentation files (the "Software"), to deal in
    the Software without restriction, including without limitation the rights to
    use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
    of the Software, and to permit persons to whom the Software is furnished to do
    so, subject to the following conditions:
    
    The above copyright notice and this permission notice shall be included in all
    copies or substantial portions of the Software.
    
    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
    SOFTWARE.
