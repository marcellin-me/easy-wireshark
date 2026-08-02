# Packet Scope CLI

An interactive macOS network-inspection CLI.

```text
npm run capture
  → choose a capture interface
  → choose an app/process with network sockets
  → view packets attributed to that process
  → inspect full Layer 1–7 records in captures/*.ndjson
```

## Requirements

- macOS
- Node.js 20 or newer
- TShark, installed with Wireshark
- `lsof` and `ifconfig`, included with macOS

Install Wireshark:

```bash
brew install --cask wireshark
```

Confirm that TShark can see capture interfaces:

```bash
tshark -D
```

## Run

```bash
npm run capture
```

No npm packages need to be installed; the CLI uses Node's built-in modules.

## How process attribution works

Packets captured through libpcap/BPF do not contain a process ID. Packet Scope therefore:

1. Uses `lsof` to read the selected process's current TCP and UDP sockets.
2. Refreshes the socket set several times per second.
3. Captures and dissects packets with TShark.
4. Matches each packet's protocol, local port, local address, and remote endpoint against the socket set.

Closed sockets remain eligible for five seconds so packets already in flight are not immediately lost.

## Output

The terminal displays compact packet summaries. Every matched packet is also written as one JSON object per line under `captures/`.

The JSON record includes:

- Interface and process metadata
- Direction: inbound or outbound
- OSI Layer 1 through Layer 7 when available
- Ethernet/Wi-Fi addresses
- IPv4/IPv6 headers
- TCP/UDP fields
- Inferred session information
- TLS/QUIC detection
- Application protocol and TShark summary
- Payload hex/ASCII preview
- Encryption classification: `encrypted`, `likely-plaintext`, or `unknown`

## Important limitations

- Process attribution is correlation, not kernel-provided packet metadata. Very short-lived sockets may be missed.
- Shared ports, socket handoff, proxies, VPNs, and system network extensions can make attribution ambiguous.
- Binary-looking data is not proof of encryption. Photos, videos, archives, and compressed data also appear unreadable.
- The strongest TLS verification is a recognized TLS/QUIC protocol plus the absence of known test markers in application data.
- Layer 1 information is generally unavailable in a standard macOS capture, and OSI Layers 5–7 are partly inferred.

For exact per-flow process attribution suitable for a production security product, the next step is a signed macOS Network Extension rather than `lsof` correlation.
