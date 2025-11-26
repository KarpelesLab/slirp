# slirp

A user-mode NAT (Network Address Translation) implementation in Go, providing TCP/IP connectivity without requiring root privileges or virtual network interfaces.

## Overview

This library implements a lightweight, user-space networking stack that intercepts IPv4 packets and translates them to real network connections. It's similar to the original SLIRP project and is useful for:

- Virtual machine networking without elevated privileges
- Network virtualization and testing
- Containerized applications requiring network isolation
- Educational purposes and protocol learning

## Features

- **TCP Connection Handling**: Full TCP state machine with flow control, windowing, and retransmission
- **UDP Support**: Stateless UDP packet forwarding with connection tracking
- **Automatic Cleanup**: Background maintenance for idle connection cleanup
- **Thread-Safe**: Concurrent handling of multiple connections
- **Zero Dependencies**: Uses only Go standard library

## Installation

```bash
go get github.com/KarpelesLab/slirp
```

## Usage

### Basic Example

```go
package main

import (
    "github.com/KarpelesLab/slirp"
)

func main() {
    // Create a new NAT stack
    stack := slirp.New()

    // Define your packet writer callback
    // This function receives complete Ethernet frames to send back to the client
    writer := func(frame []byte) error {
        // Send the frame to your virtual network interface
        // e.g., write to a TAP device or send via a socket
        return nil
    }

    // Process incoming IPv4 packets from your client
    // clientMAC: MAC address of the client (for Ethernet frame destination)
    // gwMAC: Gateway MAC address (for Ethernet frame source)
    // ipPacket: Raw IPv4 packet data (starting at IP header)
    // ns: Namespace identifier (use 0 if not using namespaces)

    var clientMAC [6]byte = [6]byte{0x52, 0x54, 0x00, 0x12, 0x34, 0x56}
    var gwMAC [6]byte = [6]byte{0x52, 0x54, 0x00, 0x12, 0x34, 0x57}

    // Handle each packet
    err := stack.HandleOutboundIPv4(0, clientMAC, gwMAC, ipPacket, writer)
    if err != nil {
        // Handle error
    }
}
```

### Integration Example

```go
// Example: Integration with a TAP device or packet source
func handleClientPackets(stack *slirp.Stack, packetSource <-chan []byte) {
    clientMAC := [6]byte{0x52, 0x54, 0x00, 0x12, 0x34, 0x56}
    gwMAC := [6]byte{0x52, 0x54, 0x00, 0x12, 0x34, 0x57}

    writer := func(frame []byte) error {
        // Send frame back to client
        return sendToTAPDevice(frame)
    }

    for packet := range packetSource {
        // Extract IP packet from Ethernet frame if needed
        ipPacket := extractIPPacket(packet)

        err := stack.HandleOutboundIPv4(0, clientMAC, gwMAC, ipPacket, writer)
        if err != nil {
            log.Printf("Error handling packet: %v", err)
        }
    }
}
```

### Virtual Listeners

The library supports virtual TCP listeners that allow services to run entirely within the slirp stack, enabling fully user-land testing by connecting multiple slirp stacks together.

```go
package main

import (
    "fmt"
    "io"
    "log"
    "github.com/KarpelesLab/slirp"
)

func main() {
    stack := slirp.New()

    // Create a virtual listener on a virtual IP address
    listener, err := stack.Listen("tcp", "10.0.0.1:8080")
    if err != nil {
        log.Fatal(err)
    }
    defer listener.Close()

    // Accept connections in a goroutine
    go func() {
        for {
            conn, err := listener.Accept()
            if err != nil {
                return
            }

            // Handle connection (echo server example)
            go func(c net.Conn) {
                defer c.Close()
                io.Copy(c, c) // Echo back
            }(conn)
        }
    }()

    // Process incoming packets that connect to 10.0.0.1:8080
    // The stack will route them to the virtual listener
    clientMAC := [6]byte{0x52, 0x54, 0x00, 0x12, 0x34, 0x56}
    gwMAC := [6]byte{0x52, 0x54, 0x00, 0x12, 0x34, 0x57}

    writer := func(frame []byte) error {
        // Send frame back to client
        return sendToClient(frame)
    }

    // When client sends SYN to 10.0.0.1:8080, it will trigger Accept()
    for packet := range packetSource {
        err := stack.HandleOutboundIPv4(0, clientMAC, gwMAC, packet, writer)
        if err != nil {
            log.Printf("Error: %v", err)
        }
    }
}
```

#### Testing with Two Slirp Stacks

Virtual listeners enable fully user-land integration testing:

```go
func TestTwoStackCommunication(t *testing.T) {
    stack1 := slirp.New()
    stack2 := slirp.New()

    // Stack2 listens on virtual address
    listener, _ := stack2.Listen("tcp", "10.0.0.2:9000")

    // Server on stack2
    go func() {
        conn, _ := listener.Accept()
        defer conn.Close()

        buf := make([]byte, 1024)
        n, _ := conn.Read(buf)
        conn.Write(buf[:n]) // Echo
    }()

    // Client on stack1 sends packets to stack2's virtual address
    // Packets from stack1 are forwarded to stack2 via the writer callbacks
    // This enables testing without real network interfaces
}
```

## API Reference

### Types

#### `Stack`

The main NAT stack that manages TCP and UDP connections.

```go
func New() *Stack
```

Creates a new NAT stack instance. Automatically starts a background maintenance goroutine for connection cleanup.

#### `Writer`

Callback function type for sending Ethernet frames back to the client.

```go
type Writer func([]byte) error
```

### Methods

#### `HandleOutboundIPv4`

```go
func (s *Stack) HandleOutboundIPv4(ns uintptr, clientMAC [6]byte, gwMAC [6]byte, ip []byte, w Writer) error
```

Processes an outbound IPv4 packet from a client.

**Parameters:**
- `ns`: Namespace identifier for connection isolation (use 0 for single namespace)
- `clientMAC`: Client's MAC address (used as destination in response frames)
- `gwMAC`: Gateway MAC address (used as source in response frames)
- `ip`: Raw IPv4 packet data (must start at IP header, not Ethernet header)
- `w`: Writer callback for sending response frames

**Returns:**
- `error`: Error if packet is malformed or processing fails

**Supported Protocols:**
- TCP (protocol 6)
- UDP (protocol 17)
- Virtual TCP listeners (packets destined for registered virtual addresses)

#### `Listen`

```go
func (s *Stack) Listen(network, address string) (*Listener, error)
```

Creates a virtual TCP listener on a virtual network address within the slirp stack.

**Parameters:**
- `network`: Must be "tcp" or "tcp4"
- `address`: Virtual IP:port to listen on (e.g., "10.0.0.1:8080")

**Returns:**
- `*Listener`: A listener that implements the `net.Listener` interface
- `error`: Error if the address is invalid or already in use

**Example:**
```go
listener, err := stack.Listen("tcp", "192.168.100.1:9000")
if err != nil {
    log.Fatal(err)
}
defer listener.Close()

conn, err := listener.Accept()
// Handle connection...
```

#### `Listener`

Virtual listener type that implements `net.Listener`:

**Methods:**
- `Accept() (net.Conn, error)`: Waits for and returns the next connection
- `Close() error`: Closes the listener
- `Addr() net.Addr`: Returns the listener's network address

#### `VirtualConn`

Virtual connection type that implements `net.Conn`. Returned by `Listener.Accept()`.

**Methods:**
- `Read(b []byte) (int, error)`: Reads data from the connection
- `Write(b []byte) (int, error)`: Writes data to the connection
- `Close() error`: Closes the connection
- `LocalAddr() net.Addr`: Returns the local network address
- `RemoteAddr() net.Addr`: Returns the remote network address
- `SetDeadline(t time.Time) error`: Not implemented
- `SetReadDeadline(t time.Time) error`: Not implemented
- `SetWriteDeadline(t time.Time) error`: Not implemented

## Implementation Details

### TCP Handling

The library implements a simplified TCP state machine:

1. **Connection Establishment**: SYN packets trigger real TCP connections to destination hosts
2. **Data Transfer**: In-order data delivery with flow control based on receive window
3. **Flow Control**: Respects client's advertised window size, implements backpressure
4. **Connection Teardown**: Proper FIN handling for graceful connection closure
5. **MSS Negotiation**: Parses and respects Maximum Segment Size from client SYN

**Features:**
- Automatic retransmission for window probe
- Send queue buffering (up to 1MB per connection)
- Idle timeout: 2 minutes
- Maintenance interval: 5 seconds

### UDP Handling

UDP connections are tracked for bi-directional packet forwarding:

1. Creates real UDP socket on first packet to destination
2. Forwards packets between client and destination
3. Maintains connection tracking for responses
4. Idle timeout: 60 seconds

### Connection Cleanup

A background goroutine runs every 30 seconds to clean up:
- TCP connections idle for >2 minutes or marked as closed
- UDP connections idle for >60 seconds

## Performance Considerations

- **Memory**: Each TCP connection buffers up to 1MB of send data
- **Goroutines**: 2 goroutines per TCP connection (reader + maintenance), 1 per UDP connection
- **Thread Safety**: All operations are protected by mutexes for concurrent access
- **Packet Processing**: Minimal copying, operates directly on provided buffers where possible

## Limitations

- IPv4 only (no IPv6 support)
- No ICMP support (ping won't work through the NAT)
- No IP fragmentation handling
- Simplified TCP implementation (no congestion control, limited retransmission)
- No support for TCP options beyond MSS

## License

MIT License - See LICENSE file for details

Copyright (c) 2025 Karpelès Lab Inc.

## Contributing

Contributions are welcome! Please ensure:
- Code follows Go conventions and passes `go vet`
- New features include tests
- Public APIs are documented

## Related Projects

- [slirp](https://gitlab.freedesktop.org/slirp/libslirp) - Original SLIRP library
- [gvisor](https://github.com/google/gvisor) - More complete userspace network stack

## Support

For bugs and feature requests, please open an issue on GitHub.
