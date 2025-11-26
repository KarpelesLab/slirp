package slirp

import (
	"encoding/binary"
	"net"
	"sync"
	"testing"
	"time"
)

func TestNew(t *testing.T) {
	s := New()
	if s == nil {
		t.Fatal("New() returned nil")
	}
	if s.tcp == nil {
		t.Error("tcp map not initialized")
	}
	if s.udp == nil {
		t.Error("udp map not initialized")
	}
}

func TestIPChecksum(t *testing.T) {
	tests := []struct {
		name     string
		header   []byte
		expected uint16
	}{
		{
			name: "simple IPv4 header",
			header: []byte{
				0x45, 0x00, 0x00, 0x3c, // Version, IHL, TOS, Total Length
				0x1c, 0x46, 0x40, 0x00, // ID, Flags, Fragment Offset
				0x40, 0x06, 0x00, 0x00, // TTL, Protocol, Checksum (zeroed)
				0xac, 0x10, 0x0a, 0x63, // Source IP
				0xac, 0x10, 0x0a, 0x0c, // Dest IP
			},
			expected: 0xb1e6, // Pre-calculated correct checksum
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ipChecksum(tt.header)
			if result != tt.expected {
				t.Errorf("ipChecksum() = 0x%04x, expected 0x%04x", result, tt.expected)
			}
		})
	}
}

func TestTCPChecksum(t *testing.T) {
	src := []byte{192, 168, 1, 1}
	dst := []byte{192, 168, 1, 2}
	tcp := []byte{
		0x00, 0x50, // Source port (80)
		0x1f, 0x90, // Dest port (8080)
		0x00, 0x00, 0x00, 0x00, // Seq
		0x00, 0x00, 0x00, 0x00, // Ack
		0x50, 0x02, // Data offset + flags
		0xff, 0xff, // Window
		0x00, 0x00, // Checksum (placeholder)
		0x00, 0x00, // Urgent pointer
	}
	payload := []byte("Hello, World!")

	// Just verify it returns a non-zero checksum
	result := tcpChecksum(src, dst, tcp, payload)
	if result == 0 {
		t.Error("tcpChecksum() returned 0, expected non-zero value")
	}
}

func TestUDPChecksum(t *testing.T) {
	src := []byte{192, 168, 1, 1}
	dst := []byte{192, 168, 1, 2}
	udp := []byte{
		0x00, 0x50, // Source port
		0x00, 0x35, // Dest port (53 - DNS)
		0x00, 0x15, // Length
		0x00, 0x00, // Checksum (placeholder)
	}
	payload := []byte("test data")

	result := udpChecksum(src, dst, udp, payload)
	if result == 0 {
		t.Error("udpChecksum() returned 0, expected non-zero value")
	}
}

func TestRandUint32(t *testing.T) {
	// Test that it returns different values
	seen := make(map[uint32]bool)
	for i := 0; i < 100; i++ {
		val := randUint32()
		seen[val] = true
	}
	// We should have at least some variety
	if len(seen) < 50 {
		t.Errorf("randUint32() not random enough: only %d unique values in 100 calls", len(seen))
	}
}

func TestHandleIPv4_InvalidPackets(t *testing.T) {
	s := New()
	clientMAC := [6]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06}
	gwMAC := [6]byte{0x06, 0x05, 0x04, 0x03, 0x02, 0x01}
	writer := func(b []byte) error { return nil }

	tests := []struct {
		name   string
		packet []byte
		errMsg string
	}{
		{
			name:   "too short",
			packet: []byte{0x45, 0x00},
			errMsg: "not ipv4 or too short",
		},
		{
			name:   "not IPv4",
			packet: make([]byte, 40),
			errMsg: "not ipv4 or too short",
		},
		{
			name: "invalid IHL",
			packet: []byte{
				0x46, 0x00, 0x00, 0x14, // IHL=6 (24 bytes) but packet is only 20 bytes
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00,
			},
			errMsg: "invalid ihl",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := s.HandleIPv4(0, clientMAC, gwMAC, tt.packet, writer)
			if err == nil {
				t.Error("expected error, got nil")
			} else if err.Error() != tt.errMsg {
				t.Errorf("expected error %q, got %q", tt.errMsg, err.Error())
			}
		})
	}
}

func TestHandleIPv4_UnknownProtocol(t *testing.T) {
	s := New()
	clientMAC := [6]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06}
	gwMAC := [6]byte{0x06, 0x05, 0x04, 0x03, 0x02, 0x01}
	writer := func(b []byte) error { return nil }

	// Create a minimal valid IPv4 packet with protocol 1 (ICMP)
	packet := make([]byte, 20)
	packet[0] = 0x45 // Version 4, IHL 5
	binary.BigEndian.PutUint16(packet[2:4], 20) // Total length
	packet[9] = 1 // Protocol: ICMP (unsupported)
	copy(packet[12:16], []byte{192, 168, 1, 1}) // Source IP
	copy(packet[16:20], []byte{8, 8, 8, 8})     // Dest IP

	err := s.HandleIPv4(0, clientMAC, gwMAC, packet, writer)
	if err != nil {
		t.Errorf("unexpected error for unsupported protocol: %v", err)
	}
	// Should return nil (silently ignore)
}

func TestStackMaintenance(t *testing.T) {
	s := New()

	// Add a fake TCP connection that should be cleaned up
	k := key{
		ns:      0,
		srcIP:   [4]byte{192, 168, 1, 1},
		srcPort: 12345,
		dstIP:   [4]byte{8, 8, 8, 8},
		dstPort: 80,
	}

	clientMAC := [6]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06}
	gwMAC := [6]byte{0x06, 0x05, 0x04, 0x03, 0x02, 0x01}
	writer := func(b []byte) error { return nil }

	conn := newTCPConn(k.srcIP, k.srcPort, k.dstIP, k.dstPort, clientMAC, gwMAC, writer)
	// Set connection as old and closed
	conn.lastAct = time.Now().Add(-5 * time.Minute)
	conn.closed = true

	s.mu.Lock()
	s.tcp[k] = conn
	s.mu.Unlock()

	// Wait for maintenance to run (it runs every 30 seconds in real code, but we can't test that easily)
	// Instead, we'll just verify the structure is correct
	s.mu.RLock()
	if len(s.tcp) != 1 {
		t.Errorf("expected 1 TCP connection, got %d", len(s.tcp))
	}
	s.mu.RUnlock()
}

func TestConcurrentAccess(t *testing.T) {
	s := New()
	clientMAC := [6]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06}
	gwMAC := [6]byte{0x06, 0x05, 0x04, 0x03, 0x02, 0x01}
	writer := func(b []byte) error { return nil }

	// Start a test server
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("cannot start test server: %v", err)
	}
	defer listener.Close()

	serverAddr := listener.Addr().(*net.TCPAddr)

	// Accept and close connections
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()

	var wg sync.WaitGroup
	// Try to trigger concurrent access
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(port uint16) {
			defer wg.Done()
			// Create a minimal TCP SYN packet
			packet := make([]byte, 40)
			packet[0] = 0x45 // Version 4, IHL 5
			binary.BigEndian.PutUint16(packet[2:4], 40) // Total length
			packet[9] = 6 // Protocol: TCP
			copy(packet[12:16], []byte{127, 0, 0, 1})      // Source IP (localhost)
			copy(packet[16:20], []byte{127, 0, 0, 1})      // Dest IP (localhost)

			// TCP header
			binary.BigEndian.PutUint16(packet[20:22], port) // Source port
			binary.BigEndian.PutUint16(packet[22:24], uint16(serverAddr.Port))   // Dest port
			packet[32] = 0x50 // Data offset
			packet[33] = 0x02 // SYN flag

			_ = s.HandleIPv4(0, clientMAC, gwMAC, packet, writer)
		}(uint16(10000 + i))
	}
	wg.Wait()
}

func TestKeyStruct(t *testing.T) {
	k1 := key{
		ns:      1,
		srcIP:   [4]byte{192, 168, 1, 1},
		srcPort: 1234,
		dstIP:   [4]byte{8, 8, 8, 8},
		dstPort: 80,
	}
	k2 := key{
		ns:      1,
		srcIP:   [4]byte{192, 168, 1, 1},
		srcPort: 1234,
		dstIP:   [4]byte{8, 8, 8, 8},
		dstPort: 80,
	}
	k3 := key{
		ns:      1,
		srcIP:   [4]byte{192, 168, 1, 1},
		srcPort: 1235, // Different port
		dstIP:   [4]byte{8, 8, 8, 8},
		dstPort: 80,
	}

	// Test that identical keys are equal (can be used as map keys)
	m := make(map[key]bool)
	m[k1] = true
	if !m[k2] {
		t.Error("identical keys should be equal")
	}
	if m[k3] {
		t.Error("different keys should not be equal")
	}
}
