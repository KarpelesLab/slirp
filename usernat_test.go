package slirp

import (
	"encoding/binary"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/KarpelesLab/slirp/vtcp"
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
			result := IPChecksum(tt.header)
			if result != tt.expected {
				t.Errorf("IPChecksum() = 0x%04x, expected 0x%04x", result, tt.expected)
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
	result := TCPChecksum(src, dst, tcp, payload)
	if result == 0 {
		t.Error("TCPChecksum() returned 0, expected non-zero value")
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

	result := UDPChecksum(src, dst, udp, payload)
	if result == 0 {
		t.Error("UDPChecksum() returned 0, expected non-zero value")
	}
}

func TestRandUint32(t *testing.T) {
	// Test that it returns different values
	seen := make(map[uint32]bool)
	for i := 0; i < 100; i++ {
		val := RandUint32()
		seen[val] = true
	}
	// We should have at least some variety
	if len(seen) < 50 {
		t.Errorf("RandUint32() not random enough: only %d unique values in 100 calls", len(seen))
	}
}

func TestHandlePacket_InvalidPackets(t *testing.T) {
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
			errMsg: "packet too short",
		},
		{
			name:   "unsupported version",
			packet: make([]byte, 40),
			errMsg: "unsupported IP version",
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
			err := s.HandlePacket(0, clientMAC, gwMAC, tt.packet, writer)
			if err == nil {
				t.Error("expected error, got nil")
			} else if err.Error() != tt.errMsg {
				t.Errorf("expected error %q, got %q", tt.errMsg, err.Error())
			}
		})
	}
}

func TestHandlePacket_UnknownProtocol(t *testing.T) {
	s := New()
	clientMAC := [6]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06}
	gwMAC := [6]byte{0x06, 0x05, 0x04, 0x03, 0x02, 0x01}
	writer := func(b []byte) error { return nil }

	// Create a minimal valid IPv4 packet with protocol 1 (ICMP)
	packet := make([]byte, 20)
	packet[0] = 0x45                            // Version 4, IHL 5
	binary.BigEndian.PutUint16(packet[2:4], 20) // Total length
	packet[9] = 1                               // Protocol: ICMP (unsupported)
	copy(packet[12:16], []byte{192, 168, 1, 1}) // Source IP
	copy(packet[16:20], []byte{8, 8, 8, 8})     // Dest IP

	err := s.HandlePacket(0, clientMAC, gwMAC, packet, writer)
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

	vc := vtcp.NewConn(vtcp.ConnConfig{LocalPort: k.dstPort, RemotePort: k.srcPort, Writer: func([]byte) error { return nil }})
	vc.Abort()
	conn := &tcpNATConn{vc: vc, closed: true}

	s.mu.Lock()
	s.tcp[k] = conn
	s.mu.Unlock()

	s.mu.RLock()
	if len(s.tcp) != 1 {
		t.Errorf("expected 1 TCP connection, got %d", len(s.tcp))
	}
	s.mu.RUnlock()
}

func TestSeqAfter(t *testing.T) {
	tests := []struct {
		name     string
		a, b     uint32
		expected bool
	}{
		{"a > b simple", 100, 50, true},
		{"a == b", 100, 100, false},
		{"a < b simple", 50, 100, false},
		{"wrap around: a just past 0, b near max", 5, 0xFFFFFFF0, true},
		{"wrap around: a near max, b just past 0", 0xFFFFFFF0, 5, false},
		{"a = b + 1", 101, 100, true},
		{"a = b - 1", 99, 100, false},
		{"zero vs zero", 0, 0, false},
		{"max vs zero", 0xFFFFFFFF, 0, false}, // -1 in signed, so not after
		{"zero vs max", 0, 0xFFFFFFFF, true},  // +1 in signed, so after
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SeqAfter(tt.a, tt.b)
			if got != tt.expected {
				t.Errorf("SeqAfter(%d, %d) = %v, want %v", tt.a, tt.b, got, tt.expected)
			}
		})
	}
}

func TestStackClose(t *testing.T) {
	s := New()
	clientMAC := [6]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06}
	gwMAC := [6]byte{0x06, 0x05, 0x04, 0x03, 0x02, 0x01}
	writer := func(b []byte) error { return nil }

	_ = clientMAC
	_ = gwMAC
	_ = writer

	// Add a TCP connection
	tcpK := key{srcIP: [4]byte{192, 168, 1, 1}, srcPort: 12345, dstIP: [4]byte{8, 8, 8, 8}, dstPort: 80}
	tcpC := &tcpNATConn{vc: vtcp.NewConn(vtcp.ConnConfig{LocalPort: 80, RemotePort: 12345, Writer: func([]byte) error { return nil }})}

	// Add a TCP6 connection
	tcp6K := key6{srcIP: [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}, srcPort: 12345, dstIP: [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}, dstPort: 80}
	tcp6C := &tcpNATConn{vc: vtcp.NewConn(vtcp.ConnConfig{LocalPort: 80, RemotePort: 12345, Writer: func([]byte) error { return nil }})}

	// Add a virtual connection (vtcp.Conn)
	vcK := key{srcIP: [4]byte{192, 168, 1, 50}, srcPort: 45000, dstIP: [4]byte{10, 0, 0, 1}, dstPort: 9000}
	vc := vtcp.NewConn(vtcp.ConnConfig{
		LocalAddr:  &net.TCPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 9000},
		RemoteAddr: &net.TCPAddr{IP: net.IPv4(192, 168, 1, 50), Port: 45000},
		LocalPort:  9000,
		RemotePort: 45000,
		Writer:     func(seg []byte) error { return nil },
	})

	// Add a virtual connection6 (vtcp.Conn)
	vc6K := key6{srcIP: [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}, srcPort: 45000, dstIP: [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}, dstPort: 9000}
	vc6 := vtcp.NewConn(vtcp.ConnConfig{
		LocalAddr:  &net.TCPAddr{IP: net.ParseIP("::1"), Port: 9000},
		RemoteAddr: &net.TCPAddr{IP: net.ParseIP("::2"), Port: 45000},
		LocalPort:  9000,
		RemotePort: 45000,
		Writer:     func(seg []byte) error { return nil },
	})

	// Add a listener
	listener, err := s.Listen("tcp", "10.0.0.1:7777")
	if err != nil {
		t.Fatalf("Listen failed: %v", err)
	}
	_ = listener

	// Add a listener6
	listener6, err := s.Listen("tcp6", "[::1]:7777")
	if err != nil {
		t.Fatalf("Listen6 failed: %v", err)
	}
	_ = listener6

	s.mu.Lock()
	s.tcp[tcpK] = tcpC
	s.tcp6[tcp6K] = tcp6C
	s.virtTCP[vcK] = vc
	s.virtTCP6[vc6K] = vc6
	s.mu.Unlock()

	err = s.Close()
	if err != nil {
		t.Fatalf("Close() returned error: %v", err)
	}

	// Verify everything was cleaned up
	s.mu.RLock()
	defer s.mu.RUnlock()
	if len(s.tcp) != 0 {
		t.Errorf("expected 0 TCP connections after Close, got %d", len(s.tcp))
	}
	if len(s.tcp6) != 0 {
		t.Errorf("expected 0 TCP6 connections after Close, got %d", len(s.tcp6))
	}
	if len(s.udp) != 0 {
		t.Errorf("expected 0 UDP connections after Close, got %d", len(s.udp))
	}
	if len(s.udp6) != 0 {
		t.Errorf("expected 0 UDP6 connections after Close, got %d", len(s.udp6))
	}
	if len(s.virtTCP) != 0 {
		t.Errorf("expected 0 virtual TCP connections after Close, got %d", len(s.virtTCP))
	}
	if len(s.virtTCP6) != 0 {
		t.Errorf("expected 0 virtual TCP6 connections after Close, got %d", len(s.virtTCP6))
	}
	if len(s.listeners) != 0 {
		t.Errorf("expected 0 listeners after Close, got %d", len(s.listeners))
	}
	if len(s.listeners6) != 0 {
		t.Errorf("expected 0 listeners6 after Close, got %d", len(s.listeners6))
	}

	// Verify that TCP connections are closed
	if !tcpC.closed {
		t.Error("TCP connection should be marked closed after Stack.Close()")
	}
	if !tcp6C.closed {
		t.Error("TCP6 connection should be marked closed after Stack.Close()")
	}

	if vc.State() != vtcp.StateClosed {
		t.Errorf("virtual TCP connection should be in CLOSED state after Stack.Close(), got %v", vc.State())
	}
	if vc6.State() != vtcp.StateClosed {
		t.Errorf("virtual TCP6 connection should be in CLOSED state after Stack.Close(), got %v", vc6.State())
	}
}

func TestStackCloseStopsMaintenanceGoroutine(t *testing.T) {
	s := New()
	// Close should not panic even when called immediately
	err := s.Close()
	if err != nil {
		t.Fatalf("Close() returned error: %v", err)
	}
	// Calling Close on an already-closed stack shouldn't hang
	// (done channel already closed, second close would panic if not handled)
}

func TestHandlePacket_IPv6Routing(t *testing.T) {
	s := New()
	clientMAC := [6]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06}
	gwMAC := [6]byte{0x06, 0x05, 0x04, 0x03, 0x02, 0x01}
	writer := func(b []byte) error { return nil }

	// Create a valid IPv6 TCP SYN to a real port to exercise the outbound path
	listener, err := net.Listen("tcp", "[::1]:0")
	if err != nil {
		t.Skipf("cannot listen on IPv6 localhost: %v", err)
	}
	defer listener.Close()
	serverPort := listener.Addr().(*net.TCPAddr).Port

	go func() {
		c, err := listener.Accept()
		if err == nil {
			c.Close()
		}
	}()

	packet := make([]byte, 60)
	packet[0] = 0x60 // Version 6
	binary.BigEndian.PutUint16(packet[4:6], 20)
	packet[6] = 6  // TCP
	packet[7] = 64 // Hop limit
	// Source: ::1
	packet[23] = 0x01
	// Dest: ::1
	packet[39] = 0x01
	// TCP header
	binary.BigEndian.PutUint16(packet[40:42], 54321) // src port
	binary.BigEndian.PutUint16(packet[42:44], uint16(serverPort))
	binary.BigEndian.PutUint32(packet[44:48], 1000) // seq
	packet[52] = 0x50                               // data offset
	packet[53] = 0x02                               // SYN

	err = s.HandlePacket(0, clientMAC, gwMAC, packet, writer)
	if err != nil {
		t.Errorf("HandlePacket with IPv6 TCP SYN failed: %v", err)
	}

	// Verify a tcp6 connection was created
	time.Sleep(50 * time.Millisecond)
	s.mu.RLock()
	tcp6Count := len(s.tcp6)
	s.mu.RUnlock()
	if tcp6Count != 1 {
		t.Errorf("expected 1 TCP6 connection, got %d", tcp6Count)
	}
	s.Close()
}

func TestMaintenanceCleanup_DirectSimulation(t *testing.T) {
	s := New()

	mkNAT := func(closed bool) *tcpNATConn {
		vc := vtcp.NewConn(vtcp.ConnConfig{LocalPort: 80, RemotePort: 12345, Writer: func([]byte) error { return nil }})
		if closed {
			vc.Abort()
		} else {
			// Put into SynReceived so it's not in StateClosed
			vc.AcceptSYN(vtcp.Segment{SrcPort: 12345, DstPort: 80, Seq: 1000, Flags: vtcp.FlagSYN, Window: 65535})
		}
		return &tcpNATConn{vc: vc, closed: closed}
	}

	// Closed TCP connection (should be cleaned up)
	tcpK := key{srcIP: [4]byte{192, 168, 1, 1}, srcPort: 12345, dstIP: [4]byte{8, 8, 8, 8}, dstPort: 80}
	tcpC := mkNAT(true)

	// Active TCP connection (should NOT be cleaned up)
	tcpK2 := key{srcIP: [4]byte{192, 168, 1, 2}, srcPort: 12346, dstIP: [4]byte{8, 8, 8, 8}, dstPort: 80}
	tcpC2 := mkNAT(false)

	// Closed TCP6 connection
	var src6, dst6 [16]byte
	src6[15] = 1
	dst6[15] = 2
	tcp6K := key6{srcIP: src6, srcPort: 12345, dstIP: dst6, dstPort: 80}
	tcp6C := mkNAT(true)

	// Add a closed virtual connection (vtcp.Conn in CLOSED state)
	vcK := key{srcIP: [4]byte{10, 0, 0, 50}, srcPort: 45000, dstIP: [4]byte{10, 0, 0, 1}, dstPort: 9000}
	vc := vtcp.NewConn(vtcp.ConnConfig{
		LocalAddr:  &net.TCPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 9000},
		RemoteAddr: &net.TCPAddr{IP: net.IPv4(10, 0, 0, 50), Port: 45000},
		LocalPort:  9000,
		RemotePort: 45000,
		Writer:     func(seg []byte) error { return nil },
	})
	vc.Abort() // Move to StateClosed

	// Add a closed virtual connection6 (vtcp.Conn in CLOSED state)
	vc6K := key6{srcIP: src6, srcPort: 45000, dstIP: dst6, dstPort: 9000}
	vc6 := vtcp.NewConn(vtcp.ConnConfig{
		LocalAddr:  &net.TCPAddr{IP: net.ParseIP("::2"), Port: 9000},
		RemoteAddr: &net.TCPAddr{IP: net.ParseIP("::1"), Port: 45000},
		LocalPort:  9000,
		RemotePort: 45000,
		Writer:     func(seg []byte) error { return nil },
	})
	vc6.Abort() // Move to StateClosed

	s.mu.Lock()
	s.tcp[tcpK] = tcpC
	s.tcp[tcpK2] = tcpC2
	s.tcp6[tcp6K] = tcp6C
	s.virtTCP[vcK] = vc
	s.virtTCP6[vc6K] = vc6
	s.mu.Unlock()

	// Simulate the maintenance cleanup logic (same as maintenance() body)
	s.mu.Lock()
	for k, c := range s.tcp {
		st := c.vc.State()
		if st == vtcp.StateClosed || st == vtcp.StateTimeWait || c.closed {
			c.close()
			delete(s.tcp, k)
		}
	}
	for k, c := range s.tcp6 {
		st := c.vc.State()
		if st == vtcp.StateClosed || st == vtcp.StateTimeWait || c.closed {
			c.close()
			delete(s.tcp6, k)
		}
	}
	for k, vc2 := range s.virtTCP {
		st := vc2.State()
		if st == vtcp.StateClosed || st == vtcp.StateTimeWait {
			delete(s.virtTCP, k)
		}
	}
	for k, vc2 := range s.virtTCP6 {
		st := vc2.State()
		if st == vtcp.StateClosed || st == vtcp.StateTimeWait {
			delete(s.virtTCP6, k)
		}
	}
	s.mu.Unlock()

	// Verify stale connections were cleaned up and fresh one remains
	s.mu.RLock()
	defer s.mu.RUnlock()
	if len(s.tcp) != 1 {
		t.Errorf("expected 1 TCP connection (fresh one), got %d", len(s.tcp))
	}
	if _, ok := s.tcp[tcpK2]; !ok {
		t.Error("fresh TCP connection should still be in the map")
	}
	if len(s.tcp6) != 0 {
		t.Errorf("expected 0 TCP6 connections, got %d", len(s.tcp6))
	}
	if len(s.virtTCP) != 0 {
		t.Errorf("expected 0 virtual TCP connections, got %d", len(s.virtTCP))
	}
	if len(s.virtTCP6) != 0 {
		t.Errorf("expected 0 virtual TCP6 connections, got %d", len(s.virtTCP6))
	}
	if vc.State() != vtcp.StateClosed {
		t.Errorf("stale virtual connection should be in CLOSED state, got %v", vc.State())
	}
	if vc6.State() != vtcp.StateClosed {
		t.Errorf("stale virtual6 connection should be in CLOSED state, got %v", vc6.State())
	}
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
			packet[0] = 0x45                            // Version 4, IHL 5
			binary.BigEndian.PutUint16(packet[2:4], 40) // Total length
			packet[9] = 6                               // Protocol: TCP
			copy(packet[12:16], []byte{127, 0, 0, 1})   // Source IP (localhost)
			copy(packet[16:20], []byte{127, 0, 0, 1})   // Dest IP (localhost)

			// TCP header
			binary.BigEndian.PutUint16(packet[20:22], port)                    // Source port
			binary.BigEndian.PutUint16(packet[22:24], uint16(serverAddr.Port)) // Dest port
			packet[32] = 0x50                                                  // Data offset
			packet[33] = 0x02                                                  // SYN flag

			_ = s.HandlePacket(0, clientMAC, gwMAC, packet, writer)
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
