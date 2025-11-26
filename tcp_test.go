package slirp

import (
	"encoding/binary"
	"net"
	"sync"
	"testing"
	"time"
)

func TestNewTCPConn(t *testing.T) {
	srcIP := [4]byte{192, 168, 1, 1}
	dstIP := [4]byte{8, 8, 8, 8}
	clientMAC := [6]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06}
	gwMAC := [6]byte{0x06, 0x05, 0x04, 0x03, 0x02, 0x01}
	writer := func(b []byte) error { return nil }

	conn := newTCPConn(srcIP, 12345, dstIP, 80, clientMAC, gwMAC, writer)

	if conn == nil {
		t.Fatal("newTCPConn returned nil")
	}
	if conn.cSrcIP != srcIP {
		t.Error("source IP not set correctly")
	}
	if conn.cSrcPort != 12345 {
		t.Error("source port not set correctly")
	}
	if conn.rIP != dstIP {
		t.Error("remote IP not set correctly")
	}
	if conn.rPort != 80 {
		t.Error("remote port not set correctly")
	}
	if conn.mss != 1460 {
		t.Errorf("default MSS should be 1460, got %d", conn.mss)
	}
	if conn.cond == nil {
		t.Error("cond not initialized")
	}
}

func TestBuildTCPPacket(t *testing.T) {
	srcMAC := [6]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06}
	dstMAC := [6]byte{0x06, 0x05, 0x04, 0x03, 0x02, 0x01}
	srcIP := [4]byte{192, 168, 1, 1}
	dstIP := [4]byte{8, 8, 8, 8}
	payload := []byte("test data")

	pkt := buildTCPPacket(srcMAC, dstMAC, srcIP, dstIP, 12345, 80, 1000, 2000, 0x18, payload)

	// Check Ethernet header (14 bytes)
	if len(pkt) < 14 {
		t.Fatal("packet too short for Ethernet header")
	}
	if !bytesEqual(pkt[0:6], dstMAC[:]) {
		t.Error("destination MAC incorrect")
	}
	if !bytesEqual(pkt[6:12], srcMAC[:]) {
		t.Error("source MAC incorrect")
	}
	if binary.BigEndian.Uint16(pkt[12:14]) != 0x0800 {
		t.Error("EtherType should be 0x0800 (IPv4)")
	}

	// Check IP header starts at offset 14
	ipStart := 14
	if pkt[ipStart]>>4 != 4 {
		t.Error("IP version should be 4")
	}

	// Check TCP header
	tcpStart := ipStart + 20
	if len(pkt) < tcpStart+20 {
		t.Fatal("packet too short for TCP header")
	}
	if binary.BigEndian.Uint16(pkt[tcpStart:tcpStart+2]) != 12345 {
		t.Error("TCP source port incorrect")
	}
	if binary.BigEndian.Uint16(pkt[tcpStart+2:tcpStart+4]) != 80 {
		t.Error("TCP dest port incorrect")
	}
	if binary.BigEndian.Uint32(pkt[tcpStart+4:tcpStart+8]) != 1000 {
		t.Error("TCP seq number incorrect")
	}
	if binary.BigEndian.Uint32(pkt[tcpStart+8:tcpStart+12]) != 2000 {
		t.Error("TCP ack number incorrect")
	}
	if pkt[tcpStart+13] != 0x18 {
		t.Errorf("TCP flags should be 0x18, got 0x%02x", pkt[tcpStart+13])
	}

	// Check payload
	payloadStart := tcpStart + 20
	if !bytesEqual(pkt[payloadStart:], payload) {
		t.Error("payload not copied correctly")
	}
}

func TestItoaU16(t *testing.T) {
	tests := []struct {
		input    uint16
		expected string
	}{
		{0, "0"},
		{1, "1"},
		{80, "80"},
		{443, "443"},
		{8080, "8080"},
		{65535, "65535"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			result := itoaU16(tt.input)
			if result != tt.expected {
				t.Errorf("itoaU16(%d) = %q, expected %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestTCPConnHandleSYN(t *testing.T) {
	// This test will try to establish a real connection, so we'll use a local server
	// Start a simple TCP echo server
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("cannot start test server: %v", err)
	}
	defer listener.Close()

	serverAddr := listener.Addr().(*net.TCPAddr)
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			conn.Close()
		}
	}()

	srcIP := [4]byte{127, 0, 0, 1}
	dstIP := [4]byte{127, 0, 0, 1}
	clientMAC := [6]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06}
	gwMAC := [6]byte{0x06, 0x05, 0x04, 0x03, 0x02, 0x01}

	var receivedFrames [][]byte
	var mu sync.Mutex
	writer := func(b []byte) error {
		mu.Lock()
		frame := make([]byte, len(b))
		copy(frame, b)
		receivedFrames = append(receivedFrames, frame)
		mu.Unlock()
		return nil
	}

	conn := newTCPConn(srcIP, 54321, dstIP, uint16(serverAddr.Port), clientMAC, gwMAC, writer)

	// Create a SYN packet
	synPacket := createTCPPacket(srcIP, dstIP, 54321, uint16(serverAddr.Port), 1000, 0, 0x02, nil)

	err = conn.handleOutbound(synPacket)
	if err != nil {
		t.Fatalf("handleOutbound failed: %v", err)
	}

	// Wait a bit for the SYN-ACK to be sent
	time.Sleep(100 * time.Millisecond)

	mu.Lock()
	frameCount := len(receivedFrames)
	mu.Unlock()

	if frameCount < 1 {
		t.Error("expected at least one frame (SYN-ACK), got none")
	}

	if conn.conn == nil {
		t.Error("TCP connection should be established")
	}
	if conn.cSeq != 1001 {
		t.Errorf("client seq should be 1001, got %d", conn.cSeq)
	}
}

func TestTCPConnFlushSendQ(t *testing.T) {
	srcIP := [4]byte{192, 168, 1, 1}
	dstIP := [4]byte{8, 8, 8, 8}
	clientMAC := [6]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06}
	gwMAC := [6]byte{0x06, 0x05, 0x04, 0x03, 0x02, 0x01}

	var sentFrames [][]byte
	var mu sync.Mutex
	writer := func(b []byte) error {
		mu.Lock()
		frame := make([]byte, len(b))
		copy(frame, b)
		sentFrames = append(sentFrames, frame)
		mu.Unlock()
		return nil
	}

	conn := newTCPConn(srcIP, 12345, dstIP, 80, clientMAC, gwMAC, writer)
	conn.recvWnd = 8192
	conn.sSeq = 5000
	conn.cSeq = 3000
	conn.sendQ = []byte("Hello, World! This is test data.")

	conn.flushSendQ()

	if len(conn.sendQ) != 0 {
		t.Errorf("sendQ should be empty after flush, has %d bytes", len(conn.sendQ))
	}

	mu.Lock()
	frameCount := len(sentFrames)
	mu.Unlock()

	if frameCount < 1 {
		t.Error("expected at least one frame to be sent")
	}
}

func TestTCPConnMSSNegotiation(t *testing.T) {
	// Start a test server
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("cannot start test server: %v", err)
	}
	defer listener.Close()

	serverAddr := listener.Addr().(*net.TCPAddr)
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			conn.Close()
		}
	}()

	srcIP := [4]byte{127, 0, 0, 1}
	dstIP := [4]byte{127, 0, 0, 1}
	clientMAC := [6]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06}
	gwMAC := [6]byte{0x06, 0x05, 0x04, 0x03, 0x02, 0x01}
	writer := func(b []byte) error { return nil }

	conn := newTCPConn(srcIP, 54321, dstIP, uint16(serverAddr.Port), clientMAC, gwMAC, writer)

	// Create a SYN packet with MSS option (MSS=1000)
	synPacket := createTCPPacketWithMSS(srcIP, dstIP, 54321, uint16(serverAddr.Port), 1000, 0, 0x02, nil, 1000)

	err = conn.handleOutbound(synPacket)
	if err != nil {
		t.Fatalf("handleOutbound failed: %v", err)
	}

	time.Sleep(50 * time.Millisecond)

	// MSS should be updated to 1000 (smaller than default 1460)
	if conn.mss != 1000 {
		t.Errorf("MSS should be 1000, got %d", conn.mss)
	}
}

// Helper functions for tests

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func createTCPPacket(srcIP, dstIP [4]byte, srcPort, dstPort uint16, seq, ack uint32, flags uint8, payload []byte) []byte {
	ihl := 20
	thl := 20
	totalLen := ihl + thl + len(payload)

	ip := make([]byte, ihl)
	ip[0] = (4 << 4) | 5 // Version 4, IHL 5
	binary.BigEndian.PutUint16(ip[2:4], uint16(totalLen))
	ip[8] = 64       // TTL
	ip[9] = 6        // Protocol: TCP
	copy(ip[12:16], srcIP[:])
	copy(ip[16:20], dstIP[:])
	binary.BigEndian.PutUint16(ip[10:12], ipChecksum(ip))

	tcp := make([]byte, thl)
	binary.BigEndian.PutUint16(tcp[0:2], srcPort)
	binary.BigEndian.PutUint16(tcp[2:4], dstPort)
	binary.BigEndian.PutUint32(tcp[4:8], seq)
	binary.BigEndian.PutUint32(tcp[8:12], ack)
	tcp[12] = (5 << 4) // Data offset
	tcp[13] = flags
	binary.BigEndian.PutUint16(tcp[14:16], 65535) // Window
	binary.BigEndian.PutUint16(tcp[16:18], tcpChecksum(ip[12:16], ip[16:20], tcp, payload))

	pkt := make([]byte, len(ip)+len(tcp)+len(payload))
	copy(pkt, ip)
	copy(pkt[len(ip):], tcp)
	copy(pkt[len(ip)+len(tcp):], payload)
	return pkt
}

func createTCPPacketWithMSS(srcIP, dstIP [4]byte, srcPort, dstPort uint16, seq, ack uint32, flags uint8, payload []byte, mss uint16) []byte {
	ihl := 20
	// TCP header with MSS option: 20 base + 4 for MSS option
	thl := 24
	totalLen := ihl + thl + len(payload)

	ip := make([]byte, ihl)
	ip[0] = (4 << 4) | 5
	binary.BigEndian.PutUint16(ip[2:4], uint16(totalLen))
	ip[8] = 64
	ip[9] = 6
	copy(ip[12:16], srcIP[:])
	copy(ip[16:20], dstIP[:])
	binary.BigEndian.PutUint16(ip[10:12], ipChecksum(ip))

	tcp := make([]byte, thl)
	binary.BigEndian.PutUint16(tcp[0:2], srcPort)
	binary.BigEndian.PutUint16(tcp[2:4], dstPort)
	binary.BigEndian.PutUint32(tcp[4:8], seq)
	binary.BigEndian.PutUint32(tcp[8:12], ack)
	tcp[12] = (6 << 4) // Data offset = 6 (24 bytes)
	tcp[13] = flags
	binary.BigEndian.PutUint16(tcp[14:16], 65535)

	// Add MSS option
	tcp[20] = 2  // Kind: MSS
	tcp[21] = 4  // Length: 4 bytes
	binary.BigEndian.PutUint16(tcp[22:24], mss)

	binary.BigEndian.PutUint16(tcp[16:18], tcpChecksum(ip[12:16], ip[16:20], tcp, payload))

	pkt := make([]byte, len(ip)+len(tcp)+len(payload))
	copy(pkt, ip)
	copy(pkt[len(ip):], tcp)
	copy(pkt[len(ip)+len(tcp):], payload)
	return pkt
}
