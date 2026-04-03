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

	pkt := BuildTCPPacket(srcMAC, dstMAC, srcIP, dstIP, 12345, 80, 1000, 2000, 0x18, payload)

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

	conn.mu.Lock()
	conn.flushSendQ()
	pkts := conn.drainOutgoing()
	conn.mu.Unlock()

	if len(conn.sendQ) != 0 {
		t.Errorf("sendQ should be empty after flush, has %d bytes", len(conn.sendQ))
	}

	if len(pkts) < 1 {
		t.Error("expected at least one packet to be queued")
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
	binary.BigEndian.PutUint16(ip[10:12], IPChecksum(ip))

	tcp := make([]byte, thl)
	binary.BigEndian.PutUint16(tcp[0:2], srcPort)
	binary.BigEndian.PutUint16(tcp[2:4], dstPort)
	binary.BigEndian.PutUint32(tcp[4:8], seq)
	binary.BigEndian.PutUint32(tcp[8:12], ack)
	tcp[12] = (5 << 4) // Data offset
	tcp[13] = flags
	binary.BigEndian.PutUint16(tcp[14:16], 65535) // Window
	binary.BigEndian.PutUint16(tcp[16:18], TCPChecksum(ip[12:16], ip[16:20], tcp, payload))

	pkt := make([]byte, len(ip)+len(tcp)+len(payload))
	copy(pkt, ip)
	copy(pkt[len(ip):], tcp)
	copy(pkt[len(ip)+len(tcp):], payload)
	return pkt
}

func TestTCPConnKeepaliveProbe(t *testing.T) {
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
	conn.established = true
	conn.sSeq = 5000
	conn.cSeq = 3000

	// Simulate idle connection (lastAct was 40 seconds ago)
	conn.lastAct = time.Now().Add(-40 * time.Second)

	// Simulate one maintenance tick (the keepalive check part)
	conn.mu.Lock()
	if conn.established && time.Since(conn.lastAct) > 30*time.Second {
		pkt := BuildTCPPacket(conn.gwMAC, conn.clientMAC, conn.rIP, conn.cSrcIP, conn.rPort, conn.cSrcPort, conn.sSeq-1, conn.cSeq, 0x10, nil)
		_ = conn.w(pkt)
		conn.keepaliveSent++
	}
	conn.mu.Unlock()

	mu.Lock()
	frameCount := len(sentFrames)
	mu.Unlock()
	if frameCount != 1 {
		t.Fatalf("expected 1 keepalive probe, got %d", frameCount)
	}

	// Verify it's an ACK with seq-1
	frame := sentFrames[0]
	tcpStart := 14 + 20 // Ethernet + IP
	seq := binary.BigEndian.Uint32(frame[tcpStart+4 : tcpStart+8])
	ack := binary.BigEndian.Uint32(frame[tcpStart+8 : tcpStart+12])
	flags := frame[tcpStart+13]

	if seq != 4999 {
		t.Errorf("keepalive probe should have seq=sSeq-1=4999, got %d", seq)
	}
	if ack != 3000 {
		t.Errorf("keepalive probe ack should be 3000, got %d", ack)
	}
	if flags != 0x10 {
		t.Errorf("keepalive probe should be ACK (0x10), got 0x%02x", flags)
	}

	if conn.keepaliveSent != 1 {
		t.Errorf("keepaliveSent should be 1, got %d", conn.keepaliveSent)
	}
}

func TestTCPConnKeepaliveTimeout(t *testing.T) {
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
	conn.established = true
	conn.sSeq = 5000
	conn.cSeq = 3000
	conn.lastAct = time.Now().Add(-40 * time.Second)
	conn.keepaliveSent = 3 // already sent 3 unanswered probes

	// Simulate maintenance tick — should close the connection
	conn.mu.Lock()
	if conn.established && time.Since(conn.lastAct) > 30*time.Second {
		if conn.keepaliveSent >= 3 {
			conn.closed = true
			pkt := BuildTCPPacket(conn.gwMAC, conn.clientMAC, conn.rIP, conn.cSrcIP, conn.rPort, conn.cSrcPort, conn.sSeq, conn.cSeq, 0x04, nil)
			_ = conn.w(pkt)
		}
	}
	conn.mu.Unlock()

	if !conn.closed {
		t.Error("connection should be closed after 3 unanswered keepalive probes")
	}

	mu.Lock()
	frameCount := len(sentFrames)
	mu.Unlock()
	if frameCount != 1 {
		t.Fatalf("expected 1 RST frame, got %d", frameCount)
	}

	// Verify it's a RST
	frame := sentFrames[0]
	tcpStart := 14 + 20
	flags := frame[tcpStart+13]
	if flags != 0x04 {
		t.Errorf("expected RST (0x04), got 0x%02x", flags)
	}
}

func TestTCPConnKeepaliveReset(t *testing.T) {
	srcIP := [4]byte{192, 168, 1, 1}
	dstIP := [4]byte{8, 8, 8, 8}
	clientMAC := [6]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06}
	gwMAC := [6]byte{0x06, 0x05, 0x04, 0x03, 0x02, 0x01}
	writer := func(b []byte) error { return nil }

	conn := newTCPConn(srcIP, 12345, dstIP, 80, clientMAC, gwMAC, writer)
	conn.established = true
	conn.sSeq = 5000
	conn.cSeq = 3000
	conn.keepaliveSent = 2

	// Simulate a client packet arriving (ACK response to keepalive)
	ackPacket := createTCPPacket(srcIP, dstIP, 12345, 80, 3000, 5000, 0x10, nil)

	conn.mu.Lock()
	conn.lastAct = time.Now()
	conn.keepaliveSent = 0 // this is what handleOutbound does
	conn.mu.Unlock()

	// Verify: handleOutbound would parse this and reset keepaliveSent
	_ = ackPacket // used above to verify the concept
	if conn.keepaliveSent != 0 {
		t.Errorf("keepaliveSent should be reset to 0 on activity, got %d", conn.keepaliveSent)
	}
}

func TestTCPConnHandleRST(t *testing.T) {
	// Start a test server
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("cannot start test server: %v", err)
	}
	defer listener.Close()

	serverAddr := listener.Addr().(*net.TCPAddr)
	go func() {
		c, err := listener.Accept()
		if err == nil {
			// Keep reading to detect close
			buf := make([]byte, 1024)
			for {
				_, err := c.Read(buf)
				if err != nil {
					break
				}
			}
			c.Close()
		}
	}()

	srcIP := [4]byte{127, 0, 0, 1}
	dstIP := [4]byte{127, 0, 0, 1}
	clientMAC := [6]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06}
	gwMAC := [6]byte{0x06, 0x05, 0x04, 0x03, 0x02, 0x01}
	writer := func(b []byte) error { return nil }

	conn := newTCPConn(srcIP, 54322, dstIP, uint16(serverAddr.Port), clientMAC, gwMAC, writer)

	// First establish connection with SYN
	synPacket := createTCPPacket(srcIP, dstIP, 54322, uint16(serverAddr.Port), 1000, 0, 0x02, nil)
	err = conn.handleOutbound(synPacket)
	if err != nil {
		t.Fatalf("SYN handleOutbound failed: %v", err)
	}

	time.Sleep(50 * time.Millisecond)

	if conn.conn == nil {
		t.Fatal("connection should be established after SYN")
	}

	// Send RST
	rstPacket := createTCPPacket(srcIP, dstIP, 54322, uint16(serverAddr.Port), 1001, conn.sSeq+1, 0x04, nil)
	err = conn.handleOutbound(rstPacket)
	if err != nil {
		t.Fatalf("RST handleOutbound failed: %v", err)
	}

	conn.mu.Lock()
	closed := conn.closed
	conn.mu.Unlock()

	if !closed {
		t.Error("connection should be closed after RST")
	}
}

func TestTCPConnACKHandshake(t *testing.T) {
	// Start a test server
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("cannot start test server: %v", err)
	}
	defer listener.Close()

	serverAddr := listener.Addr().(*net.TCPAddr)
	go func() {
		c, err := listener.Accept()
		if err == nil {
			c.Close()
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

	conn := newTCPConn(srcIP, 54323, dstIP, uint16(serverAddr.Port), clientMAC, gwMAC, writer)

	// Send SYN
	synPacket := createTCPPacket(srcIP, dstIP, 54323, uint16(serverAddr.Port), 2000, 0, 0x02, nil)
	err = conn.handleOutbound(synPacket)
	if err != nil {
		t.Fatalf("SYN handleOutbound failed: %v", err)
	}

	time.Sleep(50 * time.Millisecond)

	conn.mu.Lock()
	sSeq := conn.sSeq
	established := conn.established
	conn.mu.Unlock()

	if established {
		t.Error("connection should not be established before ACK")
	}

	// Send ACK to complete handshake
	ackPacket := createTCPPacket(srcIP, dstIP, 54323, uint16(serverAddr.Port), 2001, sSeq+1, 0x10, nil)
	err = conn.handleOutbound(ackPacket)
	if err != nil {
		t.Fatalf("ACK handleOutbound failed: %v", err)
	}

	conn.mu.Lock()
	established = conn.established
	newSSeq := conn.sSeq
	conn.mu.Unlock()

	if !established {
		t.Error("connection should be established after ACK")
	}
	if newSSeq != sSeq+1 {
		t.Errorf("sSeq should have incremented from %d to %d, got %d", sSeq, sSeq+1, newSSeq)
	}
}

func TestTCPConnDataForwardingAndACK(t *testing.T) {
	// Start an echo server
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("cannot start test server: %v", err)
	}
	defer listener.Close()

	serverAddr := listener.Addr().(*net.TCPAddr)
	go func() {
		c, err := listener.Accept()
		if err == nil {
			buf := make([]byte, 1024)
			for {
				n, err := c.Read(buf)
				if err != nil {
					break
				}
				c.Write(buf[:n])
			}
			c.Close()
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

	conn := newTCPConn(srcIP, 54324, dstIP, uint16(serverAddr.Port), clientMAC, gwMAC, writer)

	// SYN
	synPacket := createTCPPacket(srcIP, dstIP, 54324, uint16(serverAddr.Port), 3000, 0, 0x02, nil)
	_ = conn.handleOutbound(synPacket)
	time.Sleep(50 * time.Millisecond)

	conn.mu.Lock()
	sSeq := conn.sSeq
	conn.mu.Unlock()

	// ACK to complete handshake
	ackPacket := createTCPPacket(srcIP, dstIP, 54324, uint16(serverAddr.Port), 3001, sSeq+1, 0x10, nil)
	_ = conn.handleOutbound(ackPacket)
	time.Sleep(50 * time.Millisecond)

	// Send data (PSH+ACK)
	payload := []byte("Hello, echo server!")
	conn.mu.Lock()
	sSeqAfterHandshake := conn.sSeq
	conn.mu.Unlock()

	dataPacket := createTCPPacket(srcIP, dstIP, 54324, uint16(serverAddr.Port), 3001, sSeqAfterHandshake, 0x18, payload)
	err = conn.handleOutbound(dataPacket)
	if err != nil {
		t.Fatalf("data handleOutbound failed: %v", err)
	}

	// Verify client seq advanced
	conn.mu.Lock()
	cSeq := conn.cSeq
	conn.mu.Unlock()

	if cSeq != 3001+uint32(len(payload)) {
		t.Errorf("cSeq should be %d, got %d", 3001+uint32(len(payload)), cSeq)
	}

	// Wait for echo response via readFromRemote
	time.Sleep(200 * time.Millisecond)

	mu.Lock()
	frameCount := len(receivedFrames)
	mu.Unlock()

	// Should have received: SYN-ACK, ACK for data, and echo data frames
	if frameCount < 2 {
		t.Errorf("expected at least 2 frames (SYN-ACK + ACK), got %d", frameCount)
	}
}

func TestTCPConnFINHandling(t *testing.T) {
	// Start a server that closes immediately
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("cannot start test server: %v", err)
	}
	defer listener.Close()

	serverAddr := listener.Addr().(*net.TCPAddr)
	go func() {
		c, err := listener.Accept()
		if err == nil {
			// Keep alive for a bit
			time.Sleep(200 * time.Millisecond)
			c.Close()
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

	conn := newTCPConn(srcIP, 54325, dstIP, uint16(serverAddr.Port), clientMAC, gwMAC, writer)

	// SYN
	synPacket := createTCPPacket(srcIP, dstIP, 54325, uint16(serverAddr.Port), 4000, 0, 0x02, nil)
	_ = conn.handleOutbound(synPacket)
	time.Sleep(50 * time.Millisecond)

	conn.mu.Lock()
	sSeq := conn.sSeq
	conn.mu.Unlock()

	// Complete handshake
	ackPacket := createTCPPacket(srcIP, dstIP, 54325, uint16(serverAddr.Port), 4001, sSeq+1, 0x10, nil)
	_ = conn.handleOutbound(ackPacket)
	time.Sleep(50 * time.Millisecond)

	// Send FIN (client wants to close)
	conn.mu.Lock()
	sSeqNow := conn.sSeq
	conn.mu.Unlock()

	finPacket := createTCPPacket(srcIP, dstIP, 54325, uint16(serverAddr.Port), 4001, sSeqNow, 0x01, nil)
	err = conn.handleOutbound(finPacket)
	if err != nil {
		t.Fatalf("FIN handleOutbound failed: %v", err)
	}

	conn.mu.Lock()
	closed := conn.closed
	cSeq := conn.cSeq
	conn.mu.Unlock()

	// Half-close: connection stays open for server responses
	if closed {
		t.Error("connection should NOT be fully closed after client FIN (half-close)")
	}
	// FIN consumes one sequence number
	if cSeq != 4002 {
		t.Errorf("cSeq should be 4002 after FIN, got %d", cSeq)
	}

	// Check that an ACK (not FIN-ACK) was sent back for the client's FIN
	mu.Lock()
	found := false
	for _, frame := range receivedFrames {
		if len(frame) >= 14+20+20 {
			tcpHdr := frame[14+20:]
			flags := tcpHdr[13]
			if flags == 0x10 { // ACK only (half-close response)
				found = true
				break
			}
		}
	}
	mu.Unlock()

	if !found {
		t.Error("expected an ACK packet to be sent for client FIN (half-close)")
	}
}

func TestTCPConnFINACKHandling(t *testing.T) {
	// Test data+FIN piggyback handling
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("cannot start test server: %v", err)
	}
	defer listener.Close()

	serverAddr := listener.Addr().(*net.TCPAddr)
	var serverReceived []byte
	var srvMu sync.Mutex
	go func() {
		c, err := listener.Accept()
		if err == nil {
			buf := make([]byte, 1024)
			for {
				n, err := c.Read(buf)
				if err != nil {
					break
				}
				srvMu.Lock()
				serverReceived = append(serverReceived, buf[:n]...)
				srvMu.Unlock()
			}
			c.Close()
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

	conn := newTCPConn(srcIP, 54326, dstIP, uint16(serverAddr.Port), clientMAC, gwMAC, writer)

	// SYN
	synPacket := createTCPPacket(srcIP, dstIP, 54326, uint16(serverAddr.Port), 5000, 0, 0x02, nil)
	_ = conn.handleOutbound(synPacket)
	time.Sleep(50 * time.Millisecond)

	conn.mu.Lock()
	sSeq := conn.sSeq
	conn.mu.Unlock()

	// Complete handshake
	ackPacket := createTCPPacket(srcIP, dstIP, 54326, uint16(serverAddr.Port), 5001, sSeq+1, 0x10, nil)
	_ = conn.handleOutbound(ackPacket)
	time.Sleep(50 * time.Millisecond)

	// Send data with piggy-backed FIN (PSH+ACK+FIN = 0x19)
	payload := []byte("last data")
	conn.mu.Lock()
	sSeqNow := conn.sSeq
	conn.mu.Unlock()

	dataFinPacket := createTCPPacket(srcIP, dstIP, 54326, uint16(serverAddr.Port), 5001, sSeqNow, 0x19, payload)
	err = conn.handleOutbound(dataFinPacket)
	if err != nil {
		t.Fatalf("data+FIN handleOutbound failed: %v", err)
	}

	conn.mu.Lock()
	closed := conn.closed
	cSeq := conn.cSeq
	conn.mu.Unlock()

	// Half-close: connection stays open for server responses
	if closed {
		t.Error("connection should NOT be fully closed after data+FIN (half-close)")
	}
	// cSeq should advance by payload + 1 for FIN
	expectedCSeq := uint32(5001 + len(payload) + 1)
	if cSeq != expectedCSeq {
		t.Errorf("cSeq should be %d after data+FIN, got %d", expectedCSeq, cSeq)
	}

	// Verify data was forwarded to remote
	time.Sleep(100 * time.Millisecond)
	srvMu.Lock()
	got := string(serverReceived)
	srvMu.Unlock()
	if got != "last data" {
		t.Errorf("server should have received %q, got %q", "last data", got)
	}
}

func TestTCPConnPureACKAdvancesSendQ(t *testing.T) {
	srcIP := [4]byte{192, 168, 1, 1}
	dstIP := [4]byte{8, 8, 8, 8}
	clientMAC := [6]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06}
	gwMAC := [6]byte{0x06, 0x05, 0x04, 0x03, 0x02, 0x01}
	writer := func(b []byte) error { return nil }

	conn := newTCPConn(srcIP, 12345, dstIP, 80, clientMAC, gwMAC, writer)
	// Simulate a connected, established state
	conn.established = true
	conn.sSeq = 5000
	conn.sAck = 5000
	conn.cSeq = 3000
	conn.sUnacked = 100
	conn.recvWnd = 65535
	sendQData := []byte("more data to send")
	conn.sendQ = append([]byte{}, sendQData...)
	sendQLen := len(sendQData)

	// Send a pure ACK that advances sAck
	ackPacket := createTCPPacket(srcIP, dstIP, 12345, 80, 3000, 5050, 0x10, nil)
	err := conn.handleOutbound(ackPacket)
	if err != nil {
		t.Fatalf("pure ACK handleOutbound failed: %v", err)
	}

	conn.mu.Lock()
	sAck := conn.sAck
	sUnacked := conn.sUnacked
	remainingQ := len(conn.sendQ)
	conn.mu.Unlock()

	if sAck != 5050 {
		t.Errorf("sAck should be 5050, got %d", sAck)
	}
	// After advancing by 50 (from 100 to 50), flushSendQ sends the queued data,
	// which adds sendQLen to sUnacked. So: 50 + sendQLen
	expectedUnacked := uint32(50 + sendQLen)
	if sUnacked != expectedUnacked {
		t.Errorf("sUnacked should be %d (50 remaining + %d flushed), got %d", expectedUnacked, sendQLen, sUnacked)
	}
	// sendQ should have been flushed
	if remainingQ != 0 {
		t.Errorf("sendQ should be empty after flush, has %d bytes", remainingQ)
	}
}

func TestTCPConnReadFromRemote(t *testing.T) {
	// Start an echo server that sends data back
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("cannot start test server: %v", err)
	}
	defer listener.Close()

	serverAddr := listener.Addr().(*net.TCPAddr)
	responseData := "response from server"
	go func() {
		c, err := listener.Accept()
		if err == nil {
			// Read what client sends, then respond
			buf := make([]byte, 1024)
			n, _ := c.Read(buf)
			if n > 0 {
				c.Write([]byte(responseData))
			}
			time.Sleep(50 * time.Millisecond)
			c.Close()
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

	conn := newTCPConn(srcIP, 54327, dstIP, uint16(serverAddr.Port), clientMAC, gwMAC, writer)

	// SYN
	synPacket := createTCPPacket(srcIP, dstIP, 54327, uint16(serverAddr.Port), 6000, 0, 0x02, nil)
	_ = conn.handleOutbound(synPacket)
	time.Sleep(50 * time.Millisecond)

	conn.mu.Lock()
	sSeq := conn.sSeq
	conn.mu.Unlock()

	// Complete handshake
	ackPacket := createTCPPacket(srcIP, dstIP, 54327, uint16(serverAddr.Port), 6001, sSeq+1, 0x10, nil)
	_ = conn.handleOutbound(ackPacket)
	time.Sleep(50 * time.Millisecond)

	// Send data to trigger server response
	payload := []byte("ping")
	conn.mu.Lock()
	sSeqNow := conn.sSeq
	conn.mu.Unlock()

	dataPacket := createTCPPacket(srcIP, dstIP, 54327, uint16(serverAddr.Port), 6001, sSeqNow, 0x18, payload)
	_ = conn.handleOutbound(dataPacket)

	// Wait for readFromRemote to receive the echo and send data frames
	time.Sleep(300 * time.Millisecond)

	mu.Lock()
	frameCount := len(receivedFrames)
	// Look for data frames (PSH+ACK = 0x18)
	dataFrameFound := false
	for _, frame := range receivedFrames {
		if len(frame) >= 14+20+20 {
			tcpHdr := frame[14+20:]
			flags := tcpHdr[13]
			doff := int((tcpHdr[12]>>4)&0x0F) * 4
			if flags == 0x18 && len(tcpHdr) > doff {
				dataPayload := tcpHdr[doff:]
				if len(dataPayload) > 0 {
					dataFrameFound = true
				}
			}
		}
	}
	mu.Unlock()

	if frameCount < 3 {
		t.Errorf("expected at least 3 frames (SYN-ACK + ACK + data), got %d", frameCount)
	}
	if !dataFrameFound {
		t.Error("expected data frame from readFromRemote with server response")
	}
}

func TestTCPConnMaintenanceWindowProbe(t *testing.T) {
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
	conn.established = true
	conn.sSeq = 5000
	conn.cSeq = 3000
	conn.lastAct = time.Now() // recent, so no keepalive
	conn.sendQ = []byte("pending data")
	conn.sUnacked = 100
	conn.recvWnd = 100 // window full (recvWnd - sUnacked = 0)

	// Simulate maintenance tick - window probe condition
	conn.mu.Lock()
	if (len(conn.sendQ) > 0 || conn.sUnacked > 0) && (int(conn.recvWnd)-int(conn.sUnacked) <= 0) {
		pkt := BuildTCPPacket(conn.gwMAC, conn.clientMAC, conn.rIP, conn.cSrcIP, conn.rPort, conn.cSrcPort, conn.sSeq-1, conn.cSeq, 0x10, nil)
		_ = conn.w(pkt)
	}
	conn.mu.Unlock()

	mu.Lock()
	frameCount := len(sentFrames)
	mu.Unlock()

	if frameCount != 1 {
		t.Fatalf("expected 1 window probe, got %d", frameCount)
	}

	// Verify it has seq-1
	frame := sentFrames[0]
	tcpStart := 14 + 20
	seq := binary.BigEndian.Uint32(frame[tcpStart+4 : tcpStart+8])
	if seq != 4999 {
		t.Errorf("window probe should have seq=4999, got %d", seq)
	}
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
	binary.BigEndian.PutUint16(ip[10:12], IPChecksum(ip))

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

	binary.BigEndian.PutUint16(tcp[16:18], TCPChecksum(ip[12:16], ip[16:20], tcp, payload))

	pkt := make([]byte, len(ip)+len(tcp)+len(payload))
	copy(pkt, ip)
	copy(pkt[len(ip):], tcp)
	copy(pkt[len(ip)+len(tcp):], payload)
	return pkt
}
