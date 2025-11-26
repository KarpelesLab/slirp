package slirp

import (
	"encoding/binary"
	"net"
	"sync"
	"testing"
	"time"
)

func TestNewUDPConn(t *testing.T) {
	srcIP := [4]byte{192, 168, 1, 1}
	dstIP := [4]byte{8, 8, 8, 8}
	clientMAC := [6]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06}
	gwMAC := [6]byte{0x06, 0x05, 0x04, 0x03, 0x02, 0x01}
	writer := func(b []byte) error { return nil }

	// Use a valid destination (localhost)
	dstIP = [4]byte{127, 0, 0, 1}

	conn, err := newUDPConn(srcIP, 12345, dstIP, 9999, clientMAC, gwMAC, writer)
	if err != nil {
		t.Skipf("cannot create UDP connection: %v", err)
	}
	defer conn.conn.Close()

	if conn.cSrcIP != srcIP {
		t.Error("source IP not set correctly")
	}
	if conn.cSrcPort != 12345 {
		t.Error("source port not set correctly")
	}
	if conn.rIP != dstIP {
		t.Error("remote IP not set correctly")
	}
	if conn.rPort != 9999 {
		t.Error("remote port not set correctly")
	}
	if conn.conn == nil {
		t.Error("UDP connection not initialized")
	}
}

func TestNewUDPConn_Cleanup(t *testing.T) {
	srcIP := [4]byte{127, 0, 0, 1}
	dstIP := [4]byte{127, 0, 0, 1}
	clientMAC := [6]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06}
	gwMAC := [6]byte{0x06, 0x05, 0x04, 0x03, 0x02, 0x01}
	writer := func(b []byte) error { return nil }

	conn, err := newUDPConn(srcIP, 12345, dstIP, 9999, clientMAC, gwMAC, writer)
	if err != nil {
		t.Skipf("cannot create UDP connection: %v", err)
	}
	// Test that we can close the connection
	err = conn.conn.Close()
	if err != nil {
		t.Errorf("failed to close UDP connection: %v", err)
	}
}

func TestUDPConnHandleOutbound(t *testing.T) {
	// Create a UDP echo server
	serverAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("cannot resolve UDP address: %v", err)
	}

	server, err := net.ListenUDP("udp", serverAddr)
	if err != nil {
		t.Skipf("cannot start UDP server: %v", err)
	}
	defer server.Close()

	actualServerAddr := server.LocalAddr().(*net.UDPAddr)

	// Echo server goroutine
	go func() {
		buf := make([]byte, 2048)
		for {
			n, addr, err := server.ReadFromUDP(buf)
			if err != nil {
				return
			}
			if n > 0 {
				server.WriteToUDP(buf[:n], addr)
			}
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

	conn, err := newUDPConn(srcIP, 54321, dstIP, uint16(actualServerAddr.Port), clientMAC, gwMAC, writer)
	if err != nil {
		t.Fatalf("newUDPConn failed: %v", err)
	}
	defer conn.conn.Close()

	// Create a UDP packet with payload
	payload := []byte("Hello, UDP!")
	udpPacket := createUDPPacket(srcIP, dstIP, 54321, uint16(actualServerAddr.Port), payload)

	err = conn.handleOutbound(udpPacket)
	if err != nil {
		t.Fatalf("handleOutbound failed: %v", err)
	}

	// Wait for echo response
	time.Sleep(200 * time.Millisecond)

	mu.Lock()
	frameCount := len(receivedFrames)
	mu.Unlock()

	if frameCount < 1 {
		t.Error("expected at least one response frame from echo server")
	}
}

func TestUDPConnReadLoop(t *testing.T) {
	// Create a UDP server that we can send data to
	serverAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("cannot resolve UDP address: %v", err)
	}

	server, err := net.ListenUDP("udp", serverAddr)
	if err != nil {
		t.Skipf("cannot start UDP server: %v", err)
	}
	defer server.Close()

	actualServerAddr := server.LocalAddr().(*net.UDPAddr)

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

	conn, err := newUDPConn(srcIP, 54321, dstIP, uint16(actualServerAddr.Port), clientMAC, gwMAC, writer)
	if err != nil {
		t.Fatalf("newUDPConn failed: %v", err)
	}
	defer conn.conn.Close()

	// Send data from the server back to the client
	testData := []byte("Response from server")
	clientAddr := conn.conn.LocalAddr().(*net.UDPAddr)
	_, err = server.WriteToUDP(testData, clientAddr)
	if err != nil {
		t.Fatalf("failed to send test data: %v", err)
	}

	// Wait for the data to be processed
	time.Sleep(100 * time.Millisecond)

	mu.Lock()
	frameCount := len(receivedFrames)
	mu.Unlock()

	if frameCount < 1 {
		t.Error("expected at least one frame from readLoop")
	}
}

func TestUDPConnLastAct(t *testing.T) {
	srcIP := [4]byte{127, 0, 0, 1}
	dstIP := [4]byte{127, 0, 0, 1}
	clientMAC := [6]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06}
	gwMAC := [6]byte{0x06, 0x05, 0x04, 0x03, 0x02, 0x01}
	writer := func(b []byte) error { return nil }

	conn, err := newUDPConn(srcIP, 54321, dstIP, 9999, clientMAC, gwMAC, writer)
	if err != nil {
		t.Skipf("cannot create UDP connection: %v", err)
	}
	defer conn.conn.Close()

	initialLastAct := conn.lastAct

	// Wait a bit
	time.Sleep(10 * time.Millisecond)

	// Send a packet
	payload := []byte("test")
	udpPacket := createUDPPacket(srcIP, dstIP, 54321, 9999, payload)
	_ = conn.handleOutbound(udpPacket)

	conn.mu.Lock()
	updatedLastAct := conn.lastAct
	conn.mu.Unlock()

	if !updatedLastAct.After(initialLastAct) {
		t.Error("lastAct should be updated after handling packet")
	}
}

func TestUDPPacketStructure(t *testing.T) {
	srcIP := [4]byte{192, 168, 1, 1}
	dstIP := [4]byte{8, 8, 8, 8}
	payload := []byte("test data")

	pkt := createUDPPacket(srcIP, dstIP, 12345, 53, payload)

	// Check minimum length
	if len(pkt) < 28 { // 20 (IP) + 8 (UDP)
		t.Fatal("packet too short")
	}

	// Check IP header
	if pkt[0]>>4 != 4 {
		t.Error("IP version should be 4")
	}
	if pkt[9] != 17 {
		t.Error("protocol should be 17 (UDP)")
	}

	// Check IP addresses
	if !bytesEqual(pkt[12:16], srcIP[:]) {
		t.Error("source IP incorrect")
	}
	if !bytesEqual(pkt[16:20], dstIP[:]) {
		t.Error("destination IP incorrect")
	}

	// Check UDP header
	udpStart := 20
	if binary.BigEndian.Uint16(pkt[udpStart:udpStart+2]) != 12345 {
		t.Error("UDP source port incorrect")
	}
	if binary.BigEndian.Uint16(pkt[udpStart+2:udpStart+4]) != 53 {
		t.Error("UDP dest port incorrect")
	}

	// Check payload
	payloadStart := udpStart + 8
	if !bytesEqual(pkt[payloadStart:], payload) {
		t.Error("payload incorrect")
	}
}

func TestHandleIPv4_UDP(t *testing.T) {
	s := New()

	// Create UDP echo server
	serverAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("cannot resolve UDP address: %v", err)
	}

	server, err := net.ListenUDP("udp", serverAddr)
	if err != nil {
		t.Skipf("cannot start UDP server: %v", err)
	}
	defer server.Close()

	actualServerAddr := server.LocalAddr().(*net.UDPAddr)

	// Echo server
	go func() {
		buf := make([]byte, 2048)
		for {
			n, addr, err := server.ReadFromUDP(buf)
			if err != nil {
				return
			}
			if n > 0 {
				server.WriteToUDP(buf[:n], addr)
			}
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

	payload := []byte("Hello from test!")
	udpPacket := createUDPPacket(srcIP, dstIP, 54321, uint16(actualServerAddr.Port), payload)

	err = s.HandleIPv4(0, clientMAC, gwMAC, udpPacket, writer)
	if err != nil {
		t.Fatalf("HandleIPv4 failed: %v", err)
	}

	// Wait for echo response
	time.Sleep(200 * time.Millisecond)

	mu.Lock()
	frameCount := len(receivedFrames)
	mu.Unlock()

	if frameCount < 1 {
		t.Error("expected at least one response frame")
	}

	// Verify the connection is tracked
	s.mu.RLock()
	udpConnCount := len(s.udp)
	s.mu.RUnlock()

	if udpConnCount != 1 {
		t.Errorf("expected 1 UDP connection tracked, got %d", udpConnCount)
	}
}

func TestUDPConnShortPacket(t *testing.T) {
	srcIP := [4]byte{127, 0, 0, 1}
	dstIP := [4]byte{127, 0, 0, 1}
	clientMAC := [6]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06}
	gwMAC := [6]byte{0x06, 0x05, 0x04, 0x03, 0x02, 0x01}
	writer := func(b []byte) error { return nil }

	conn, err := newUDPConn(srcIP, 54321, dstIP, 9999, clientMAC, gwMAC, writer)
	if err != nil {
		t.Skipf("cannot create UDP connection: %v", err)
	}
	defer conn.conn.Close()

	// Create a packet that's too short (less than 28 bytes for IP+UDP headers)
	shortPacket := make([]byte, 25)
	shortPacket[0] = 0x45 // IPv4, IHL=5
	shortPacket[9] = 17   // UDP protocol

	err = conn.handleOutbound(shortPacket)
	// Should handle gracefully (return nil)
	if err != nil {
		t.Errorf("handleOutbound should handle short packets gracefully, got error: %v", err)
	}
}

// Helper function to create UDP packets for testing
func createUDPPacket(srcIP, dstIP [4]byte, srcPort, dstPort uint16, payload []byte) []byte {
	ihl := 20
	uh := 8
	totalLen := ihl + uh + len(payload)

	ip := make([]byte, ihl)
	ip[0] = (4 << 4) | 5 // Version 4, IHL 5
	binary.BigEndian.PutUint16(ip[2:4], uint16(totalLen))
	ip[8] = 64 // TTL
	ip[9] = 17 // Protocol: UDP
	copy(ip[12:16], srcIP[:])
	copy(ip[16:20], dstIP[:])
	binary.BigEndian.PutUint16(ip[10:12], ipChecksum(ip))

	udp := make([]byte, uh)
	binary.BigEndian.PutUint16(udp[0:2], srcPort)
	binary.BigEndian.PutUint16(udp[2:4], dstPort)
	binary.BigEndian.PutUint16(udp[4:6], uint16(uh+len(payload)))
	binary.BigEndian.PutUint16(udp[6:8], udpChecksum(ip[12:16], ip[16:20], udp, payload))

	pkt := make([]byte, len(ip)+len(udp)+len(payload))
	copy(pkt, ip)
	copy(pkt[len(ip):], udp)
	copy(pkt[len(ip)+len(udp):], payload)
	return pkt
}
