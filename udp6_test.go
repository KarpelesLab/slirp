package slirp

import (
	"encoding/binary"
	"net"
	"sync"
	"testing"
	"time"
)

func createUDPPacket6(srcIP, dstIP [16]byte, srcPort, dstPort uint16, payload []byte) []byte {
	uh := 8
	payloadLen := uh + len(payload)

	ip := make([]byte, 40)
	ip[0] = 0x60 // Version 6
	binary.BigEndian.PutUint16(ip[4:6], uint16(payloadLen))
	ip[6] = 17 // Next Header: UDP
	ip[7] = 64 // Hop Limit
	copy(ip[8:24], srcIP[:])
	copy(ip[24:40], dstIP[:])

	udp := make([]byte, uh)
	binary.BigEndian.PutUint16(udp[0:2], srcPort)
	binary.BigEndian.PutUint16(udp[2:4], dstPort)
	binary.BigEndian.PutUint16(udp[4:6], uint16(uh+len(payload)))

	// Checksum
	var udpWithPayload []byte
	if len(payload) > 0 {
		udpWithPayload = make([]byte, len(udp)+len(payload))
		copy(udpWithPayload, udp)
		copy(udpWithPayload[len(udp):], payload)
	} else {
		udpWithPayload = udp
	}
	binary.BigEndian.PutUint16(udp[6:8], 0)
	binary.BigEndian.PutUint16(udp[6:8], IPv6Checksum(srcIP, dstIP, 17, uint32(len(udpWithPayload)), udpWithPayload))

	pkt := make([]byte, len(ip)+len(udp)+len(payload))
	copy(pkt, ip)
	copy(pkt[len(ip):], udp)
	copy(pkt[len(ip)+len(udp):], payload)
	return pkt
}

func TestNewUDPConn6(t *testing.T) {
	var srcIP, dstIP [16]byte
	srcIP[15] = 1 // ::1
	dstIP[15] = 1 // ::1
	writer := func(b []byte) error { return nil }

	conn, err := newUDPConn6(srcIP, 12345, dstIP, 9999, writer)
	if err != nil {
		t.Skipf("cannot create UDP6 connection: %v", err)
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

func TestUDPConn6HandleOutbound(t *testing.T) {
	// Create a UDP echo server on IPv6
	serverAddr, err := net.ResolveUDPAddr("udp6", "[::1]:0")
	if err != nil {
		t.Skipf("cannot resolve UDP6 address: %v", err)
	}

	server, err := net.ListenUDP("udp6", serverAddr)
	if err != nil {
		t.Skipf("cannot start UDP6 server: %v", err)
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

	var srcIP, dstIP [16]byte
	srcIP[15] = 1 // ::1
	dstIP[15] = 1 // ::1

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

	conn, err := newUDPConn6(srcIP, 54321, dstIP, uint16(actualServerAddr.Port), writer)
	if err != nil {
		t.Fatalf("newUDPConn6 failed: %v", err)
	}
	defer conn.conn.Close()

	// Create and send a UDP6 packet
	payload := []byte("Hello IPv6 UDP!")
	udpPacket := createUDPPacket6(srcIP, dstIP, 54321, uint16(actualServerAddr.Port), payload)

	err = conn.handleOutbound(udpPacket)
	if err != nil {
		t.Fatalf("handleOutbound failed: %v", err)
	}

	// Wait for echo response via readLoop
	time.Sleep(200 * time.Millisecond)

	mu.Lock()
	frameCount := len(receivedFrames)
	mu.Unlock()

	if frameCount < 1 {
		t.Error("expected at least one response frame from echo server")
	}

	// Verify the response frame is a valid IPv6 UDP packet
	if frameCount >= 1 {
		mu.Lock()
		frame := receivedFrames[0]
		mu.Unlock()

		if len(frame) < 40+8 {
			t.Fatal("response frame too short")
		}

		// Check IPv6 header
		ipv6 := frame
		if ipv6[0]>>4 != 6 {
			t.Errorf("expected IPv6 version 6, got %d", ipv6[0]>>4)
		}
		if ipv6[6] != 17 {
			t.Errorf("expected UDP protocol (17), got %d", ipv6[6])
		}

		// Check UDP header - ports should be swapped
		udpHdr := ipv6[40:]
		responseSrcPort := binary.BigEndian.Uint16(udpHdr[0:2])
		responseDstPort := binary.BigEndian.Uint16(udpHdr[2:4])
		if responseSrcPort != uint16(actualServerAddr.Port) {
			t.Errorf("response src port should be %d, got %d", actualServerAddr.Port, responseSrcPort)
		}
		if responseDstPort != 54321 {
			t.Errorf("response dst port should be 54321, got %d", responseDstPort)
		}
	}
}

func TestUDPConn6HandleOutboundShortPacket(t *testing.T) {
	var srcIP, dstIP [16]byte
	srcIP[15] = 1
	dstIP[15] = 1
	writer := func(b []byte) error { return nil }

	conn, err := newUDPConn6(srcIP, 54321, dstIP, 9999, writer)
	if err != nil {
		t.Skipf("cannot create UDP6 connection: %v", err)
	}
	defer conn.conn.Close()

	// Packet too short (< 48 bytes)
	shortPacket := make([]byte, 40)
	shortPacket[0] = 0x60
	err = conn.handleOutbound(shortPacket)
	if err != nil {
		t.Errorf("handleOutbound should handle short packets gracefully, got: %v", err)
	}
}

func TestHandlePacket_IPv6UDP(t *testing.T) {
	s := New()

	// Create IPv6 UDP echo server
	serverAddr, err := net.ResolveUDPAddr("udp6", "[::1]:0")
	if err != nil {
		t.Skipf("cannot resolve UDP6 address: %v", err)
	}

	server, err := net.ListenUDP("udp6", serverAddr)
	if err != nil {
		t.Skipf("cannot start UDP6 server: %v", err)
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

	var srcIP, dstIP [16]byte
	srcIP[15] = 1 // ::1
	dstIP[15] = 1 // ::1
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

	payload := []byte("UDP6 test!")
	udpPacket := createUDPPacket6(srcIP, dstIP, 54321, uint16(actualServerAddr.Port), payload)

	err = s.HandlePacket(0, udpPacket, writer)
	if err != nil {
		t.Fatalf("HandlePacket failed: %v", err)
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
	udp6Count := len(s.udp6)
	s.mu.RUnlock()

	if udp6Count != 1 {
		t.Errorf("expected 1 UDP6 connection tracked, got %d", udp6Count)
	}
}

func TestUDPConn6ReadLoop(t *testing.T) {
	// Create a UDP server that sends data to the client
	serverAddr, err := net.ResolveUDPAddr("udp6", "[::1]:0")
	if err != nil {
		t.Skipf("cannot resolve UDP6 address: %v", err)
	}

	server, err := net.ListenUDP("udp6", serverAddr)
	if err != nil {
		t.Skipf("cannot start UDP6 server: %v", err)
	}
	defer server.Close()

	actualServerAddr := server.LocalAddr().(*net.UDPAddr)

	var srcIP, dstIP [16]byte
	srcIP[15] = 1
	dstIP[15] = 1
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

	conn, err := newUDPConn6(srcIP, 54321, dstIP, uint16(actualServerAddr.Port), writer)
	if err != nil {
		t.Fatalf("newUDPConn6 failed: %v", err)
	}
	defer conn.conn.Close()

	// Send data from the server back to the client
	testData := []byte("Response from IPv6 server")
	clientAddr := conn.conn.LocalAddr().(*net.UDPAddr)
	_, err = server.WriteToUDP(testData, clientAddr)
	if err != nil {
		t.Fatalf("failed to send test data: %v", err)
	}

	// Wait for readLoop to process
	time.Sleep(100 * time.Millisecond)

	mu.Lock()
	frameCount := len(receivedFrames)
	mu.Unlock()

	if frameCount < 1 {
		t.Error("expected at least one frame from readLoop")
	}

	// Check lastAct was updated
	conn.mu.Lock()
	lastAct := conn.lastAct
	conn.mu.Unlock()

	if time.Since(lastAct) > 1*time.Second {
		t.Error("lastAct should have been updated recently")
	}
}
