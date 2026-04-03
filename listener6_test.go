package slirp

import (
	"encoding/binary"
	"io"
	"sync"
	"testing"
	"time"
)

func TestStackListen6(t *testing.T) {
	s := New()
	l, err := s.Listen("tcp6", "[::1]:8080")
	if err != nil {
		t.Fatalf("Listen failed: %v", err)
	}
	defer l.Close()

	if l.Addr().String() != "[::1]:8080" {
		t.Errorf("Expected address [::1]:8080, got %s", l.Addr().String())
	}
}

func TestStackListen6Duplicate(t *testing.T) {
	s := New()
	l1, err := s.Listen("tcp6", "[fe80::1]:9000")
	if err != nil {
		t.Fatalf("First Listen failed: %v", err)
	}
	defer l1.Close()

	_, err = s.Listen("tcp6", "[fe80::1]:9000")
	if err == nil {
		t.Error("Expected error for duplicate address, got nil")
	}
}

func TestVirtualConnection6(t *testing.T) {
	t.Skip("Complex integration test - needs refinement")

	s := New()
	clientMAC := [6]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06}
	gwMAC := [6]byte{0x06, 0x05, 0x04, 0x03, 0x02, 0x01}

	// Create listener
	listener, err := s.Listen("tcp6", "[::1]:9000")
	if err != nil {
		t.Fatalf("Listen failed: %v", err)
	}
	defer listener.Close()

	// Server goroutine
	done := make(chan bool)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			t.Errorf("Accept failed: %v", err)
			done <- false
			return
		}
		defer conn.Close()

		// Read from client
		buf := make([]byte, 100)
		n, err := conn.Read(buf)
		if err != nil {
			t.Errorf("Read failed: %v", err)
			done <- false
			return
		}

		// Echo back
		_, err = conn.Write(buf[:n])
		if err != nil {
			t.Errorf("Write failed: %v", err)
			done <- false
			return
		}
		done <- true
	}()

	// Client sends data
	var receivedData []byte
	var writer func([]byte) error
	writer = func(frame []byte) error {
		if len(frame) < 14+40+20 {
			return nil
		}
		// Extract TCP payload from frame
		tcp := frame[14+40:]
		doff := int((tcp[12]>>4)&0x0F) * 4
		if len(tcp) > doff {
			payload := tcp[doff:]
			if len(payload) > 0 {
				receivedData = append(receivedData, payload...)
			}
		}
		return s.HandlePacket(0, clientMAC, gwMAC, frame[14:], writer)
	}

	// Send SYN packet
	synPacket := make([]byte, 60)
	synPacket[0] = 0x60                                        // Version 6
	binary.BigEndian.PutUint16(synPacket[4:6], 20)           // Payload length
	synPacket[6] = 6                                          // TCP
	synPacket[7] = 64                                         // Hop limit
	synPacket[23] = 0x02                                     // Source: ::2
	synPacket[39] = 0x01                                     // Dest: ::1
	binary.BigEndian.PutUint16(synPacket[40:42], 54321)      // Source port
	binary.BigEndian.PutUint16(synPacket[42:44], 9000)       // Dest port
	binary.BigEndian.PutUint32(synPacket[44:48], 1000)       // Seq
	synPacket[52] = 0x50                                     // Data offset
	synPacket[53] = 0x02                                     // SYN flag

	err = s.HandlePacket(0, clientMAC, gwMAC, synPacket, writer)
	if err != nil {
		t.Fatalf("HandlePacket(SYN) failed: %v", err)
	}

	// Send ACK to complete handshake
	ackPacket := make([]byte, 60)
	copy(ackPacket, synPacket)
	binary.BigEndian.PutUint32(ackPacket[44:48], 1001)  // Seq
	binary.BigEndian.PutUint32(ackPacket[48:52], 1001)  // Ack (server's seq + 1)
	ackPacket[53] = 0x10                                 // ACK flag

	time.Sleep(10 * time.Millisecond)
	err = s.HandlePacket(0, clientMAC, gwMAC, ackPacket, writer)
	if err != nil {
		t.Fatalf("HandlePacket(ACK) failed: %v", err)
	}

	// Send data
	testData := []byte("Hello IPv6!")
	dataPacket := make([]byte, 60+len(testData))
	copy(dataPacket, ackPacket)
	binary.BigEndian.PutUint16(dataPacket[4:6], uint16(20+len(testData))) // Update payload length
	dataPacket[53] = 0x18                                                   // PSH+ACK
	copy(dataPacket[60:], testData)

	time.Sleep(10 * time.Millisecond)
	err = s.HandlePacket(0, clientMAC, gwMAC, dataPacket, writer)
	if err != nil {
		t.Fatalf("HandlePacket(data) failed: %v", err)
	}

	// Wait for server to process
	select {
	case success := <-done:
		if !success {
			t.Fatal("Server processing failed")
		}
	case <-time.After(1 * time.Second):
		t.Fatal("Server timed out")
	}
}

func TestVirtualConn6ReadWrite(t *testing.T) {
	clientMAC := [6]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06}
	gwMAC := [6]byte{0x06, 0x05, 0x04, 0x03, 0x02, 0x01}
	writer := func(b []byte) error { return nil }

	var localIP, remoteIP [16]byte
	localIP[15] = 1
	remoteIP[15] = 2

	vc := newVirtualConn6(localIP, 9000, remoteIP, 54321, clientMAC, gwMAC, writer)
	vc.established = true

	// Test Write
	data := []byte("test data")
	n, err := vc.Write(data)
	if err != nil {
		t.Fatalf("Write failed: %v", err)
	}
	if n != len(data) {
		t.Errorf("Expected to write %d bytes, wrote %d", len(data), n)
	}
}

func TestVirtualConn6Close(t *testing.T) {
	clientMAC := [6]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06}
	gwMAC := [6]byte{0x06, 0x05, 0x04, 0x03, 0x02, 0x01}
	writer := func(b []byte) error { return nil }

	var localIP, remoteIP [16]byte
	localIP[15] = 1
	remoteIP[15] = 2

	vc := newVirtualConn6(localIP, 9000, remoteIP, 54321, clientMAC, gwMAC, writer)
	vc.established = true

	err := vc.Close()
	if err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	// Try to read after close
	buf := make([]byte, 10)
	_, err = vc.Read(buf)
	if err != io.EOF {
		t.Errorf("Expected EOF after close, got %v", err)
	}
}

func TestVirtualConn6Addresses(t *testing.T) {
	clientMAC := [6]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06}
	gwMAC := [6]byte{0x06, 0x05, 0x04, 0x03, 0x02, 0x01}
	writer := func(b []byte) error { return nil }

	var localIP, remoteIP [16]byte
	localIP[15] = 1   // ::1
	remoteIP[15] = 2  // ::2

	vc := newVirtualConn6(localIP, 9000, remoteIP, 54321, clientMAC, gwMAC, writer)

	if vc.LocalAddr().String() != "[::1]:9000" {
		t.Errorf("Expected local address [::1]:9000, got %s", vc.LocalAddr().String())
	}

	if vc.RemoteAddr().String() != "[::2]:54321" {
		t.Errorf("Expected remote address [::2]:54321, got %s", vc.RemoteAddr().String())
	}
}

func TestListener6AcceptAfterClose(t *testing.T) {
	s := New()
	listener, err := s.Listen("tcp6", "[::1]:9001")
	if err != nil {
		t.Fatalf("Listen failed: %v", err)
	}

	// Close listener
	listener.Close()

	// Try to accept after close
	_, err = listener.Accept()
	if err == nil {
		t.Error("Expected error when accepting on closed listener")
	}
}

func TestVirtualConn6HandleInboundRST(t *testing.T) {
	clientMAC := [6]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06}
	gwMAC := [6]byte{0x06, 0x05, 0x04, 0x03, 0x02, 0x01}
	writer := func(b []byte) error { return nil }

	var localIP, remoteIP [16]byte
	localIP[15] = 1
	remoteIP[15] = 2

	vc := newVirtualConn6(localIP, 9000, remoteIP, 54321, clientMAC, gwMAC, writer)
	vc.established = true
	vc.clientSeq = 5001
	vc.ack = 5001
	vc.seq = 7000

	// Create RST packet (IPv6 header + TCP header)
	rstPkt := createTCPPacket6(remoteIP, localIP, 54321, 9000, 5001, 7000, 0x04, nil)
	err := vc.handleInbound(rstPkt)
	if err != nil {
		t.Fatalf("handleInbound RST failed: %v", err)
	}

	if !vc.closed.Load() {
		t.Error("virtual connection should be closed after RST")
	}

	// Read should return EOF
	buf := make([]byte, 100)
	_, err = vc.Read(buf)
	if err != io.EOF {
		t.Errorf("Read after RST should return EOF, got %v", err)
	}

	// Write should return error
	_, err = vc.Write([]byte("test"))
	if err == nil {
		t.Error("Write after RST should return error")
	}
}

func TestVirtualConn6HandleInboundData(t *testing.T) {
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

	var localIP, remoteIP [16]byte
	localIP[15] = 1
	remoteIP[15] = 2

	vc := newVirtualConn6(localIP, 9000, remoteIP, 54321, clientMAC, gwMAC, writer)
	vc.established = true
	vc.clientSeq = 5001
	vc.ack = 5001
	vc.seq = 7000

	// Create data packet
	payload := []byte("hello ipv6 client")
	dataPkt := createTCPPacket6(remoteIP, localIP, 54321, 9000, 5001, 7000, 0x18, payload)
	err := vc.handleInbound(dataPkt)
	if err != nil {
		t.Fatalf("handleInbound data failed: %v", err)
	}

	// Read the data
	buf := make([]byte, 100)
	n, err := vc.Read(buf)
	if err != nil {
		t.Fatalf("Read failed: %v", err)
	}
	if string(buf[:n]) != "hello ipv6 client" {
		t.Errorf("expected %q, got %q", "hello ipv6 client", string(buf[:n]))
	}

	// Verify ACK was sent
	mu.Lock()
	ackSent := false
	for _, frame := range receivedFrames {
		if len(frame) >= 14+40+20 {
			hdr := frame[14+40:]
			flags := hdr[13]
			if (flags & 0x10) != 0 {
				ackSent = true
				break
			}
		}
	}
	mu.Unlock()

	if !ackSent {
		t.Error("expected ACK to be sent after receiving data")
	}

	// Verify clientSeq advanced
	vc.mu.Lock()
	cs := vc.clientSeq
	vc.mu.Unlock()
	if cs != 5001+uint32(len(payload)) {
		t.Errorf("clientSeq should be %d, got %d", 5001+uint32(len(payload)), cs)
	}
}

func TestVirtualConn6HandleInboundFIN(t *testing.T) {
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

	var localIP, remoteIP [16]byte
	localIP[15] = 1
	remoteIP[15] = 2

	vc := newVirtualConn6(localIP, 9000, remoteIP, 54321, clientMAC, gwMAC, writer)
	vc.established = true
	vc.clientSeq = 5001
	vc.ack = 5001
	vc.seq = 7000

	// Create FIN packet
	finPkt := createTCPPacket6(remoteIP, localIP, 54321, 9000, 5001, 7000, 0x01, nil)
	err := vc.handleInbound(finPkt)
	if err != nil {
		t.Fatalf("handleInbound FIN failed: %v", err)
	}

	if !vc.closed.Load() {
		t.Error("virtual connection should be closed after FIN")
	}

	// Verify FIN-ACK was sent
	mu.Lock()
	finAckSent := false
	for _, frame := range receivedFrames {
		if len(frame) >= 14+40+20 {
			hdr := frame[14+40:]
			flags := hdr[13]
			if flags == 0x11 { // FIN+ACK
				finAckSent = true
				break
			}
		}
	}
	mu.Unlock()

	if !finAckSent {
		t.Error("expected FIN-ACK to be sent in response to FIN")
	}

	// clientSeq should have advanced by 1
	vc.mu.Lock()
	cs := vc.clientSeq
	vc.mu.Unlock()
	if cs != 5002 {
		t.Errorf("clientSeq should be 5002 after FIN, got %d", cs)
	}
}

func TestVirtualConn6HandleInboundACKHandshake(t *testing.T) {
	clientMAC := [6]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06}
	gwMAC := [6]byte{0x06, 0x05, 0x04, 0x03, 0x02, 0x01}
	writer := func(b []byte) error { return nil }

	var localIP, remoteIP [16]byte
	localIP[15] = 1
	remoteIP[15] = 2

	vc := newVirtualConn6(localIP, 9000, remoteIP, 54321, clientMAC, gwMAC, writer)
	// Not yet established
	vc.clientSeq = 5001
	vc.ack = 5001
	initialSeq := vc.seq

	// ACK with correct ack number to complete handshake
	ackPkt := createTCPPacket6(remoteIP, localIP, 54321, 9000, 5001, initialSeq+1, 0x10, nil)
	err := vc.handleInbound(ackPkt)
	if err != nil {
		t.Fatalf("handleInbound ACK failed: %v", err)
	}

	vc.mu.Lock()
	established := vc.established
	newSeq := vc.seq
	vc.mu.Unlock()

	if !established {
		t.Error("virtual connection should be established after ACK handshake")
	}
	if newSeq != initialSeq+1 {
		t.Errorf("seq should have incremented from %d to %d, got %d", initialSeq, initialSeq+1, newSeq)
	}
}

func TestVirtualConn6HandleInboundShortPackets(t *testing.T) {
	clientMAC := [6]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06}
	gwMAC := [6]byte{0x06, 0x05, 0x04, 0x03, 0x02, 0x01}
	writer := func(b []byte) error { return nil }

	var localIP, remoteIP [16]byte
	localIP[15] = 1
	remoteIP[15] = 2

	vc := newVirtualConn6(localIP, 9000, remoteIP, 54321, clientMAC, gwMAC, writer)

	// Too short for IPv6 header
	err := vc.handleInbound(make([]byte, 30))
	if err != nil {
		t.Errorf("should handle short packet gracefully, got: %v", err)
	}

	// IPv6 header present but TCP too short
	shortPkt := make([]byte, 50)
	shortPkt[0] = 0x60
	err = vc.handleInbound(shortPkt)
	if err != nil {
		t.Errorf("should handle short TCP gracefully, got: %v", err)
	}
}

func TestVirtualConn6CloseSendsFIN(t *testing.T) {
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

	var localIP, remoteIP [16]byte
	localIP[15] = 1
	remoteIP[15] = 2

	vc := newVirtualConn6(localIP, 9000, remoteIP, 54321, clientMAC, gwMAC, writer)
	vc.established = true
	vc.seq = 8000
	vc.ack = 6000

	err := vc.Close()
	if err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	// Should send FIN when established
	mu.Lock()
	finSent := false
	for _, frame := range sentFrames {
		if len(frame) >= 14+40+20 {
			hdr := frame[14+40:]
			flags := hdr[13]
			if flags == 0x11 { // FIN+ACK
				finSent = true
				break
			}
		}
	}
	mu.Unlock()

	if !finSent {
		t.Error("Close() on established IPv6 connection should send FIN+ACK")
	}

	// Second close should be a no-op
	err = vc.Close()
	if err != nil {
		t.Fatalf("second Close failed: %v", err)
	}
}

func TestVirtualConn6SetDeadlines(t *testing.T) {
	clientMAC := [6]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06}
	gwMAC := [6]byte{0x06, 0x05, 0x04, 0x03, 0x02, 0x01}
	writer := func(b []byte) error { return nil }

	var localIP, remoteIP [16]byte
	localIP[15] = 1
	remoteIP[15] = 2

	vc := newVirtualConn6(localIP, 9000, remoteIP, 54321, clientMAC, gwMAC, writer)

	if err := vc.SetDeadline(time.Now()); err != nil {
		t.Errorf("SetDeadline should return nil, got %v", err)
	}
	if err := vc.SetReadDeadline(time.Now()); err != nil {
		t.Errorf("SetReadDeadline should return nil, got %v", err)
	}
	if err := vc.SetWriteDeadline(time.Now()); err != nil {
		t.Errorf("SetWriteDeadline should return nil, got %v", err)
	}
}

func TestVirtualConn6WriteAfterClose(t *testing.T) {
	clientMAC := [6]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06}
	gwMAC := [6]byte{0x06, 0x05, 0x04, 0x03, 0x02, 0x01}
	writer := func(b []byte) error { return nil }

	var localIP, remoteIP [16]byte
	localIP[15] = 1
	remoteIP[15] = 2

	vc := newVirtualConn6(localIP, 9000, remoteIP, 54321, clientMAC, gwMAC, writer)
	vc.established = true
	vc.Close()

	_, err := vc.Write([]byte("test"))
	if err == nil {
		t.Error("Write after Close should return error")
	}
}

func TestIPv6VirtualListenerFullHandshake(t *testing.T) {
	s := New()

	listener, err := s.Listen("tcp6", "[::1]:9010")
	if err != nil {
		t.Fatalf("Listen failed: %v", err)
	}
	defer listener.Close()

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

	// Server goroutine
	serverDone := make(chan string, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			serverDone <- ""
			return
		}
		defer conn.Close()
		buf := make([]byte, 1024)
		n, err := conn.Read(buf)
		if err != nil {
			serverDone <- ""
			return
		}
		serverDone <- string(buf[:n])
	}()

	var srcIP, dstIP [16]byte
	srcIP[15] = 2 // ::2
	dstIP[15] = 1 // ::1
	srcPort := uint16(55555)
	dstPort := uint16(9010)

	// SYN
	synPkt := createTCPPacket6(srcIP, dstIP, srcPort, dstPort, 1000, 0, 0x02, nil)
	err = s.HandlePacket(0, clientMAC, gwMAC, synPkt, writer)
	if err != nil {
		t.Fatalf("HandlePacket SYN failed: %v", err)
	}

	time.Sleep(50 * time.Millisecond)

	// Get SYN-ACK
	mu.Lock()
	if len(receivedFrames) < 1 {
		mu.Unlock()
		t.Fatal("expected SYN-ACK frame")
	}
	synAckFrame := receivedFrames[0]
	mu.Unlock()

	if len(synAckFrame) < 14+40+20 {
		t.Fatal("SYN-ACK frame too short")
	}
	tcpHeader := synAckFrame[14+40:]
	serverSeq := binary.BigEndian.Uint32(tcpHeader[4:8])
	serverAck := binary.BigEndian.Uint32(tcpHeader[8:12])

	if serverAck != 1001 {
		t.Errorf("server ack = %d, expected 1001", serverAck)
	}

	// ACK to complete handshake
	ackPkt := createTCPPacket6(srcIP, dstIP, srcPort, dstPort, 1001, serverSeq+1, 0x10, nil)
	err = s.HandlePacket(0, clientMAC, gwMAC, ackPkt, writer)
	if err != nil {
		t.Fatalf("HandlePacket ACK failed: %v", err)
	}

	time.Sleep(50 * time.Millisecond)

	// Send data
	testData := []byte("IPv6 virtual data!")
	dataPkt := createTCPPacket6(srcIP, dstIP, srcPort, dstPort, 1001, serverSeq+1, 0x18, testData)
	err = s.HandlePacket(0, clientMAC, gwMAC, dataPkt, writer)
	if err != nil {
		t.Fatalf("HandlePacket data failed: %v", err)
	}

	// Wait for server to receive
	select {
	case data := <-serverDone:
		if data != "IPv6 virtual data!" {
			t.Errorf("server received %q, expected %q", data, "IPv6 virtual data!")
		}
	case <-time.After(1 * time.Second):
		t.Error("timeout waiting for server to receive data")
	}
}
