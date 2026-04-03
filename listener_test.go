package slirp

import (
	"encoding/binary"
	"sync"
	"testing"
	"time"

	"github.com/KarpelesLab/slirp/vtcp"
)

func TestStackListen(t *testing.T) {
	s := New()

	listener, err := s.Listen("tcp", "192.168.1.100:8080")
	if err != nil {
		t.Fatalf("Listen failed: %v", err)
	}
	defer listener.Close()

	if listener.Addr().String() != "192.168.1.100:8080" {
		t.Errorf("listener address = %s, expected 192.168.1.100:8080", listener.Addr().String())
	}
}

func TestStackListenDuplicate(t *testing.T) {
	s := New()

	listener1, err := s.Listen("tcp", "192.168.1.100:8080")
	if err != nil {
		t.Fatalf("First Listen failed: %v", err)
	}
	defer listener1.Close()

	_, err = s.Listen("tcp", "192.168.1.100:8080")
	if err == nil {
		t.Error("expected error for duplicate listener, got nil")
	}
}

func TestStackListenUnsupportedNetwork(t *testing.T) {
	s := New()

	_, err := s.Listen("udp", "192.168.1.100:8080")
	if err == nil {
		t.Error("expected error for UDP, got nil")
	}
}

func TestListenerClose(t *testing.T) {
	s := New()

	listener, err := s.Listen("tcp", "192.168.1.100:8080")
	if err != nil {
		t.Fatalf("Listen failed: %v", err)
	}

	err = listener.Close()
	if err != nil {
		t.Errorf("Close failed: %v", err)
	}

	// Should be able to listen on same address after close
	listener2, err := s.Listen("tcp", "192.168.1.100:8080")
	if err != nil {
		t.Fatalf("Second Listen after close failed: %v", err)
	}
	defer listener2.Close()
}

func TestVirtualConnection(t *testing.T) {
	s := New()

	// Create virtual listener
	listener, err := s.Listen("tcp", "10.0.0.1:9000")
	if err != nil {
		t.Fatalf("Listen failed: %v", err)
	}
	defer listener.Close()

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
	serverDone := make(chan bool)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			t.Errorf("Accept failed: %v", err)
			serverDone <- false
			return
		}
		defer conn.Close()

		// Read data from client
		buf := make([]byte, 1024)
		n, err := conn.Read(buf)
		if err != nil {
			t.Errorf("Read failed: %v", err)
			serverDone <- false
			return
		}

		// Echo it back
		_, err = conn.Write(buf[:n])
		if err != nil {
			t.Errorf("Write failed: %v", err)
			serverDone <- false
			return
		}

		serverDone <- true
	}()

	// Give server time to start
	time.Sleep(10 * time.Millisecond)

	// Client: Send SYN
	srcIP := [4]byte{192, 168, 1, 50}
	dstIP := [4]byte{10, 0, 0, 1}
	srcPort := uint16(45000)
	dstPort := uint16(9000)

	synPkt := createTCPPacket(srcIP, dstIP, srcPort, dstPort, 1000, 0, 0x02, nil)
	err = s.HandlePacket(0, synPkt, writer)
	if err != nil {
		t.Fatalf("HandlePacket SYN failed: %v", err)
	}

	// Wait for SYN-ACK
	time.Sleep(50 * time.Millisecond)

	mu.Lock()
	frameCount := len(receivedFrames)
	mu.Unlock()

	if frameCount < 1 {
		t.Fatal("expected SYN-ACK frame")
	}

	// Parse SYN-ACK to get server's seq
	synAckFrame := receivedFrames[0]
	if len(synAckFrame) < 20+20 {
		t.Fatal("SYN-ACK frame too short")
	}
	tcpHeader := synAckFrame[20:]
	serverSeq := binary.BigEndian.Uint32(tcpHeader[4:8])
	serverAck := binary.BigEndian.Uint32(tcpHeader[8:12])

	if serverAck != 1001 {
		t.Errorf("server ack = %d, expected 1001", serverAck)
	}

	// Send ACK to complete handshake
	ackPkt := createTCPPacket(srcIP, dstIP, srcPort, dstPort, 1001, serverSeq+1, 0x10, nil)
	err = s.HandlePacket(0, ackPkt, writer)
	if err != nil {
		t.Fatalf("HandlePacket ACK failed: %v", err)
	}

	time.Sleep(50 * time.Millisecond)

	// Send data
	payload := []byte("Hello, virtual server!")
	dataPkt := createTCPPacket(srcIP, dstIP, srcPort, dstPort, 1001, serverSeq+1, 0x18, payload)
	err = s.HandlePacket(0, dataPkt, writer)
	if err != nil {
		t.Fatalf("HandlePacket data failed: %v", err)
	}

	// Wait for server to process and echo
	time.Sleep(100 * time.Millisecond)

	// Check that server responded
	mu.Lock()
	finalFrameCount := len(receivedFrames)
	mu.Unlock()

	if finalFrameCount < 2 {
		t.Errorf("expected at least 2 frames (SYN-ACK + data), got %d", finalFrameCount)
	}

	// Wait for server to complete
	select {
	case success := <-serverDone:
		if !success {
			t.Error("server goroutine reported failure")
		}
	case <-time.After(1 * time.Second):
		t.Error("timeout waiting for server")
	}
}

func TestTwoSlirpConnection(t *testing.T) {
	// Test connecting two slirp stacks together
	stack := New()

	// Stack listens on virtual address
	listener, err := stack.Listen("tcp", "10.0.0.2:8080")
	if err != nil {
		t.Fatalf("Listen failed: %v", err)
	}
	defer listener.Close()

	// Server goroutine
	serverDone := make(chan []byte, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			t.Errorf("Accept failed: %v", err)
			return
		}
		defer conn.Close()

		buf := make([]byte, 1024)
		n, err := conn.Read(buf)
		if err != nil {
			t.Errorf("Server Read failed: %v", err)
			return
		}

		serverDone <- buf[:n]

		// Echo back
		_, _ = conn.Write(buf[:n])
	}()

	// Client connection through the same stack
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

	srcIP := [4]byte{192, 168, 1, 100}
	dstIP := [4]byte{10, 0, 0, 2}
	srcPort := uint16(50000)
	dstPort := uint16(8080)

	// Send SYN
	synPkt := createTCPPacket(srcIP, dstIP, srcPort, dstPort, 5000, 0, 0x02, nil)
	err = stack.HandlePacket(0, synPkt, writer)
	if err != nil {
		t.Fatalf("Client SYN failed: %v", err)
	}

	// Wait for SYN-ACK
	time.Sleep(50 * time.Millisecond)

	mu.Lock()
	if len(receivedFrames) < 1 {
		mu.Unlock()
		t.Fatal("expected SYN-ACK frame")
	}
	synAckFrame := receivedFrames[0]
	mu.Unlock()

	// Parse SYN-ACK
	if len(synAckFrame) < 20+20 {
		t.Fatal("SYN-ACK frame too short")
	}
	tcpHeader := synAckFrame[20:]
	serverSeq := binary.BigEndian.Uint32(tcpHeader[4:8])

	// Send ACK to complete handshake
	ackPkt := createTCPPacket(srcIP, dstIP, srcPort, dstPort, 5001, serverSeq+1, 0x10, nil)
	err = stack.HandlePacket(0, ackPkt, writer)
	if err != nil {
		t.Fatalf("Client ACK failed: %v", err)
	}

	time.Sleep(50 * time.Millisecond)

	// Send data
	testData := []byte("Hello virtual server!")
	dataPkt := createTCPPacket(srcIP, dstIP, srcPort, dstPort, 5001, serverSeq+1, 0x18, testData)
	err = stack.HandlePacket(0, dataPkt, writer)
	if err != nil {
		t.Fatalf("Client data send failed: %v", err)
	}

	// Check if server received the data
	select {
	case receivedData := <-serverDone:
		if string(receivedData) != string(testData) {
			t.Errorf("Server received %q, expected %q", string(receivedData), string(testData))
		}
	case <-time.After(500 * time.Millisecond):
		t.Error("timeout waiting for server to receive data")
	}
}

func TestListenerAcceptAfterClose(t *testing.T) {
	s := New()

	listener, err := s.Listen("tcp", "192.168.1.100:8080")
	if err != nil {
		t.Fatalf("Listen failed: %v", err)
	}

	err = listener.Close()
	if err != nil {
		t.Errorf("Close failed: %v", err)
	}

	// Accept should return error after close
	_, err = listener.Accept()
	if err == nil {
		t.Error("Accept after Close should return error")
	}
}

func TestVirtualConnHandleInboundRST(t *testing.T) {
	s := New()

	listener, err := s.Listen("tcp", "10.0.0.1:9001")
	if err != nil {
		t.Fatalf("Listen failed: %v", err)
	}
	defer listener.Close()

	writer := func(b []byte) error { return nil }

	srcIP := [4]byte{192, 168, 1, 50}
	dstIP := [4]byte{10, 0, 0, 1}
	srcPort := uint16(45001)
	dstPort := uint16(9001)

	// Send SYN to create the virtual connection
	synPkt := createTCPPacket(srcIP, dstIP, srcPort, dstPort, 1000, 0, 0x02, nil)
	err = s.HandlePacket(0, synPkt, writer)
	if err != nil {
		t.Fatalf("HandlePacket SYN failed: %v", err)
	}

	time.Sleep(50 * time.Millisecond)

	// Find the virtual connection
	k := key{ns: 0, srcIP: srcIP, srcPort: srcPort, dstIP: dstIP, dstPort: dstPort}
	s.mu.RLock()
	vc := s.virtTCP[k]
	s.mu.RUnlock()

	if vc == nil {
		t.Fatal("virtual connection should have been created")
	}

	// Now send RST - vtcp.Conn handles RST regardless of seq/ack values
	rstPkt := createTCPPacket(srcIP, dstIP, srcPort, dstPort, 1001, 0, 0x04, nil)
	err = s.HandlePacket(0, rstPkt, writer)
	if err != nil {
		t.Fatalf("HandlePacket RST failed: %v", err)
	}

	// vtcp.Conn should be in CLOSED state after RST
	if vc.State() != vtcp.StateClosed {
		t.Errorf("virtual connection should be CLOSED after RST, got %v", vc.State())
	}
}

func TestVirtualConnHandleInboundFIN(t *testing.T) {
	s := New()

	listener, err := s.Listen("tcp", "10.0.0.1:9002")
	if err != nil {
		t.Fatalf("Listen failed: %v", err)
	}
	defer listener.Close()

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

	srcIP := [4]byte{192, 168, 1, 50}
	dstIP := [4]byte{10, 0, 0, 1}
	srcPort := uint16(45002)
	dstPort := uint16(9002)

	// Accept in the background
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 1024)
		// Read will eventually return EOF when FIN is processed
		_, _ = conn.Read(buf)
	}()

	// SYN
	synPkt := createTCPPacket(srcIP, dstIP, srcPort, dstPort, 2000, 0, 0x02, nil)
	_ = s.HandlePacket(0, synPkt, writer)
	time.Sleep(50 * time.Millisecond)

	// Get server seq from SYN-ACK
	mu.Lock()
	if len(receivedFrames) < 1 {
		mu.Unlock()
		t.Fatal("expected SYN-ACK")
	}
	synAckFrame := receivedFrames[0]
	mu.Unlock()
	tcpHeader := synAckFrame[20:]
	serverSeq := binary.BigEndian.Uint32(tcpHeader[4:8])

	// ACK to complete handshake
	ackPkt := createTCPPacket(srcIP, dstIP, srcPort, dstPort, 2001, serverSeq+1, 0x10, nil)
	_ = s.HandlePacket(0, ackPkt, writer)
	time.Sleep(50 * time.Millisecond)

	// Send FIN+ACK (RFC 9293 requires ACK on all synchronized segments)
	finPkt := createTCPPacket(srcIP, dstIP, srcPort, dstPort, 2001, serverSeq+1, 0x11, nil)
	_ = s.HandlePacket(0, finPkt, writer)
	time.Sleep(50 * time.Millisecond)

	// Check that an ACK was sent in response to FIN
	mu.Lock()
	ackFound := false
	for i, frame := range receivedFrames {
		if i == 0 {
			continue // skip SYN-ACK
		}
		if len(frame) >= 20+20 {
			hdr := frame[20:]
			flags := hdr[13]
			if (flags & 0x10) != 0 { // ACK flag set
				ackFound = true
				break
			}
		}
	}
	mu.Unlock()

	if !ackFound {
		t.Error("expected ACK to be sent in response to FIN")
	}

	// Server goroutine should complete (Read returns EOF)
	select {
	case <-serverDone:
	case <-time.After(1 * time.Second):
		t.Error("timeout waiting for server to finish after FIN")
	}
}

func TestVirtualConnHandleInboundData(t *testing.T) {
	s := New()

	listener, err := s.Listen("tcp", "10.0.0.1:9003")
	if err != nil {
		t.Fatalf("Listen failed: %v", err)
	}
	defer listener.Close()

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

	srcIP := [4]byte{192, 168, 1, 50}
	dstIP := [4]byte{10, 0, 0, 1}
	srcPort := uint16(45003)
	dstPort := uint16(9003)

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

	// SYN
	synPkt := createTCPPacket(srcIP, dstIP, srcPort, dstPort, 5000, 0, 0x02, nil)
	_ = s.HandlePacket(0, synPkt, writer)
	time.Sleep(50 * time.Millisecond)

	// Parse SYN-ACK
	mu.Lock()
	if len(receivedFrames) < 1 {
		mu.Unlock()
		t.Fatal("expected SYN-ACK")
	}
	synAckFrame := receivedFrames[0]
	mu.Unlock()
	tcpHeader := synAckFrame[20:]
	serverSeq := binary.BigEndian.Uint32(tcpHeader[4:8])

	// ACK to complete handshake
	ackPkt := createTCPPacket(srcIP, dstIP, srcPort, dstPort, 5001, serverSeq+1, 0x10, nil)
	_ = s.HandlePacket(0, ackPkt, writer)
	time.Sleep(50 * time.Millisecond)

	// Send data
	payload := []byte("hello from client")
	dataPkt := createTCPPacket(srcIP, dstIP, srcPort, dstPort, 5001, serverSeq+1, 0x18, payload)
	_ = s.HandlePacket(0, dataPkt, writer)

	// Verify server received the data
	select {
	case data := <-serverDone:
		if data != "hello from client" {
			t.Errorf("expected %q, got %q", "hello from client", data)
		}
	case <-time.After(1 * time.Second):
		t.Error("timeout waiting for server to receive data")
	}

	// Verify an ACK was sent back to the client
	mu.Lock()
	ackSent := false
	for i, frame := range receivedFrames {
		if i == 0 {
			continue // skip SYN-ACK
		}
		if len(frame) >= 20+20 {
			hdr := frame[20:]
			flags := hdr[13]
			if (flags & 0x10) != 0 { // ACK
				ackSent = true
				break
			}
		}
	}
	mu.Unlock()

	if !ackSent {
		t.Error("expected ACK to be sent after receiving data")
	}
}
