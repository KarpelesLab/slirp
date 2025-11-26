package slirp

import (
	"encoding/binary"
	"io"
	"sync"
	"testing"
	"time"
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
	err = s.HandlePacket(0, clientMAC, gwMAC, synPkt, writer)
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
	if len(synAckFrame) < 14+20+20 {
		t.Fatal("SYN-ACK frame too short")
	}
	tcpHeader := synAckFrame[14+20:]
	serverSeq := binary.BigEndian.Uint32(tcpHeader[4:8])
	serverAck := binary.BigEndian.Uint32(tcpHeader[8:12])

	if serverAck != 1001 {
		t.Errorf("server ack = %d, expected 1001", serverAck)
	}

	// Send ACK to complete handshake
	ackPkt := createTCPPacket(srcIP, dstIP, srcPort, dstPort, 1001, serverSeq+1, 0x10, nil)
	err = s.HandlePacket(0, clientMAC, gwMAC, ackPkt, writer)
	if err != nil {
		t.Fatalf("HandlePacket ACK failed: %v", err)
	}

	time.Sleep(50 * time.Millisecond)

	// Send data
	payload := []byte("Hello, virtual server!")
	dataPkt := createTCPPacket(srcIP, dstIP, srcPort, dstPort, 1001, serverSeq+1, 0x18, payload)
	err = s.HandlePacket(0, clientMAC, gwMAC, dataPkt, writer)
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
	clientMAC := [6]byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x01}
	gwMAC := [6]byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x02}

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
	err = stack.HandlePacket(0, clientMAC, gwMAC, synPkt, writer)
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
	if len(synAckFrame) < 14+20+20 {
		t.Fatal("SYN-ACK frame too short")
	}
	tcpHeader := synAckFrame[14+20:]
	serverSeq := binary.BigEndian.Uint32(tcpHeader[4:8])

	// Send ACK to complete handshake
	ackPkt := createTCPPacket(srcIP, dstIP, srcPort, dstPort, 5001, serverSeq+1, 0x10, nil)
	err = stack.HandlePacket(0, clientMAC, gwMAC, ackPkt, writer)
	if err != nil {
		t.Fatalf("Client ACK failed: %v", err)
	}

	time.Sleep(50 * time.Millisecond)

	// Send data
	testData := []byte("Hello virtual server!")
	dataPkt := createTCPPacket(srcIP, dstIP, srcPort, dstPort, 5001, serverSeq+1, 0x18, testData)
	err = stack.HandlePacket(0, clientMAC, gwMAC, dataPkt, writer)
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

func TestVirtualConnReadWrite(t *testing.T) {
	clientMAC := [6]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06}
	gwMAC := [6]byte{0x06, 0x05, 0x04, 0x03, 0x02, 0x01}
	writer := func(b []byte) error { return nil }

	localIP := [4]byte{10, 0, 0, 1}
	remoteIP := [4]byte{192, 168, 1, 50}

	vc := newVirtualConn(localIP, 9000, remoteIP, 45000, clientMAC, gwMAC, writer)
	vc.established = true

	// Test Write and Read
	testData := []byte("test message")

	// Write should queue data
	n, err := vc.Write(testData)
	if err != nil {
		t.Errorf("Write failed: %v", err)
	}
	if n != len(testData) {
		t.Errorf("Write returned %d, expected %d", n, len(testData))
	}

	// Simulate receiving data from client
	vc.recvMu.Lock()
	vc.recvBuf = append(vc.recvBuf, []byte("received data")...)
	vc.recvMu.Unlock()
	vc.recvCond.Broadcast()

	// Read should return the data
	buf := make([]byte, 100)
	n, err = vc.Read(buf)
	if err != nil {
		t.Errorf("Read failed: %v", err)
	}
	if string(buf[:n]) != "received data" {
		t.Errorf("Read returned %q, expected %q", string(buf[:n]), "received data")
	}
}

func TestVirtualConnClose(t *testing.T) {
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

	localIP := [4]byte{10, 0, 0, 1}
	remoteIP := [4]byte{192, 168, 1, 50}

	vc := newVirtualConn(localIP, 9000, remoteIP, 45000, clientMAC, gwMAC, writer)
	vc.established = true

	err := vc.Close()
	if err != nil {
		t.Errorf("Close failed: %v", err)
	}

	// Verify closed state
	vc.mu.Lock()
	closed := vc.closed
	vc.mu.Unlock()

	if !closed {
		t.Error("connection should be marked as closed")
	}

	// Read should return EOF
	buf := make([]byte, 100)
	_, err = vc.Read(buf)
	if err != io.EOF {
		t.Errorf("Read after close should return EOF, got %v", err)
	}

	// Write should return error
	_, err = vc.Write([]byte("test"))
	if err == nil {
		t.Error("Write after close should return error")
	}
}

func TestVirtualConnAddresses(t *testing.T) {
	clientMAC := [6]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06}
	gwMAC := [6]byte{0x06, 0x05, 0x04, 0x03, 0x02, 0x01}
	writer := func(b []byte) error { return nil }

	localIP := [4]byte{10, 0, 0, 1}
	remoteIP := [4]byte{192, 168, 1, 50}

	vc := newVirtualConn(localIP, 9000, remoteIP, 45000, clientMAC, gwMAC, writer)

	if vc.LocalAddr().String() != "10.0.0.1:9000" {
		t.Errorf("LocalAddr = %s, expected 10.0.0.1:9000", vc.LocalAddr().String())
	}

	if vc.RemoteAddr().String() != "192.168.1.50:45000" {
		t.Errorf("RemoteAddr = %s, expected 192.168.1.50:45000", vc.RemoteAddr().String())
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
