package slirp

import (
	"encoding/binary"
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
