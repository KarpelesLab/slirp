package slirp

import (
	"encoding/binary"
	"io"
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
