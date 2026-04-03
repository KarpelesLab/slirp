package vclient

import (
	"encoding/binary"
	"net"
	"testing"
)

func TestUDPConnReadWrite(t *testing.T) {
	c := New([6]byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}, func([]byte) error { return nil })
	defer c.Close()

	localIP := [4]byte{10, 0, 0, 2}
	remoteIP := [4]byte{10, 0, 0, 1}
	gwMAC := [6]byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x02}

	conn := newUDPConn(c, localIP, 50000, remoteIP, 12345, gwMAC)

	// Enqueue a datagram via handleInbound
	conn.handleInbound([]byte("hello udp"))

	// Read it back
	buf := make([]byte, 64)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if string(buf[:n]) != "hello udp" {
		t.Errorf("Read = %q, want %q", string(buf[:n]), "hello udp")
	}
}

func TestUDPConnReadMultiple(t *testing.T) {
	c := New([6]byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}, func([]byte) error { return nil })
	defer c.Close()

	conn := newUDPConn(c, [4]byte{10, 0, 0, 2}, 50000, [4]byte{10, 0, 0, 1}, 12345, [6]byte{})

	conn.handleInbound([]byte("first"))
	conn.handleInbound([]byte("second"))

	buf := make([]byte, 64)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("Read 1: %v", err)
	}
	if string(buf[:n]) != "first" {
		t.Errorf("Read 1 = %q, want %q", string(buf[:n]), "first")
	}

	n, err = conn.Read(buf)
	if err != nil {
		t.Fatalf("Read 2: %v", err)
	}
	if string(buf[:n]) != "second" {
		t.Errorf("Read 2 = %q, want %q", string(buf[:n]), "second")
	}
}

func TestUDPConnReadClosed(t *testing.T) {
	c := New([6]byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}, func([]byte) error { return nil })
	defer c.Close()

	conn := newUDPConn(c, [4]byte{10, 0, 0, 2}, 50000, [4]byte{10, 0, 0, 1}, 12345, [6]byte{})
	k := connKey{localPort: 50000, remoteIP: [4]byte{10, 0, 0, 1}, remotePort: 12345}
	c.udpMu.Lock()
	c.udpConns[k] = conn
	c.udpMu.Unlock()

	conn.Close()

	buf := make([]byte, 64)
	_, err := conn.Read(buf)
	if err == nil {
		t.Error("expected error reading from closed connection")
	}
}

func TestUDPConnWriteClosed(t *testing.T) {
	c := New([6]byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}, func([]byte) error { return nil })
	defer c.Close()

	conn := newUDPConn(c, [4]byte{10, 0, 0, 2}, 50000, [4]byte{10, 0, 0, 1}, 12345, [6]byte{})
	k := connKey{localPort: 50000, remoteIP: [4]byte{10, 0, 0, 1}, remotePort: 12345}
	c.udpMu.Lock()
	c.udpConns[k] = conn
	c.udpMu.Unlock()

	conn.Close()

	_, err := conn.Write([]byte("data"))
	if err == nil {
		t.Error("expected error writing to closed connection")
	}
}

func TestUDPConnAddresses(t *testing.T) {
	c := New([6]byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}, func([]byte) error { return nil })
	defer c.Close()

	conn := newUDPConn(c, [4]byte{10, 0, 0, 2}, 50000, [4]byte{10, 0, 0, 1}, 12345, [6]byte{})

	local := conn.LocalAddr().(*net.UDPAddr)
	if local.Port != 50000 {
		t.Errorf("LocalAddr port = %d, want 50000", local.Port)
	}
	if !local.IP.Equal(net.IPv4(10, 0, 0, 2)) {
		t.Errorf("LocalAddr IP = %v, want 10.0.0.2", local.IP)
	}

	remote := conn.RemoteAddr().(*net.UDPAddr)
	if remote.Port != 12345 {
		t.Errorf("RemoteAddr port = %d, want 12345", remote.Port)
	}
	if !remote.IP.Equal(net.IPv4(10, 0, 0, 1)) {
		t.Errorf("RemoteAddr IP = %v, want 10.0.0.1", remote.IP)
	}
}

func TestUDPConnHandleInboundCopiesData(t *testing.T) {
	c := New([6]byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}, func([]byte) error { return nil })
	defer c.Close()

	conn := newUDPConn(c, [4]byte{10, 0, 0, 2}, 50000, [4]byte{10, 0, 0, 1}, 12345, [6]byte{})

	// handleInbound should copy the data, not retain the slice
	original := []byte("original")
	conn.handleInbound(original)
	// Modify original
	original[0] = 'X'

	buf := make([]byte, 64)
	n, _ := conn.Read(buf)
	if string(buf[:n]) != "original" {
		t.Errorf("data was not copied: got %q, want %q", string(buf[:n]), "original")
	}
}

// buildIPUDP builds a raw IP+UDP packet for handleUDP testing.
func buildIPUDP(srcIP, dstIP [4]byte, srcPort, dstPort uint16, payload []byte) []byte {
	ipHdrLen := 20
	udpHdrLen := 8
	totalLen := ipHdrLen + udpHdrLen + len(payload)

	pkt := make([]byte, totalLen)
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], uint16(totalLen))
	pkt[8] = 64
	pkt[9] = 17 // UDP
	copy(pkt[12:16], srcIP[:])
	copy(pkt[16:20], dstIP[:])

	udp := pkt[ipHdrLen:]
	binary.BigEndian.PutUint16(udp[0:2], srcPort)
	binary.BigEndian.PutUint16(udp[2:4], dstPort)
	binary.BigEndian.PutUint16(udp[4:6], uint16(udpHdrLen+len(payload)))

	if len(payload) > 0 {
		copy(udp[udpHdrLen:], payload)
	}
	return pkt
}

func TestHandleUDPDispatch(t *testing.T) {
	c := New([6]byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}, func([]byte) error { return nil })
	defer c.Close()

	localIP := [4]byte{10, 0, 0, 2}
	remoteIP := [4]byte{10, 0, 0, 1}

	conn := newUDPConn(c, localIP, 50000, remoteIP, 12345, [6]byte{})
	k := connKey{localPort: 50000, remoteIP: remoteIP, remotePort: 12345}
	c.udpMu.Lock()
	c.udpConns[k] = conn
	c.udpMu.Unlock()

	// Build IP+UDP packet and dispatch through handleUDP
	pkt := buildIPUDP(remoteIP, localIP, 12345, 50000, []byte("dispatched"))
	err := c.handleUDP(pkt, 20)
	if err != nil {
		t.Fatalf("handleUDP: %v", err)
	}

	// Read from the connection
	buf := make([]byte, 64)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if string(buf[:n]) != "dispatched" {
		t.Errorf("Read = %q, want %q", string(buf[:n]), "dispatched")
	}
}

func TestHandleUDPDHCPPath(t *testing.T) {
	c := New([6]byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}, func([]byte) error { return nil })
	defer c.Close()

	// Build packet from port 67 to port 68 (DHCP)
	pkt := buildIPUDP([4]byte{10, 0, 0, 1}, [4]byte{10, 0, 0, 2}, 67, 68, []byte("dhcp-data"))
	err := c.handleUDP(pkt, 20)
	if err != nil {
		t.Fatalf("handleUDP: %v", err)
	}

	// Should be delivered to dhcpCh
	select {
	case data := <-c.dhcpCh:
		if string(data) != "dhcp-data" {
			t.Errorf("DHCP data = %q, want %q", string(data), "dhcp-data")
		}
	default:
		t.Error("expected data on dhcpCh")
	}
}

func TestHandleUDPNoConnection(t *testing.T) {
	c := New([6]byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}, func([]byte) error { return nil })
	defer c.Close()

	// Build packet for a port with no registered connection
	pkt := buildIPUDP([4]byte{10, 0, 0, 1}, [4]byte{10, 0, 0, 2}, 9999, 8888, []byte("orphan"))
	err := c.handleUDP(pkt, 20)
	if err != nil {
		t.Fatalf("handleUDP should not error on unmatched packet: %v", err)
	}
}

func TestHandleUDPTooShort(t *testing.T) {
	c := New([6]byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}, func([]byte) error { return nil })
	defer c.Close()

	// UDP header needs at least 8 bytes after IP header
	shortPkt := make([]byte, 24) // 20 IP + 4 (too short for UDP)
	shortPkt[0] = 0x45
	shortPkt[9] = 17
	err := c.handleUDP(shortPkt, 20)
	if err != nil {
		t.Fatalf("handleUDP should not error on short packet: %v", err)
	}
}

func TestUDPConnDoubleClose(t *testing.T) {
	c := New([6]byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}, func([]byte) error { return nil })
	defer c.Close()

	conn := newUDPConn(c, [4]byte{10, 0, 0, 2}, 50000, [4]byte{10, 0, 0, 1}, 12345, [6]byte{})
	k := connKey{localPort: 50000, remoteIP: [4]byte{10, 0, 0, 1}, remotePort: 12345}
	c.udpMu.Lock()
	c.udpConns[k] = conn
	c.udpMu.Unlock()

	err := conn.Close()
	if err != nil {
		t.Fatalf("first Close: %v", err)
	}
	err = conn.Close()
	if err != nil {
		t.Fatalf("second Close should be nil: %v", err)
	}
}
