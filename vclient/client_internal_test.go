package vclient

import (
	"net"
	"testing"
)

func TestMAC(t *testing.T) {
	mac := [6]byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}
	c := New(mac, func([]byte) error { return nil })
	defer c.Close()

	if c.MAC() != mac {
		t.Errorf("MAC() = %v, want %v", c.MAC(), mac)
	}
}

func TestSetDNS(t *testing.T) {
	c := New([6]byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}, func([]byte) error { return nil })
	defer c.Close()

	c.SetDNS([]net.IP{net.IPv4(8, 8, 8, 8), net.IPv4(8, 8, 4, 4)})

	c.mu.RLock()
	defer c.mu.RUnlock()
	if len(c.dns) != 2 {
		t.Fatalf("dns length = %d, want 2", len(c.dns))
	}
	if c.dns[0] != [4]byte{8, 8, 8, 8} {
		t.Errorf("dns[0] = %v, want 8.8.8.8", c.dns[0])
	}
	if c.dns[1] != [4]byte{8, 8, 4, 4} {
		t.Errorf("dns[1] = %v, want 8.8.4.4", c.dns[1])
	}
}

func TestHTTPClient(t *testing.T) {
	c := New([6]byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}, func([]byte) error { return nil })
	defer c.Close()

	hc := c.HTTPClient()
	if hc == nil {
		t.Fatal("HTTPClient() returned nil")
	}
	if hc.Transport == nil {
		t.Error("HTTPClient().Transport should not be nil")
	}
}

func TestUDPConnWritePacket(t *testing.T) {
	var sent []byte
	c := New([6]byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}, func(frame []byte) error {
		sent = make([]byte, len(frame))
		copy(sent, frame)
		return nil
	})
	defer c.Close()
	c.SetIP(net.IPv4(10, 0, 0, 2), net.IPv4Mask(255, 255, 255, 0), net.IPv4(10, 0, 0, 1))

	conn := newUDPConn(c, [4]byte{10, 0, 0, 2}, 50000, [4]byte{10, 0, 0, 1}, 12345,
		[6]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff})

	n, err := conn.writePacket([]byte("test"))
	if err != nil {
		t.Fatalf("writePacket: %v", err)
	}
	if n != 4 {
		t.Errorf("writePacket returned %d, want 4", n)
	}
	if sent == nil {
		t.Fatal("no frame was sent")
	}
	// Frame should be: 14 (eth) + 20 (IP) + 8 (UDP) + 4 (payload) = 46 bytes
	if len(sent) != 46 {
		t.Errorf("frame length = %d, want 46", len(sent))
	}
}

func TestHandleFrameARP(t *testing.T) {
	c := New([6]byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}, func([]byte) error { return nil })
	defer c.Close()
	c.SetIP(net.IPv4(10, 0, 0, 2), net.IPv4Mask(255, 255, 255, 0), net.IPv4(10, 0, 0, 1))

	// Build minimal ARP frame (14 eth + 28 arp = 42 bytes)
	frame := make([]byte, 42)
	// Ethernet: dst, src, type=0x0806
	frame[12] = 0x08
	frame[13] = 0x06
	// ARP: hwtype=1, proto=0x0800, hlen=6, plen=4, oper=1 (request)
	frame[14] = 0
	frame[15] = 1
	frame[16] = 0x08
	frame[17] = 0x00
	frame[18] = 6
	frame[19] = 4
	frame[20] = 0
	frame[21] = 1 // request
	// Target IP = our IP (10.0.0.2)
	frame[38] = 10
	frame[40] = 0
	frame[41] = 2

	err := c.HandleFrame(frame)
	if err != nil {
		t.Fatalf("HandleFrame ARP: %v", err)
	}
}

func TestHandleFrameShort(t *testing.T) {
	c := New([6]byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}, func([]byte) error { return nil })
	defer c.Close()

	// Frame too short
	err := c.HandleFrame([]byte{0x00, 0x01})
	if err != nil {
		t.Errorf("HandleFrame should return nil for short frame, got: %v", err)
	}
}

func TestHandleFrameUnknownEtherType(t *testing.T) {
	c := New([6]byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}, func([]byte) error { return nil })
	defer c.Close()

	frame := make([]byte, 20)
	frame[12] = 0x99 // unknown ethertype
	frame[13] = 0x99

	err := c.HandleFrame(frame)
	if err != nil {
		t.Errorf("HandleFrame should return nil for unknown ethertype, got: %v", err)
	}
}

func TestAllocPortWrap(t *testing.T) {
	c := New([6]byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}, func([]byte) error { return nil })
	defer c.Close()

	c.portMu.Lock()
	c.nextPort = 65535
	c.portMu.Unlock()

	p1 := c.allocPort()
	if p1 != 65535 {
		t.Errorf("first alloc = %d, want 65535", p1)
	}
	p2 := c.allocPort()
	if p2 != 49152 {
		t.Errorf("after wrap = %d, want 49152", p2)
	}
}

func TestSendIPv4NoWriter(t *testing.T) {
	c := New([6]byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}, nil)
	defer c.Close()

	err := c.sendIPv4([6]byte{}, []byte{0x45})
	if err == nil {
		t.Error("expected error with nil writer")
	}
}

func TestResolverReturnValue(t *testing.T) {
	c := New([6]byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}, func([]byte) error { return nil })
	defer c.Close()
	c.SetDNS([]net.IP{net.IPv4(8, 8, 8, 8)})

	r := c.Resolver()
	if r == nil {
		t.Fatal("Resolver() returned nil")
	}
	if !r.PreferGo {
		t.Error("Resolver should have PreferGo=true")
	}
}
