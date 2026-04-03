package vclient

import (
	"net"
	"testing"
)

func TestSetDNS(t *testing.T) {
	c := New(func([]byte) error { return nil })
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
	c := New(func([]byte) error { return nil })
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
	c := New(func(packet []byte) error {
		sent = make([]byte, len(packet))
		copy(sent, packet)
		return nil
	})
	defer c.Close()
	c.SetIP(net.IPv4(10, 0, 0, 2), net.IPv4Mask(255, 255, 255, 0), net.IPv4(10, 0, 0, 1))

	conn := newUDPConn(c, [4]byte{10, 0, 0, 2}, 50000, [4]byte{10, 0, 0, 1}, 12345)

	n, err := conn.writePacket([]byte("test"))
	if err != nil {
		t.Fatalf("writePacket: %v", err)
	}
	if n != 4 {
		t.Errorf("writePacket returned %d, want 4", n)
	}
	if sent == nil {
		t.Fatal("no packet was sent")
	}
	// Packet should be: 20 (IP) + 8 (UDP) + 4 (payload) = 32 bytes
	if len(sent) != 32 {
		t.Errorf("packet length = %d, want 32", len(sent))
	}
}

func TestAllocPortWrap(t *testing.T) {
	c := New(func([]byte) error { return nil })
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

func TestSendPacketNoWriter(t *testing.T) {
	c := New(nil)
	defer c.Close()

	err := c.sendPacket([]byte{0x45})
	if err == nil {
		t.Error("expected error with nil writer")
	}
}

func TestResolverReturnValue(t *testing.T) {
	c := New(func([]byte) error { return nil })
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
