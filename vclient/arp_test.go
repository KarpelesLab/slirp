package vclient

import (
	"encoding/binary"
	"net"
	"sync"
	"testing"
)

func TestSetGatewayMAC(t *testing.T) {
	c := New([6]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06}, nil)
	defer c.Close()
	c.SetIP(net.IPv4(10, 0, 0, 2), net.IPv4Mask(255, 255, 255, 0), net.IPv4(10, 0, 0, 1))

	gwMAC := [6]byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF}
	c.SetGatewayMAC(gwMAC)

	got := c.getGatewayMAC()
	if got != gwMAC {
		t.Errorf("getGatewayMAC() = %v, want %v", got, gwMAC)
	}
}

func TestGetGatewayMACFallback(t *testing.T) {
	c := New([6]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06}, nil)
	defer c.Close()

	// No gateway set, no sentinel -- should return broadcast
	got := c.getGatewayMAC()
	if got != [6]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff} {
		t.Errorf("getGatewayMAC() = %v, want broadcast", got)
	}
}

func TestGetGatewayMACSentinel(t *testing.T) {
	c := New([6]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06}, nil)
	defer c.Close()

	// Set sentinel (used by Pipe)
	sentinel := [6]byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66}
	c.arpMu.Lock()
	c.arpTable[[4]byte{0, 0, 0, 0}] = sentinel
	c.arpMu.Unlock()

	got := c.getGatewayMAC()
	if got != sentinel {
		t.Errorf("getGatewayMAC() = %v, want sentinel %v", got, sentinel)
	}
}

// buildARPFrame builds a complete Ethernet+ARP frame.
func buildARPFrame(dstMAC, srcMAC [6]byte, oper uint16, senderMAC [6]byte, senderIP, targetIP [4]byte) []byte {
	frame := make([]byte, 42)
	copy(frame[0:6], dstMAC[:])
	copy(frame[6:12], srcMAC[:])
	binary.BigEndian.PutUint16(frame[12:14], 0x0806)

	arp := frame[14:]
	binary.BigEndian.PutUint16(arp[0:2], 1)      // HTYPE: Ethernet
	binary.BigEndian.PutUint16(arp[2:4], 0x0800) // PTYPE: IPv4
	arp[4] = 6                                   // HLEN
	arp[5] = 4                                   // PLEN
	binary.BigEndian.PutUint16(arp[6:8], oper)
	copy(arp[8:14], senderMAC[:])
	copy(arp[14:18], senderIP[:])
	// target MAC left zero for requests
	copy(arp[24:28], targetIP[:])
	return frame
}

func TestHandleARPRequest(t *testing.T) {
	var sent [][]byte
	var mu sync.Mutex
	c := New([6]byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}, func(frame []byte) error {
		cpy := make([]byte, len(frame))
		copy(cpy, frame)
		mu.Lock()
		sent = append(sent, cpy)
		mu.Unlock()
		return nil
	})
	defer c.Close()
	c.SetIP(net.IPv4(10, 0, 0, 2), net.IPv4Mask(255, 255, 255, 0), net.IPv4(10, 0, 0, 1))

	// Build ARP request asking for our IP
	senderMAC := [6]byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x99}
	senderIP := [4]byte{10, 0, 0, 1}
	targetIP := [4]byte{10, 0, 0, 2} // our IP
	frame := buildARPFrame([6]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, senderMAC, 1, senderMAC, senderIP, targetIP)

	err := c.handleARP(frame)
	if err != nil {
		t.Fatalf("handleARP: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(sent) != 1 {
		t.Fatalf("expected 1 reply frame, got %d", len(sent))
	}

	reply := sent[0]
	if len(reply) < 42 {
		t.Fatalf("reply too short: %d", len(reply))
	}
	// Check it's an ARP reply
	oper := binary.BigEndian.Uint16(reply[14+6 : 14+8])
	if oper != 2 {
		t.Errorf("reply oper = %d, want 2 (Reply)", oper)
	}
	// Reply sender MAC should be our MAC
	var replySenderMAC [6]byte
	copy(replySenderMAC[:], reply[14+8:14+14])
	if replySenderMAC != c.mac {
		t.Errorf("reply sender MAC = %v, want %v", replySenderMAC, c.mac)
	}
}

func TestHandleARPRequestNotOurIP(t *testing.T) {
	sent := 0
	c := New([6]byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}, func(frame []byte) error {
		sent++
		return nil
	})
	defer c.Close()
	c.SetIP(net.IPv4(10, 0, 0, 2), net.IPv4Mask(255, 255, 255, 0), net.IPv4(10, 0, 0, 1))

	// ARP request for a different IP
	frame := buildARPFrame(
		[6]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		[6]byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x99},
		1, // request
		[6]byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x99},
		[4]byte{10, 0, 0, 1},
		[4]byte{10, 0, 0, 99}, // not our IP
	)
	err := c.handleARP(frame)
	if err != nil {
		t.Fatalf("handleARP: %v", err)
	}
	if sent != 0 {
		t.Errorf("should not send reply for non-matching IP, sent %d frames", sent)
	}
}

func TestHandleARPReply(t *testing.T) {
	c := New([6]byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}, func([]byte) error { return nil })
	defer c.Close()
	c.SetIP(net.IPv4(10, 0, 0, 2), net.IPv4Mask(255, 255, 255, 0), net.IPv4(10, 0, 0, 1))

	// Register a waiter for 10.0.0.1
	waitCh := make(chan [6]byte, 1)
	c.arpMu.Lock()
	c.arpWait[[4]byte{10, 0, 0, 1}] = append(c.arpWait[[4]byte{10, 0, 0, 1}], waitCh)
	c.arpMu.Unlock()

	// Build ARP reply
	replyMAC := [6]byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF}
	frame := buildARPFrame(
		c.mac,
		replyMAC,
		2, // reply
		replyMAC,
		[4]byte{10, 0, 0, 1},
		[4]byte{10, 0, 0, 2},
	)
	err := c.handleARP(frame)
	if err != nil {
		t.Fatalf("handleARP: %v", err)
	}

	// Check ARP table was updated
	c.arpMu.Lock()
	mac, ok := c.arpTable[[4]byte{10, 0, 0, 1}]
	c.arpMu.Unlock()
	if !ok {
		t.Fatal("ARP table should contain 10.0.0.1")
	}
	if mac != replyMAC {
		t.Errorf("ARP table MAC = %v, want %v", mac, replyMAC)
	}

	// Check waiter was notified
	select {
	case got := <-waitCh:
		if got != replyMAC {
			t.Errorf("waiter got MAC %v, want %v", got, replyMAC)
		}
	default:
		t.Error("waiter was not notified")
	}
}

func TestHandleARPTooShort(t *testing.T) {
	c := New([6]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06}, nil)
	defer c.Close()
	// Frame shorter than 42 bytes
	err := c.handleARP(make([]byte, 30))
	if err != nil {
		t.Errorf("expected nil error for short frame, got %v", err)
	}
}

func TestHandleARPBadHardwareType(t *testing.T) {
	c := New([6]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06}, nil)
	defer c.Close()
	frame := buildARPFrame([6]byte{}, [6]byte{}, 1, [6]byte{}, [4]byte{}, [4]byte{})
	// Set hardware type to non-Ethernet
	binary.BigEndian.PutUint16(frame[14:16], 99)
	err := c.handleARP(frame)
	if err != nil {
		t.Errorf("expected nil error for bad hwtype, got %v", err)
	}
}

func TestHandleARPBadProtocolType(t *testing.T) {
	c := New([6]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06}, nil)
	defer c.Close()
	frame := buildARPFrame([6]byte{}, [6]byte{}, 1, [6]byte{}, [4]byte{}, [4]byte{})
	// Set protocol type to non-IPv4
	binary.BigEndian.PutUint16(frame[16:18], 0x86DD)
	err := c.handleARP(frame)
	if err != nil {
		t.Errorf("expected nil error for bad proto, got %v", err)
	}
}

func TestSendARPRequest(t *testing.T) {
	var sent []byte
	c := New([6]byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}, func(frame []byte) error {
		sent = make([]byte, len(frame))
		copy(sent, frame)
		return nil
	})
	defer c.Close()
	c.SetIP(net.IPv4(10, 0, 0, 2), net.IPv4Mask(255, 255, 255, 0), net.IPv4(10, 0, 0, 1))

	err := c.sendARPRequest([4]byte{10, 0, 0, 1})
	if err != nil {
		t.Fatalf("sendARPRequest: %v", err)
	}
	if len(sent) < 42 {
		t.Fatalf("frame too short: %d", len(sent))
	}
	// Ethernet destination should be broadcast
	for i := 0; i < 6; i++ {
		if sent[i] != 0xff {
			t.Errorf("dst MAC byte %d = 0x%02x, want 0xff", i, sent[i])
		}
	}
	// EtherType should be ARP
	et := binary.BigEndian.Uint16(sent[12:14])
	if et != 0x0806 {
		t.Errorf("EtherType = 0x%04x, want 0x0806", et)
	}
	// ARP operation should be Request (1)
	oper := binary.BigEndian.Uint16(sent[14+6 : 14+8])
	if oper != 1 {
		t.Errorf("ARP oper = %d, want 1", oper)
	}
	// Target IP
	var targetIP [4]byte
	copy(targetIP[:], sent[14+24:14+28])
	if targetIP != [4]byte{10, 0, 0, 1} {
		t.Errorf("target IP = %v, want 10.0.0.1", targetIP)
	}
}

func TestSendARPRequestNoWriter(t *testing.T) {
	c := New([6]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06}, nil)
	defer c.Close()
	c.SetIP(net.IPv4(10, 0, 0, 2), net.IPv4Mask(255, 255, 255, 0), net.IPv4(10, 0, 0, 1))

	err := c.sendARPRequest([4]byte{10, 0, 0, 1})
	if err == nil {
		t.Error("expected error with nil writer")
	}
}

func TestSendARPReply(t *testing.T) {
	var sent []byte
	c := New([6]byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}, func(frame []byte) error {
		sent = make([]byte, len(frame))
		copy(sent, frame)
		return nil
	})
	defer c.Close()
	c.SetIP(net.IPv4(10, 0, 0, 2), net.IPv4Mask(255, 255, 255, 0), net.IPv4(10, 0, 0, 1))

	targetMAC := [6]byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF}
	err := c.sendARPReply([4]byte{10, 0, 0, 1}, targetMAC)
	if err != nil {
		t.Fatalf("sendARPReply: %v", err)
	}
	if len(sent) < 42 {
		t.Fatalf("frame too short: %d", len(sent))
	}
	// Ethernet destination should be the target MAC
	var dstMAC [6]byte
	copy(dstMAC[:], sent[0:6])
	if dstMAC != targetMAC {
		t.Errorf("dst MAC = %v, want %v", dstMAC, targetMAC)
	}
	// ARP operation should be Reply (2)
	oper := binary.BigEndian.Uint16(sent[14+6 : 14+8])
	if oper != 2 {
		t.Errorf("ARP oper = %d, want 2", oper)
	}
	// Sender IP should be our IP
	var senderIP [4]byte
	copy(senderIP[:], sent[14+14:14+18])
	if senderIP != [4]byte{10, 0, 0, 2} {
		t.Errorf("sender IP = %v, want 10.0.0.2", senderIP)
	}
}

func TestSendARPReplyNoWriter(t *testing.T) {
	c := New([6]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06}, nil)
	defer c.Close()
	c.SetIP(net.IPv4(10, 0, 0, 2), net.IPv4Mask(255, 255, 255, 0), net.IPv4(10, 0, 0, 1))

	err := c.sendARPReply([4]byte{10, 0, 0, 1}, [6]byte{})
	if err == nil {
		t.Error("expected error with nil writer")
	}
}
