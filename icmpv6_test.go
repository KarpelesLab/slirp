package slirp

import (
	"encoding/binary"
	"testing"
)

func TestICMPv6EchoRequest(t *testing.T) {
	s := New()

	var receivedFrame []byte
	writer := func(b []byte) error {
		receivedFrame = make([]byte, len(b))
		copy(receivedFrame, b)
		return nil
	}

	// Create ICMPv6 Echo Request packet
	payload := []byte("hello")
	icmpLen := 8 + len(payload) // 8 byte header + payload
	packet := make([]byte, 40+icmpLen)

	// IPv6 header
	packet[0] = 0x60 // Version 6
	binary.BigEndian.PutUint16(packet[4:6], uint16(icmpLen))
	packet[6] = 58 // Next Header: ICMPv6
	packet[7] = 64 // Hop Limit

	// Source: ::1
	packet[23] = 0x01

	// Dest: ::2
	packet[39] = 0x02

	// ICMPv6 Echo Request
	icmp := packet[40:]
	icmp[0] = 128                               // Type: Echo Request
	icmp[1] = 0                                 // Code
	binary.BigEndian.PutUint16(icmp[2:4], 0)    // Checksum placeholder
	binary.BigEndian.PutUint16(icmp[4:6], 1234) // Identifier
	binary.BigEndian.PutUint16(icmp[6:8], 1)    // Sequence number
	copy(icmp[8:], payload)

	// Calculate checksum
	var srcIP, dstIP [16]byte
	copy(srcIP[:], packet[8:24])
	copy(dstIP[:], packet[24:40])
	checksum := IPv6Checksum(srcIP, dstIP, 58, uint32(len(icmp)), icmp)
	binary.BigEndian.PutUint16(icmp[2:4], checksum)

	err := s.HandlePacket(0, packet, writer)
	if err != nil {
		t.Fatalf("HandlePacket failed: %v", err)
	}

	if receivedFrame == nil {
		t.Fatal("No Echo Reply received")
	}

	// Verify it's an IPv6 packet
	if len(receivedFrame) < 40+8 {
		t.Fatal("Reply frame too short")
	}

	// Check IPv6 header
	ipv6 := receivedFrame
	if ipv6[0]>>4 != 6 {
		t.Errorf("Expected IPv6 version 6, got %d", ipv6[0]>>4)
	}

	if ipv6[6] != 58 {
		t.Errorf("Expected ICMPv6 protocol (58), got %d", ipv6[6])
	}

	// Check ICMPv6 Echo Reply
	replyICMP := ipv6[40:]
	if replyICMP[0] != 129 {
		t.Errorf("Expected ICMPv6 Echo Reply (129), got %d", replyICMP[0])
	}

	// Check identifier and sequence match
	if binary.BigEndian.Uint16(replyICMP[4:6]) != 1234 {
		t.Error("Identifier doesn't match")
	}
	if binary.BigEndian.Uint16(replyICMP[6:8]) != 1 {
		t.Error("Sequence number doesn't match")
	}

	// Check payload
	replyPayload := replyICMP[8 : 8+len(payload)]
	if string(replyPayload) != string(payload) {
		t.Errorf("Payload mismatch: got %q, want %q", replyPayload, payload)
	}
}

func TestICMPv6RouterSolicitation(t *testing.T) {
	s := New()

	var receivedFrame []byte
	writer := func(b []byte) error {
		receivedFrame = make([]byte, len(b))
		copy(receivedFrame, b)
		return nil
	}

	// Create ICMPv6 Router Solicitation packet
	icmpLen := 8
	packet := make([]byte, 40+icmpLen)

	// IPv6 header
	packet[0] = 0x60 // Version 6
	binary.BigEndian.PutUint16(packet[4:6], uint16(icmpLen))
	packet[6] = 58  // Next Header: ICMPv6
	packet[7] = 255 // Hop Limit

	// Source: fe80::1
	packet[8] = 0xfe
	packet[9] = 0x80
	packet[23] = 0x01

	// Dest: All-routers multicast (ff02::2)
	packet[24] = 0xff
	packet[25] = 0x02
	packet[39] = 0x02

	// ICMPv6 Router Solicitation
	icmp := packet[40:]
	icmp[0] = 133 // Type: Router Solicitation
	icmp[1] = 0   // Code

	// Calculate checksum
	var srcIP, dstIP [16]byte
	copy(srcIP[:], packet[8:24])
	copy(dstIP[:], packet[24:40])
	checksum := IPv6Checksum(srcIP, dstIP, 58, uint32(len(icmp)), icmp)
	binary.BigEndian.PutUint16(icmp[2:4], checksum)

	err := s.HandlePacket(0, packet, writer)
	if err != nil {
		t.Fatalf("HandlePacket failed: %v", err)
	}

	// Router Solicitation should be silently ignored (no response)
	if receivedFrame != nil {
		t.Error("Router Solicitation should not generate a response")
	}
}

func TestICMPv6UnknownType(t *testing.T) {
	s := New()

	var receivedFrame []byte
	writer := func(b []byte) error {
		receivedFrame = make([]byte, len(b))
		copy(receivedFrame, b)
		return nil
	}

	// Create ICMPv6 packet with unknown type
	icmpLen := 8
	packet := make([]byte, 40+icmpLen)

	// IPv6 header
	packet[0] = 0x60 // Version 6
	binary.BigEndian.PutUint16(packet[4:6], uint16(icmpLen))
	packet[6] = 58 // Next Header: ICMPv6
	packet[7] = 64 // Hop Limit

	// Addresses
	packet[23] = 0x01
	packet[39] = 0x02

	// ICMPv6 with unknown type
	icmp := packet[40:]
	icmp[0] = 255 // Unknown type
	icmp[1] = 0   // Code

	err := s.HandlePacket(0, packet, writer)
	if err != nil {
		t.Fatalf("HandlePacket failed: %v", err)
	}

	// Unknown types should be silently ignored
	if receivedFrame != nil {
		t.Error("Unknown ICMPv6 type should not generate a response")
	}
}
