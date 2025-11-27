package slirp

import (
	"encoding/binary"
	"testing"
)

func TestICMPv6EchoRequest(t *testing.T) {
	s := New()
	clientMAC := [6]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06}
	gwMAC := [6]byte{0x06, 0x05, 0x04, 0x03, 0x02, 0x01}

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
	icmp[0] = 128 // Type: Echo Request
	icmp[1] = 0   // Code
	binary.BigEndian.PutUint16(icmp[2:4], 0) // Checksum placeholder
	binary.BigEndian.PutUint16(icmp[4:6], 1234) // Identifier
	binary.BigEndian.PutUint16(icmp[6:8], 1)    // Sequence number
	copy(icmp[8:], payload)

	// Calculate checksum
	var srcIP, dstIP [16]byte
	copy(srcIP[:], packet[8:24])
	copy(dstIP[:], packet[24:40])
	checksum := ipv6Checksum(srcIP, dstIP, 58, uint32(len(icmp)), icmp)
	binary.BigEndian.PutUint16(icmp[2:4], checksum)

	err := s.HandlePacket(0, clientMAC, gwMAC, packet, writer)
	if err != nil {
		t.Fatalf("HandlePacket failed: %v", err)
	}

	if receivedFrame == nil {
		t.Fatal("No Echo Reply received")
	}

	// Verify it's an IPv6 frame
	if len(receivedFrame) < 14+40+8 {
		t.Fatal("Reply frame too short")
	}

	etherType := binary.BigEndian.Uint16(receivedFrame[12:14])
	if etherType != 0x86DD {
		t.Errorf("Expected IPv6 EtherType 0x86DD, got 0x%04x", etherType)
	}

	// Check IPv6 header
	ipv6 := receivedFrame[14:]
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

func TestICMPv6NeighborSolicitation(t *testing.T) {
	s := New()
	clientMAC := [6]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06}
	gwMAC := [6]byte{0x06, 0x05, 0x04, 0x03, 0x02, 0x01}

	var receivedFrame []byte
	writer := func(b []byte) error {
		receivedFrame = make([]byte, len(b))
		copy(receivedFrame, b)
		return nil
	}

	// Create ICMPv6 Neighbor Solicitation packet
	icmpLen := 32 // 24 byte NS + 8 byte source link-layer option
	packet := make([]byte, 40+icmpLen)

	// IPv6 header
	packet[0] = 0x60 // Version 6
	binary.BigEndian.PutUint16(packet[4:6], uint16(icmpLen))
	packet[6] = 58  // Next Header: ICMPv6
	packet[7] = 255 // Hop Limit (must be 255 for NDP)

	// Source: fe80::1
	packet[8] = 0xfe
	packet[9] = 0x80
	packet[23] = 0x01

	// Dest: Solicited-node multicast for fe80::2
	// ff02::1:ff00:2
	packet[24] = 0xff
	packet[25] = 0x02
	packet[37] = 0x01
	packet[38] = 0xff
	packet[39] = 0x02

	// ICMPv6 Neighbor Solicitation
	icmp := packet[40:]
	icmp[0] = 135 // Type: Neighbor Solicitation
	icmp[1] = 0   // Code
	binary.BigEndian.PutUint16(icmp[2:4], 0) // Checksum placeholder
	// Reserved (4 bytes)
	// Target Address: fe80::2
	icmp[8] = 0xfe
	icmp[9] = 0x80
	icmp[23] = 0x02

	// Source Link-Layer Address Option
	icmp[24] = 1 // Type: Source Link-Layer Address
	icmp[25] = 1 // Length (in units of 8 bytes)
	copy(icmp[26:32], clientMAC[:])

	// Calculate checksum
	var srcIP, dstIP [16]byte
	copy(srcIP[:], packet[8:24])
	copy(dstIP[:], packet[24:40])
	checksum := ipv6Checksum(srcIP, dstIP, 58, uint32(len(icmp)), icmp)
	binary.BigEndian.PutUint16(icmp[2:4], checksum)

	err := s.HandlePacket(0, clientMAC, gwMAC, packet, writer)
	if err != nil {
		t.Fatalf("HandlePacket failed: %v", err)
	}

	if receivedFrame == nil {
		t.Fatal("No Neighbor Advertisement received")
	}

	// Verify it's an IPv6 frame
	if len(receivedFrame) < 14+40+32 {
		t.Fatal("Reply frame too short")
	}

	etherType := binary.BigEndian.Uint16(receivedFrame[12:14])
	if etherType != 0x86DD {
		t.Errorf("Expected IPv6 EtherType 0x86DD, got 0x%04x", etherType)
	}

	// Check IPv6 header
	ipv6 := receivedFrame[14:]
	if ipv6[0]>>4 != 6 {
		t.Errorf("Expected IPv6 version 6, got %d", ipv6[0]>>4)
	}

	// Check ICMPv6 Neighbor Advertisement
	replyICMP := ipv6[40:]
	if replyICMP[0] != 136 {
		t.Errorf("Expected ICMPv6 Neighbor Advertisement (136), got %d", replyICMP[0])
	}

	// Check flags (Solicited and Override should be set)
	flags := replyICMP[4]
	if (flags & 0x60) != 0x60 {
		t.Errorf("Expected S and O flags set (0x60), got 0x%02x", flags)
	}

	// Check Target Address matches
	targetAddr := replyICMP[8:24]
	expectedTarget := make([]byte, 16)
	expectedTarget[0] = 0xfe
	expectedTarget[1] = 0x80
	expectedTarget[15] = 0x02
	for i := 0; i < 16; i++ {
		if targetAddr[i] != expectedTarget[i] {
			t.Errorf("Target address mismatch at byte %d: got 0x%02x, want 0x%02x", i, targetAddr[i], expectedTarget[i])
			break
		}
	}

	// Check Target Link-Layer Address option
	if replyICMP[24] != 2 {
		t.Errorf("Expected Target Link-Layer Address option (2), got %d", replyICMP[24])
	}
	replyMAC := replyICMP[26:32]
	for i := 0; i < 6; i++ {
		if replyMAC[i] != gwMAC[i] {
			t.Errorf("Target MAC mismatch at byte %d: got 0x%02x, want 0x%02x", i, replyMAC[i], gwMAC[i])
			break
		}
	}
}

func TestICMPv6RouterSolicitation(t *testing.T) {
	s := New()
	clientMAC := [6]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06}
	gwMAC := [6]byte{0x06, 0x05, 0x04, 0x03, 0x02, 0x01}

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
	checksum := ipv6Checksum(srcIP, dstIP, 58, uint32(len(icmp)), icmp)
	binary.BigEndian.PutUint16(icmp[2:4], checksum)

	err := s.HandlePacket(0, clientMAC, gwMAC, packet, writer)
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
	clientMAC := [6]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06}
	gwMAC := [6]byte{0x06, 0x05, 0x04, 0x03, 0x02, 0x01}

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

	err := s.HandlePacket(0, clientMAC, gwMAC, packet, writer)
	if err != nil {
		t.Fatalf("HandlePacket failed: %v", err)
	}

	// Unknown types should be silently ignored
	if receivedFrame != nil {
		t.Error("Unknown ICMPv6 type should not generate a response")
	}
}
