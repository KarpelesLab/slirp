package slirp

import (
	"encoding/binary"
	"testing"
)

func TestHandleIPv6_Basic(t *testing.T) {
	s := New()
	clientMAC := [6]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06}
	gwMAC := [6]byte{0x06, 0x05, 0x04, 0x03, 0x02, 0x01}
	writer := func(b []byte) error { return nil }

	// Create a minimal IPv6 TCP SYN packet
	packet := make([]byte, 60) // 40 byte header + 20 byte TCP header

	// IPv6 header
	packet[0] = 0x60 // Version 6
	binary.BigEndian.PutUint16(packet[4:6], 20) // Payload length (TCP header)
	packet[6] = 6  // Next Header: TCP
	packet[7] = 64 // Hop Limit

	// Source address: ::1 (localhost)
	packet[23] = 0x01

	// Destination address: ::1 (localhost)
	packet[39] = 0x01

	// TCP header at byte 40
	binary.BigEndian.PutUint16(packet[40:42], 12345) // Source port
	binary.BigEndian.PutUint16(packet[42:44], 80)    // Dest port
	binary.BigEndian.PutUint32(packet[44:48], 1000)  // Seq
	packet[52] = 0x50                                // Data offset (5 * 4 = 20 bytes)
	packet[53] = 0x02                                // SYN flag

	err := s.HandlePacket(0, clientMAC, gwMAC, packet, writer)
	// IPv6 TCP should now work (dial will fail but no error returned)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestHandleIPv6_TooShort(t *testing.T) {
	s := New()
	clientMAC := [6]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06}
	gwMAC := [6]byte{0x06, 0x05, 0x04, 0x03, 0x02, 0x01}
	writer := func(b []byte) error { return nil }

	// Packet too short for IPv6 header
	packet := make([]byte, 30)
	packet[0] = 0x60 // Version 6

	err := s.HandlePacket(0, clientMAC, gwMAC, packet, writer)
	if err == nil {
		t.Error("expected error for short packet, got nil")
	} else if err.Error() != "IPv6 packet too short" {
		t.Errorf("expected 'IPv6 packet too short', got %q", err.Error())
	}
}

func TestHandleIPv6_UDP(t *testing.T) {
	s := New()
	clientMAC := [6]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06}
	gwMAC := [6]byte{0x06, 0x05, 0x04, 0x03, 0x02, 0x01}
	writer := func(b []byte) error { return nil }

	// Create IPv6 UDP packet with some data
	data := []byte("test")
	packet := make([]byte, 48+len(data)) // 40 byte header + 8 byte UDP header + data

	// IPv6 header
	packet[0] = 0x60 // Version 6
	binary.BigEndian.PutUint16(packet[4:6], uint16(8+len(data))) // Payload length
	packet[6] = 17 // Next Header: UDP
	packet[7] = 64 // Hop Limit

	// Source address: ::1 (localhost)
	packet[23] = 0x01

	// Destination address: ::1 (localhost)
	packet[39] = 0x01

	// UDP header at byte 40
	binary.BigEndian.PutUint16(packet[40:42], 54321) // Source port
	binary.BigEndian.PutUint16(packet[42:44], 53)    // Dest port (DNS)
	binary.BigEndian.PutUint16(packet[44:46], uint16(8+len(data))) // Length

	// Copy data
	copy(packet[48:], data)

	err := s.HandlePacket(0, clientMAC, gwMAC, packet, writer)
	// IPv6 UDP should now work (dial will fail but no error returned)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestHandleIPv6_ICMPv6(t *testing.T) {
	s := New()
	clientMAC := [6]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06}
	gwMAC := [6]byte{0x06, 0x05, 0x04, 0x03, 0x02, 0x01}
	writer := func(b []byte) error { return nil }

	// Create IPv6 ICMPv6 packet
	packet := make([]byte, 48) // 40 byte header + 8 byte ICMPv6

	// IPv6 header
	packet[0] = 0x60 // Version 6
	binary.BigEndian.PutUint16(packet[4:6], 8) // Payload length
	packet[6] = 58 // Next Header: ICMPv6
	packet[7] = 64 // Hop Limit

	// Addresses
	packet[8] = 0xfe
	packet[9] = 0x80
	packet[24] = 0xfe
	packet[25] = 0x80

	err := s.HandlePacket(0, clientMAC, gwMAC, packet, writer)
	// ICMPv6 should return nil (silently ignored for now)
	if err != nil {
		t.Errorf("expected nil for ICMPv6, got %v", err)
	}
}

func TestIPv6Checksum(t *testing.T) {
	// Test IPv6 pseudo-header checksum calculation
	src := [16]byte{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	dst := [16]byte{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}

	data := []byte{
		0x00, 0x50, // Source port
		0x00, 0x50, // Dest port
		0x00, 0x00, 0x00, 0x00, // Seq
		0x00, 0x00, 0x00, 0x00, // Ack
		0x50, 0x02, // Data offset + flags
		0xff, 0xff, // Window
		0x00, 0x00, // Checksum placeholder
		0x00, 0x00, // Urgent pointer
	}

	// Calculate checksum
	checksum := ipv6Checksum(src, dst, 6, uint32(len(data)), data)

	// Checksum should be non-zero
	if checksum == 0 {
		t.Error("IPv6 checksum should be non-zero")
	}
}

func TestHandlePacket_IPv6Detection(t *testing.T) {
	s := New()
	clientMAC := [6]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06}
	gwMAC := [6]byte{0x06, 0x05, 0x04, 0x03, 0x02, 0x01}
	writer := func(b []byte) error { return nil }

	// Create minimal IPv6 TCP packet
	packet := make([]byte, 60)
	packet[0] = 0x60 // Version 6
	binary.BigEndian.PutUint16(packet[4:6], 20)
	packet[6] = 6  // TCP
	packet[7] = 64 // Hop limit

	// Fill in addresses (::1)
	packet[23] = 0x01
	packet[39] = 0x01

	// TCP header
	binary.BigEndian.PutUint16(packet[40:42], 12345) // Source port
	binary.BigEndian.PutUint16(packet[42:44], 80)    // Dest port
	packet[52] = 0x50                                // Data offset
	packet[53] = 0x02                                // SYN flag

	err := s.HandlePacket(0, clientMAC, gwMAC, packet, writer)

	// Should detect IPv6 and successfully handle it
	if err != nil {
		t.Errorf("unexpected error from IPv6 handler: %v", err)
	}
}
