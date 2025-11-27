package slirp

import (
	"encoding/binary"
)

// ICMPv6 Type codes
const (
	ICMPv6TypeEchoRequest      = 128
	ICMPv6TypeEchoReply        = 129
	ICMPv6TypeRouterSolicitation = 133
	ICMPv6TypeRouterAdvertisement = 134
	ICMPv6TypeNeighborSolicitation = 135
	ICMPv6TypeNeighborAdvertisement = 136
)

// handleICMPv6 processes ICMPv6 packets
func (s *Stack) handleICMPv6(namespace uintptr, clientMAC, gwMAC [6]byte, packet []byte, srcIP, dstIP [16]byte, w Writer) error {
	// ICMPv6 starts at byte 40 (after IPv6 header)
	if len(packet) < 48 { // 40 byte IPv6 header + 8 byte minimum ICMPv6
		return nil
	}

	icmp := packet[40:]
	if len(icmp) < 8 {
		return nil
	}

	icmpType := icmp[0]
	icmpCode := icmp[1]

	switch icmpType {
	case ICMPv6TypeEchoRequest:
		return s.handleICMPv6EchoRequest(clientMAC, gwMAC, packet, srcIP, dstIP, w)

	case ICMPv6TypeNeighborSolicitation:
		return s.handleICMPv6NeighborSolicitation(clientMAC, gwMAC, packet, srcIP, dstIP, w)

	case ICMPv6TypeRouterSolicitation:
		// Router Solicitation - typically we ignore this in a NAT context
		// In a full implementation, we might send Router Advertisement
		return nil

	case ICMPv6TypeNeighborAdvertisement, ICMPv6TypeRouterAdvertisement:
		// These are responses, we generally don't need to handle them
		return nil

	default:
		// Unknown ICMPv6 type, ignore
		_ = icmpCode
		return nil
	}
}

// handleICMPv6EchoRequest handles ping6 requests
func (s *Stack) handleICMPv6EchoRequest(clientMAC, gwMAC [6]byte, packet []byte, srcIP, dstIP [16]byte, w Writer) error {
	// Extract the ICMPv6 payload
	icmp := packet[40:]
	if len(icmp) < 8 {
		return nil
	}

	// Build Echo Reply
	// We'll reflect the packet back, changing type to Echo Reply
	replyICMP := make([]byte, len(icmp))
	copy(replyICMP, icmp)
	replyICMP[0] = ICMPv6TypeEchoReply // Change type to Echo Reply
	replyICMP[1] = 0                    // Code = 0

	// Recalculate checksum
	binary.BigEndian.PutUint16(replyICMP[2:4], 0)
	checksum := ipv6Checksum(dstIP, srcIP, 58, uint32(len(replyICMP)), replyICMP)
	binary.BigEndian.PutUint16(replyICMP[2:4], checksum)

	// Build IPv6 header
	ip := make([]byte, 40)
	ip[0] = 0x60 // Version 6
	binary.BigEndian.PutUint16(ip[4:6], uint16(len(replyICMP)))
	ip[6] = 58 // Next Header: ICMPv6
	ip[7] = 64 // Hop Limit
	copy(ip[8:24], dstIP[:])   // Source = original dest
	copy(ip[24:40], srcIP[:])  // Dest = original source

	// Build Ethernet frame
	frame := make([]byte, 14+len(ip)+len(replyICMP))
	copy(frame[0:6], clientMAC[:])  // Dest MAC
	copy(frame[6:12], gwMAC[:])     // Source MAC
	binary.BigEndian.PutUint16(frame[12:14], 0x86DD) // IPv6 EtherType
	copy(frame[14:], ip)
	copy(frame[14+len(ip):], replyICMP)

	return w(frame)
}

// handleICMPv6NeighborSolicitation handles Neighbor Discovery
func (s *Stack) handleICMPv6NeighborSolicitation(clientMAC, gwMAC [6]byte, packet []byte, srcIP, dstIP [16]byte, w Writer) error {
	icmp := packet[40:]
	if len(icmp) < 24 { // NS message is at least 24 bytes
		return nil
	}

	// Extract target address (bytes 8-23 of ICMPv6 message)
	var targetAddr [16]byte
	copy(targetAddr[:], icmp[8:24])

	// Check if the target address matches our gateway address
	// For now, we'll respond to any NS for the destination IP in the packet
	// This is a simplified implementation

	// Build Neighbor Advertisement
	na := make([]byte, 32) // 24 bytes base + 8 bytes for Target Link-Layer Address option
	na[0] = ICMPv6TypeNeighborAdvertisement
	na[1] = 0 // Code = 0
	// Checksum placeholder
	binary.BigEndian.PutUint16(na[2:4], 0)
	// Flags: Router=0, Solicited=1, Override=1
	na[4] = 0x60 // S=1, O=1
	// Reserved bytes 5-7 are already zero
	// Target Address (bytes 8-23)
	copy(na[8:24], targetAddr[:])

	// Target Link-Layer Address Option (Type 2, Length 1 = 8 bytes)
	na[24] = 2   // Type: Target Link-Layer Address
	na[25] = 1   // Length: 1 (in units of 8 bytes)
	copy(na[26:32], gwMAC[:]) // Our MAC address

	// Calculate checksum
	checksum := ipv6Checksum(dstIP, srcIP, 58, uint32(len(na)), na)
	binary.BigEndian.PutUint16(na[2:4], checksum)

	// Build IPv6 header
	ip := make([]byte, 40)
	ip[0] = 0x60 // Version 6
	binary.BigEndian.PutUint16(ip[4:6], uint16(len(na)))
	ip[6] = 58 // Next Header: ICMPv6
	ip[7] = 255 // Hop Limit (must be 255 for NDP)
	copy(ip[8:24], dstIP[:])   // Source = target address
	copy(ip[24:40], srcIP[:])  // Dest = original source

	// Build Ethernet frame
	frame := make([]byte, 14+len(ip)+len(na))
	copy(frame[0:6], clientMAC[:])  // Dest MAC
	copy(frame[6:12], gwMAC[:])     // Source MAC
	binary.BigEndian.PutUint16(frame[12:14], 0x86DD) // IPv6 EtherType
	copy(frame[14:], ip)
	copy(frame[14+len(ip):], na)

	return w(frame)
}
