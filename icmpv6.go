package slirp

import (
	"encoding/binary"
)

// ICMPv6 Type codes
const (
	ICMPv6TypeEchoRequest           = 128
	ICMPv6TypeEchoReply             = 129
	ICMPv6TypeRouterSolicitation    = 133
	ICMPv6TypeRouterAdvertisement   = 134
	ICMPv6TypeNeighborSolicitation  = 135
	ICMPv6TypeNeighborAdvertisement = 136
)

// handleICMPv6 processes ICMPv6 packets
func (s *Stack) handleICMPv6(namespace uintptr, packet []byte, srcIP, dstIP [16]byte, w Writer) error {
	// ICMPv6 starts at byte 40 (after IPv6 header)
	if len(packet) < 48 { // 40 byte IPv6 header + 8 byte minimum ICMPv6
		return nil
	}

	icmp := packet[40:]
	if len(icmp) < 8 {
		return nil
	}

	icmpType := icmp[0]

	switch icmpType {
	case ICMPv6TypeEchoRequest:
		return s.handleICMPv6EchoRequest(packet, srcIP, dstIP, w)

	case ICMPv6TypeRouterSolicitation:
		// Router Solicitation - typically we ignore this in a NAT context
		return nil

	case ICMPv6TypeNeighborSolicitation, ICMPv6TypeNeighborAdvertisement, ICMPv6TypeRouterAdvertisement:
		// L2 concerns — ignored in pure L3 mode
		return nil

	default:
		return nil
	}
}

// handleICMPv6EchoRequest handles ping6 requests
func (s *Stack) handleICMPv6EchoRequest(packet []byte, srcIP, dstIP [16]byte, w Writer) error {
	// Extract the ICMPv6 payload
	icmp := packet[40:]
	if len(icmp) < 8 {
		return nil
	}

	// Build Echo Reply
	replyICMP := make([]byte, len(icmp))
	copy(replyICMP, icmp)
	replyICMP[0] = ICMPv6TypeEchoReply // Change type to Echo Reply
	replyICMP[1] = 0                   // Code = 0

	// Recalculate checksum
	binary.BigEndian.PutUint16(replyICMP[2:4], 0)
	checksum := IPv6Checksum(dstIP, srcIP, 58, uint32(len(replyICMP)), replyICMP)
	binary.BigEndian.PutUint16(replyICMP[2:4], checksum)

	// Build IPv6 header
	ip := make([]byte, 40)
	ip[0] = 0x60 // Version 6
	binary.BigEndian.PutUint16(ip[4:6], uint16(len(replyICMP)))
	ip[6] = 58                // Next Header: ICMPv6
	ip[7] = 64                // Hop Limit
	copy(ip[8:24], dstIP[:])  // Source = original dest
	copy(ip[24:40], srcIP[:]) // Dest = original source

	// Build raw IP packet (no Ethernet header)
	pkt := make([]byte, len(ip)+len(replyICMP))
	copy(pkt, ip)
	copy(pkt[len(ip):], replyICMP)

	return w(pkt)
}
