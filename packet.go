package slirp

import "encoding/binary"

// buildPacket4 wraps a raw TCP segment in an IPv4 packet (no Ethernet header).
func buildPacket4(srcIP, dstIP [4]byte, tcpSeg []byte) []byte {
	ihl := 20
	totalLen := ihl + len(tcpSeg)

	ip := make([]byte, ihl)
	ip[0] = (4 << 4) | 5
	binary.BigEndian.PutUint16(ip[2:4], uint16(totalLen))
	ip[8] = 64 // TTL
	ip[9] = 6  // TCP
	copy(ip[12:16], srcIP[:])
	copy(ip[16:20], dstIP[:])
	binary.BigEndian.PutUint16(ip[10:12], 0)
	binary.BigEndian.PutUint16(ip[10:12], IPChecksum(ip))

	// Compute TCP checksum (requires IP pseudo-header)
	tcpCopy := make([]byte, len(tcpSeg))
	copy(tcpCopy, tcpSeg)
	// Zero the checksum field before computing
	if len(tcpCopy) >= 18 {
		binary.BigEndian.PutUint16(tcpCopy[16:18], 0)
		// Split into header and payload at data offset
		doff := int(tcpCopy[12]>>4) * 4
		if doff > 0 && doff <= len(tcpCopy) {
			hdr := tcpCopy[:doff]
			payload := tcpCopy[doff:]
			cs := TCPChecksum(ip[12:16], ip[16:20], hdr, payload)
			binary.BigEndian.PutUint16(tcpCopy[16:18], cs)
		}
	}

	pkt := make([]byte, ihl+len(tcpCopy))
	copy(pkt, ip)
	copy(pkt[ihl:], tcpCopy)
	return pkt
}

// buildPacket6 wraps a raw TCP segment in an IPv6 packet (no Ethernet header).
func buildPacket6(srcIP, dstIP [16]byte, tcpSeg []byte) []byte {
	ip := make([]byte, 40)
	ip[0] = 0x60 // Version 6
	binary.BigEndian.PutUint16(ip[4:6], uint16(len(tcpSeg)))
	ip[6] = 6  // Next Header: TCP
	ip[7] = 64 // Hop Limit
	copy(ip[8:24], srcIP[:])
	copy(ip[24:40], dstIP[:])

	// Compute TCP checksum with IPv6 pseudo-header
	tcpCopy := make([]byte, len(tcpSeg))
	copy(tcpCopy, tcpSeg)
	if len(tcpCopy) >= 18 {
		binary.BigEndian.PutUint16(tcpCopy[16:18], 0)
		cs := IPv6Checksum(srcIP, dstIP, 6, uint32(len(tcpCopy)), tcpCopy)
		binary.BigEndian.PutUint16(tcpCopy[16:18], cs)
	}

	pkt := make([]byte, 40+len(tcpCopy))
	copy(pkt, ip)
	copy(pkt[40:], tcpCopy)
	return pkt
}
