package slirp

import (
	"encoding/binary"
)

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func createTCPPacket(srcIP, dstIP [4]byte, srcPort, dstPort uint16, seq, ack uint32, flags uint8, payload []byte) []byte {
	ihl := 20
	thl := 20
	totalLen := ihl + thl + len(payload)

	ip := make([]byte, ihl)
	ip[0] = (4 << 4) | 5
	binary.BigEndian.PutUint16(ip[2:4], uint16(totalLen))
	ip[8] = 64
	ip[9] = 6
	copy(ip[12:16], srcIP[:])
	copy(ip[16:20], dstIP[:])
	binary.BigEndian.PutUint16(ip[10:12], IPChecksum(ip))

	tcp := make([]byte, thl)
	binary.BigEndian.PutUint16(tcp[0:2], srcPort)
	binary.BigEndian.PutUint16(tcp[2:4], dstPort)
	binary.BigEndian.PutUint32(tcp[4:8], seq)
	binary.BigEndian.PutUint32(tcp[8:12], ack)
	tcp[12] = (5 << 4)
	tcp[13] = flags
	binary.BigEndian.PutUint16(tcp[14:16], 65535)
	binary.BigEndian.PutUint16(tcp[16:18], TCPChecksum(ip[12:16], ip[16:20], tcp, payload))

	pkt := make([]byte, len(ip)+len(tcp)+len(payload))
	copy(pkt, ip)
	copy(pkt[len(ip):], tcp)
	copy(pkt[len(ip)+len(tcp):], payload)
	return pkt
}

func createTCPPacket6(srcIP, dstIP [16]byte, srcPort, dstPort uint16, seq, ack uint32, flags uint8, payload []byte) []byte {
	thl := 20
	payloadLen := thl + len(payload)

	ip := make([]byte, 40)
	ip[0] = 0x60
	binary.BigEndian.PutUint16(ip[4:6], uint16(payloadLen))
	ip[6] = 6
	ip[7] = 64
	copy(ip[8:24], srcIP[:])
	copy(ip[24:40], dstIP[:])

	tcp := make([]byte, thl)
	binary.BigEndian.PutUint16(tcp[0:2], srcPort)
	binary.BigEndian.PutUint16(tcp[2:4], dstPort)
	binary.BigEndian.PutUint32(tcp[4:8], seq)
	binary.BigEndian.PutUint32(tcp[8:12], ack)
	tcp[12] = (5 << 4)
	tcp[13] = flags
	binary.BigEndian.PutUint16(tcp[14:16], 65535)

	var combined []byte
	if len(payload) > 0 {
		combined = make([]byte, len(tcp)+len(payload))
		copy(combined, tcp)
		copy(combined[len(tcp):], payload)
	} else {
		combined = tcp
	}
	binary.BigEndian.PutUint16(tcp[16:18], 0)
	binary.BigEndian.PutUint16(tcp[16:18], IPv6Checksum(srcIP, dstIP, 6, uint32(len(combined)), combined))

	pkt := make([]byte, len(ip)+len(tcp)+len(payload))
	copy(pkt, ip)
	copy(pkt[len(ip):], tcp)
	copy(pkt[len(ip)+len(tcp):], payload)
	return pkt
}
