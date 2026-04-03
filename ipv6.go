package slirp

import (
	"encoding/binary"
	"errors"
	"net"

	"github.com/KarpelesLab/slirp/vtcp"
)

// key6 represents a connection key for IPv6
type key6 struct {
	ns      uintptr
	srcIP   [16]byte
	srcPort uint16
	dstIP   [16]byte
	dstPort uint16
}

// handleIPv6 processes an IPv6 packet
func (s *Stack) handleIPv6(namespace uintptr, clientMAC [6]byte, gwMAC [6]byte, packet []byte, w Writer) error {
	// IPv6 header is fixed 40 bytes
	if len(packet) < 40 {
		return errors.New("IPv6 packet too short")
	}

	// Parse IPv6 header
	// Bytes 0-3: Version(4 bits), Traffic Class(8 bits), Flow Label(20 bits)
	// Bytes 4-5: Payload Length
	// Byte 6: Next Header (protocol)
	// Byte 7: Hop Limit
	// Bytes 8-23: Source Address (128 bits)
	// Bytes 24-39: Destination Address (128 bits)

	payloadLen := binary.BigEndian.Uint16(packet[4:6])
	if len(packet) < 40+int(payloadLen) {
		return errors.New("IPv6 packet shorter than payload length")
	}
	packet = packet[:40+int(payloadLen)]

	nextHeader := packet[6] // This is the protocol (TCP=6, UDP=17, etc.)

	var srcIP, dstIP [16]byte
	copy(srcIP[:], packet[8:24])
	copy(dstIP[:], packet[24:40])

	// Skip extension headers to find the transport protocol
	proto, transportOff := skipExtensionHeaders(packet, nextHeader, 40)

	switch proto {
	case 6: // TCP
		if len(packet) < transportOff+20 {
			return nil
		}
		return s.handleIPv6TCP(namespace, clientMAC, gwMAC, packet, srcIP, dstIP, transportOff, w)

	case 17: // UDP
		if len(packet) < transportOff+8 {
			return nil
		}
		return s.handleIPv6UDP(namespace, clientMAC, gwMAC, packet, srcIP, dstIP, transportOff, w)

	case 58: // ICMPv6
		if len(packet) < transportOff+8 {
			return nil
		}
		return s.handleICMPv6(namespace, clientMAC, gwMAC, packet, srcIP, dstIP, w)

	default:
		// Unsupported protocol
		return nil
	}
}

// skipExtensionHeaders walks through IPv6 extension headers starting at the
// given offset and returns the final transport protocol number and the byte
// offset where that protocol's header begins.
func skipExtensionHeaders(packet []byte, nextHeader uint8, offset int) (proto uint8, transportOff int) {
	for {
		switch nextHeader {
		case 0, 43, 60: // Hop-by-Hop, Routing, Destination Options
			if offset+2 > len(packet) {
				return nextHeader, offset
			}
			nh := packet[offset]
			hdrLen := (int(packet[offset+1]) + 1) * 8
			nextHeader = nh
			offset += hdrLen
		case 44: // Fragment — fixed 8 bytes
			if offset+8 > len(packet) {
				return nextHeader, offset
			}
			nh := packet[offset]
			nextHeader = nh
			offset += 8
		default:
			return nextHeader, offset
		}
	}
}

func (s *Stack) handleIPv6TCP(namespace uintptr, clientMAC, gwMAC [6]byte, packet []byte, srcIP, dstIP [16]byte, transportOff int, w Writer) error {
	tcp := packet[transportOff:]
	if len(tcp) < 20 {
		return nil
	}

	srcPort := binary.BigEndian.Uint16(tcp[0:2])
	dstPort := binary.BigEndian.Uint16(tcp[2:4])
	flags := tcp[13]

	// Check if this is destined for a virtual listener
	lk := listenerKey6{ip: dstIP, port: dstPort}
	s.mu.Lock()
	listener := s.listeners6[lk]
	if listener == nil {
		// Fallback: check wildcard listener (::)
		listener = s.listeners6[listenerKey6{port: dstPort}]
	}
	if listener != nil && (flags&0x02) != 0 { // SYN to virtual listener
		k := key6{ns: namespace, srcIP: srcIP, srcPort: srcPort, dstIP: dstIP, dstPort: dstPort}
		vc := s.virtTCP6[k]
		if vc == nil {
			seg, err := vtcp.ParseSegment(tcp)
			if err != nil {
				s.mu.Unlock()
				return err
			}
			localAddr := &net.TCPAddr{IP: net.IP(dstIP[:]), Port: int(dstPort)}
			remoteAddr := &net.TCPAddr{IP: net.IP(srcIP[:]), Port: int(srcPort)}
			vc = vtcp.NewConn(vtcp.ConnConfig{
				LocalPort:  dstPort,
				RemotePort: srcPort,
				LocalAddr:  localAddr,
				RemoteAddr: remoteAddr,
				Writer: func(tcpSeg []byte) error {
					return w(buildFrame6(gwMAC, clientMAC, dstIP, srcIP, tcpSeg))
				},
				MSS:       1440,
				Keepalive: true,
			})
			pkts := vc.AcceptSYN(seg)
			s.virtTCP6[k] = vc
			s.mu.Unlock()
			for _, pkt := range pkts {
				_ = vc.Writer()(pkt)
			}
			select {
			case listener.acceptCh <- vc:
			default:
				// Accept queue full — clean up
				vc.Abort()
				s.mu.Lock()
				delete(s.virtTCP6, k)
				s.mu.Unlock()
			}
			return nil
		}
		// Retransmitted SYN
		seg, err := vtcp.ParseSegment(tcp)
		if err != nil {
			s.mu.Unlock()
			return err
		}
		s.mu.Unlock()
		pkts := vc.HandleSegment(seg)
		for _, pkt := range pkts {
			_ = vc.Writer()(pkt)
		}
		return nil
	}

	// Check if this is for an existing virtual connection
	k := key6{ns: namespace, srcIP: srcIP, srcPort: srcPort, dstIP: dstIP, dstPort: dstPort}
	vc := s.virtTCP6[k]
	if vc != nil {
		seg, err := vtcp.ParseSegment(tcp)
		if err != nil {
			s.mu.Unlock()
			return err
		}
		s.mu.Unlock()
		pkts := vc.HandleSegment(seg)
		for _, pkt := range pkts {
			_ = vc.Writer()(pkt)
		}
		return nil
	}

	// Existing outbound NAT connection
	c := s.tcp6[k]
	if c != nil {
		seg, err := vtcp.ParseSegment(tcp)
		if err != nil {
			s.mu.Unlock()
			return err
		}
		s.mu.Unlock()
		pkts := c.vc.HandleSegment(seg)
		for _, pkt := range pkts {
			_ = c.vc.Writer()(pkt)
		}
		return nil
	}

	// Non-SYN to non-existent → RST (RFC 9293 §3.10.7.1)
	if (flags & 0x02) == 0 {
		s.mu.Unlock()
		var rstSeg *vtcp.Segment
		if (flags & 0x10) != 0 {
			// Incoming has ACK: send RST with SEQ=SEG.ACK (no ACK flag)
			segACK := binary.BigEndian.Uint32(tcp[8:12])
			rstSeg = &vtcp.Segment{SrcPort: dstPort, DstPort: srcPort, Seq: segACK, Flags: vtcp.FlagRST}
		} else {
			// No ACK: send RST+ACK with SEQ=0, ACK=SEG.SEQ+SEG.LEN
			segSEQ := binary.BigEndian.Uint32(tcp[4:8])
			dataOff := int(tcp[12]>>4) * 4
			dataLen := uint32(len(tcp) - dataOff)
			if (tcp[13] & 0x01) != 0 { // FIN flag
				dataLen++
			}
			rstSeg = &vtcp.Segment{SrcPort: dstPort, DstPort: srcPort, Seq: 0, Ack: segSEQ + dataLen, Flags: vtcp.FlagRST | vtcp.FlagACK}
		}
		pkt := buildFrame6(gwMAC, clientMAC, dstIP, srcIP, rstSeg.Marshal())
		_ = w(pkt)
		return nil
	}

	// SYN → create outbound NAT connection
	seg, err := vtcp.ParseSegment(tcp)
	if err != nil {
		s.mu.Unlock()
		return err
	}
	// Check if a dial is already in progress for this key
	if _, dup := s.pending6[k]; dup {
		s.mu.Unlock()
		return nil
	}
	s.pending6[k] = struct{}{}
	s.mu.Unlock()

	remoteAddr := "[" + net.IP(dstIP[:]).String() + "]:" + itoaU16(dstPort)
	remote, err := net.Dial("tcp", remoteAddr)

	s.mu.Lock()
	delete(s.pending6, k)
	if err != nil {
		s.mu.Unlock()
		rst := buildFrame6(gwMAC, clientMAC, dstIP, srcIP,
			(&vtcp.Segment{SrcPort: dstPort, DstPort: srcPort, Ack: seg.Seq + 1, Flags: vtcp.FlagRST | vtcp.FlagACK}).Marshal())
		_ = w(rst)
		return nil
	}
	// Another goroutine may have created the connection while we were dialing
	if s.tcp6[k] != nil {
		s.mu.Unlock()
		_ = remote.Close()
		return nil
	}

	localAddr6 := &net.TCPAddr{IP: net.IP(dstIP[:]), Port: int(dstPort)}
	remoteAddr6 := &net.TCPAddr{IP: net.IP(srcIP[:]), Port: int(srcPort)}
	vc6 := vtcp.NewConn(vtcp.ConnConfig{
		LocalPort:  dstPort,
		RemotePort: srcPort,
		LocalAddr:  localAddr6,
		RemoteAddr: remoteAddr6,
		Writer: func(tcpSeg []byte) error {
			return w(buildFrame6(gwMAC, clientMAC, dstIP, srcIP, tcpSeg))
		},
		MSS:       1440,
		Keepalive: true,
	})
	synAckPkts := vc6.AcceptSYN(seg)
	nc := &tcpNATConn{vc: vc6, remote: remote}

	s.tcp6[k] = nc
	s.mu.Unlock()

	for _, pkt := range synAckPkts {
		_ = vc6.Writer()(pkt)
	}
	nc.startBridge()
	return nil
}

func (s *Stack) handleIPv6UDP(namespace uintptr, clientMAC, gwMAC [6]byte, packet []byte, srcIP, dstIP [16]byte, transportOff int, w Writer) error {
	udp := packet[transportOff:]
	if len(udp) < 8 {
		return nil
	}

	srcPort := binary.BigEndian.Uint16(udp[0:2])
	dstPort := binary.BigEndian.Uint16(udp[2:4])

	// Create connection key
	k := key6{ns: namespace, srcIP: srcIP, srcPort: srcPort, dstIP: dstIP, dstPort: dstPort}

	s.mu.Lock()
	u := s.udp6[k]
	if u == nil {
		var err error
		u, err = newUDPConn6(srcIP, srcPort, dstIP, dstPort, clientMAC, gwMAC, w)
		if err != nil {
			s.mu.Unlock()
			return err
		}
		s.udp6[k] = u
	}
	s.mu.Unlock()
	return u.handleOutbound(packet)
}

// IPv6Checksum calculates the pseudo-header checksum for IPv6 TCP/UDP.
func IPv6Checksum(src, dst [16]byte, protocol uint8, upperLayerPacketLength uint32, data []byte) uint16 {
	var sum uint32

	// IPv6 pseudo-header:
	// Source address (128 bits)
	for i := 0; i < 16; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(src[i : i+2]))
	}

	// Destination address (128 bits)
	for i := 0; i < 16; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(dst[i : i+2]))
	}

	// Upper-Layer Packet Length (32 bits)
	sum += upperLayerPacketLength >> 16
	sum += upperLayerPacketLength & 0xFFFF

	// Next Header (protocol) (8 bits, zero-padded to 16)
	sum += uint32(protocol)

	// Actual data
	for i := 0; i+1 < len(data); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(data[i : i+2]))
	}
	if len(data)%2 == 1 {
		sum += uint32(data[len(data)-1]) << 8
	}

	// Fold 32-bit sum to 16 bits
	for (sum >> 16) != 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}

	return ^uint16(sum)
}
