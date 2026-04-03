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

	_ = binary.BigEndian.Uint16(packet[4:6]) // payloadLen - not used yet
	nextHeader := packet[6]                   // This is the protocol (TCP=6, UDP=17, etc.)

	var srcIP, dstIP [16]byte
	copy(srcIP[:], packet[8:24])
	copy(dstIP[:], packet[24:40])

	// For now, we'll skip extension headers and assume nextHeader is the protocol
	// TODO: Handle IPv6 extension headers properly

	switch nextHeader {
	case 6: // TCP
		if len(packet) < 40+20 {
			return nil
		}
		return s.handleIPv6TCP(namespace, clientMAC, gwMAC, packet, srcIP, dstIP, w)

	case 17: // UDP
		if len(packet) < 40+8 {
			return nil
		}
		return s.handleIPv6UDP(namespace, clientMAC, gwMAC, packet, srcIP, dstIP, w)

	case 58: // ICMPv6
		if len(packet) < 48 {
			return nil
		}
		return s.handleICMPv6(namespace, clientMAC, gwMAC, packet, srcIP, dstIP, w)

	default:
		// Unsupported protocol
		return nil
	}
}

func (s *Stack) handleIPv6TCP(namespace uintptr, clientMAC, gwMAC [6]byte, packet []byte, srcIP, dstIP [16]byte, w Writer) error {
	// TCP header starts at byte 40
	tcp := packet[40:]
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

	// Non-SYN to non-existent → RST
	if (flags & 0x02) == 0 {
		s.mu.Unlock()
		seq := binary.BigEndian.Uint32(tcp[4:8])
		pkt := buildFrame6(gwMAC, clientMAC, dstIP, srcIP,
			(&vtcp.Segment{SrcPort: dstPort, DstPort: srcPort, Ack: seq + 1, Flags: vtcp.FlagRST | vtcp.FlagACK}).Marshal())
		_ = w(pkt)
		return nil
	}

	// SYN → create outbound NAT connection
	seg, err := vtcp.ParseSegment(tcp)
	if err != nil {
		s.mu.Unlock()
		return err
	}
	s.mu.Unlock()

	remoteAddr := "[" + net.IP(dstIP[:]).String() + "]:" + itoaU16(dstPort)
	remote, err := net.Dial("tcp", remoteAddr)
	if err != nil {
		rst := buildFrame6(gwMAC, clientMAC, dstIP, srcIP,
			(&vtcp.Segment{SrcPort: dstPort, DstPort: srcPort, Ack: seg.Seq + 1, Flags: vtcp.FlagRST | vtcp.FlagACK}).Marshal())
		_ = w(rst)
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

	s.mu.Lock()
	s.tcp6[k] = nc
	s.mu.Unlock()

	for _, pkt := range synAckPkts {
		_ = vc6.Writer()(pkt)
	}
	nc.startBridge()
	return nil
}

func (s *Stack) handleIPv6UDP(namespace uintptr, clientMAC, gwMAC [6]byte, packet []byte, srcIP, dstIP [16]byte, w Writer) error {
	// UDP header starts at byte 40
	udp := packet[40:]
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
