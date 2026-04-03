package slirp

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/KarpelesLab/slirp/vtcp"
)

// Writer is the callback used to emit raw IP packets back to the client.
type Writer func([]byte) error

type key struct {
	ns      uintptr
	srcIP   [4]byte
	srcPort uint16
	dstIP   [4]byte
	dstPort uint16
}

type Stack struct {
	mu         sync.RWMutex
	tcp        map[key]*tcpNATConn
	udp        map[key]*udpConn
	tcp6       map[key6]*tcpNATConn
	udp6       map[key6]*udpConn6
	listeners  map[listenerKey]*Listener
	listeners6 map[listenerKey6]*Listener6
	virtTCP    map[key]*vtcp.Conn
	virtTCP6   map[key6]*vtcp.Conn
	pending    map[key]struct{}
	pending6   map[key6]struct{}
	done       chan struct{}
	closeOnce  sync.Once
}

func New() *Stack {
	s := &Stack{
		tcp:        make(map[key]*tcpNATConn),
		udp:        make(map[key]*udpConn),
		tcp6:       make(map[key6]*tcpNATConn),
		udp6:       make(map[key6]*udpConn6),
		listeners:  make(map[listenerKey]*Listener),
		listeners6: make(map[listenerKey6]*Listener6),
		virtTCP:    make(map[key]*vtcp.Conn),
		virtTCP6:   make(map[key6]*vtcp.Conn),
		pending:    make(map[key]struct{}),
		pending6:   make(map[key6]struct{}),
		done:       make(chan struct{}),
	}
	go s.maintenance()
	return s
}

// Close shuts down the stack, stopping the maintenance goroutine and
// closing all active connections.
func (s *Stack) Close() error {
	s.closeOnce.Do(func() { close(s.done) })

	s.mu.Lock()
	defer s.mu.Unlock()

	// Close all TCP connections
	for k, c := range s.tcp {
		c.close()
		delete(s.tcp, k)
	}
	// Close all TCP6 connections
	for k, c := range s.tcp6 {
		c.close()
		delete(s.tcp6, k)
	}
	// Close all UDP connections
	for k, u := range s.udp {
		u.mu.Lock()
		if u.conn != nil {
			_ = u.conn.Close()
		}
		u.mu.Unlock()
		delete(s.udp, k)
	}
	// Close all UDP6 connections
	for k, u := range s.udp6 {
		u.mu.Lock()
		if u.conn != nil {
			_ = u.conn.Close()
		}
		u.mu.Unlock()
		delete(s.udp6, k)
	}
	// Close all virtual TCP connections
	for k, vc := range s.virtTCP {
		vc.Abort()
		delete(s.virtTCP, k)
	}
	// Close all virtual TCP6 connections
	for k, vc := range s.virtTCP6 {
		vc.Abort()
		delete(s.virtTCP6, k)
	}
	// Close all listeners
	for k, l := range s.listeners {
		l.closeOnce.Do(func() { close(l.closeCh) })
		delete(s.listeners, k)
	}
	for k, l := range s.listeners6 {
		l.closeOnce.Do(func() { close(l.closeCh) })
		delete(s.listeners6, k)
	}

	return nil
}

// HandlePacket processes an IP packet (starting at IP header).
// This handles traffic in both directions - there is no separate "inbound" handler.
// Supports both IPv4 and IPv6 packets with TCP and UDP protocols.
//
// Parameters:
//   - namespace: Identifier for connection isolation (use 0 for single namespace)
//   - packet: Raw IP packet data (must start at IP header)
//   - w: Writer callback for sending raw IP packets back to the endpoint
func (s *Stack) HandlePacket(namespace uintptr, packet []byte, w Writer) error {
	if len(packet) < 20 {
		return errors.New("packet too short")
	}

	// Check IP version
	version := packet[0] >> 4
	switch version {
	case 4:
		return s.handleIPv4(namespace, packet, w)
	case 6:
		return s.handleIPv6(namespace, packet, w)
	default:
		return errors.New("unsupported IP version")
	}
}

func (s *Stack) handleIPv4(namespace uintptr, ip []byte, w Writer) error {
	if len(ip) < 20 {
		return errors.New("IPv4 packet too short")
	}
	ihl := int(ip[0]&0x0F) * 4
	if len(ip) < ihl {
		return errors.New("invalid ihl")
	}
	proto := ip[9]
	var srcIP, dstIP [4]byte
	copy(srcIP[:], ip[12:16])
	copy(dstIP[:], ip[16:20])

	switch proto {
	case 6: // TCP
		if len(ip) < ihl+20 {
			return nil
		}
		tcp := ip[ihl:]
		srcPort := binary.BigEndian.Uint16(tcp[0:2])
		dstPort := binary.BigEndian.Uint16(tcp[2:4])
		flags := tcp[13]

		// Check if this is destined for a virtual listener
		lk := listenerKey{ip: dstIP, port: dstPort}
		s.mu.Lock()
		listener := s.listeners[lk]
		if listener == nil {
			// Fallback: check wildcard listener (0.0.0.0)
			listener = s.listeners[listenerKey{port: dstPort}]
		}
		if listener != nil && (flags&0x02) != 0 { // SYN to virtual listener
			k := key{ns: namespace, srcIP: srcIP, srcPort: srcPort, dstIP: dstIP, dstPort: dstPort}
			vc := s.virtTCP[k]
			if vc == nil {
				// Parse the TCP segment and create a vtcp.Conn
				seg, err := vtcp.ParseSegment(tcp)
				if err != nil {
					s.mu.Unlock()
					return err
				}
				localAddr := &net.TCPAddr{IP: net.IP(dstIP[:]).To4(), Port: int(dstPort)}
				remoteAddr := &net.TCPAddr{IP: net.IP(srcIP[:]).To4(), Port: int(srcPort)}
				vc = vtcp.NewConn(vtcp.ConnConfig{
					LocalPort:  dstPort,
					RemotePort: srcPort,
					LocalAddr:  localAddr,
					RemoteAddr: remoteAddr,
					Writer: func(tcpSeg []byte) error {
						return w(buildPacket4(dstIP, srcIP, tcpSeg))
					},
					MSS:       1460,
					Keepalive: true,
				})
				pkts := vc.AcceptSYN(seg)
				s.virtTCP[k] = vc
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
					delete(s.virtTCP, k)
					s.mu.Unlock()
				}
				return nil
			}
			// Retransmitted SYN — HandleSegment will respond with SYN-ACK
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
		k := key{ns: namespace, srcIP: srcIP, srcPort: srcPort, dstIP: dstIP, dstPort: dstPort}
		vc := s.virtTCP[k]
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
		c := s.tcp[k]
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

		// Non-SYN to non-existent connection → RST (RFC 9293 §3.10.7.1)
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
			pkt := buildPacket4(dstIP, srcIP, rstSeg.Marshal())
			_ = w(pkt)
			return nil
		}

		// SYN → create new outbound NAT connection
		seg, err := vtcp.ParseSegment(tcp)
		if err != nil {
			s.mu.Unlock()
			return err
		}
		// Check if a dial is already in progress for this key
		if _, dup := s.pending[k]; dup {
			s.mu.Unlock()
			return nil
		}
		s.pending[k] = struct{}{}
		s.mu.Unlock()

		// Dial remote outside any lock
		remoteAddr := net.IP(dstIP[:]).String() + ":" + itoaU16(dstPort)
		remote, err := net.Dial("tcp", remoteAddr)

		s.mu.Lock()
		delete(s.pending, k)
		if err != nil {
			s.mu.Unlock()
			// Send RST to client
			rst := buildPacket4(dstIP, srcIP,
				(&vtcp.Segment{SrcPort: dstPort, DstPort: srcPort, Ack: seg.Seq + 1, Flags: vtcp.FlagRST | vtcp.FlagACK}).Marshal())
			_ = w(rst)
			return nil
		}
		// Another goroutine may have created the connection while we were dialing
		if s.tcp[k] != nil {
			s.mu.Unlock()
			_ = remote.Close()
			return nil
		}

		localAddr := &net.TCPAddr{IP: net.IP(dstIP[:]).To4(), Port: int(dstPort)}
		remoteClientAddr := &net.TCPAddr{IP: net.IP(srcIP[:]).To4(), Port: int(srcPort)}
		natVC := vtcp.NewConn(vtcp.ConnConfig{
			LocalPort:  dstPort,
			RemotePort: srcPort,
			LocalAddr:  localAddr,
			RemoteAddr: remoteClientAddr,
			Writer: func(tcpSeg []byte) error {
				return w(buildPacket4(dstIP, srcIP, tcpSeg))
			},
			MSS:       1460,
			Keepalive: true,
		})
		synAckPkts := natVC.AcceptSYN(seg)
		nc := &tcpNATConn{vc: natVC, remote: remote}

		s.tcp[k] = nc
		s.mu.Unlock()

		// Send SYN-ACK
		for _, pkt := range synAckPkts {
			_ = natVC.Writer()(pkt)
		}

		// Start bidirectional bridge
		nc.startBridge()
		return nil
	case 17: // UDP
		if len(ip) < ihl+8 {
			return nil
		}
		udp := ip[ihl:]
		srcPort := binary.BigEndian.Uint16(udp[0:2])
		dstPort := binary.BigEndian.Uint16(udp[2:4])
		k := key{ns: namespace, srcIP: srcIP, srcPort: srcPort, dstIP: dstIP, dstPort: dstPort}
		s.mu.Lock()
		u := s.udp[k]
		if u == nil {
			var err error
			u, err = newUDPConn(srcIP, srcPort, dstIP, dstPort, w)
			if err != nil {
				s.mu.Unlock()
				return err
			}
			s.udp[k] = u
		}
		s.mu.Unlock()
		return u.handleOutbound(ip)
	default:
		// ignore other protocols
		return nil
	}
}

func (s *Stack) maintenance() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-s.done:
			return
		case <-ticker.C:
		}
		now := time.Now()
		s.mu.Lock()
		// TCP cleanup: only remove StateClosed; TIME_WAIT connections stay
		// until vtcp's own timer transitions them to Closed.
		for k, c := range s.tcp {
			if c.vc.State() == vtcp.StateClosed {
				c.close()
				delete(s.tcp, k)
			}
		}
		// TCP6 cleanup
		for k, c := range s.tcp6 {
			if c.vc.State() == vtcp.StateClosed {
				c.close()
				delete(s.tcp6, k)
			}
		}
		// UDP cleanup
		for k, u := range s.udp {
			u.mu.Lock()
			idle := now.Sub(u.lastAct)
			if idle > 60*time.Second {
				if u.conn != nil {
					_ = u.conn.Close()
				}
				delete(s.udp, k)
			}
			u.mu.Unlock()
		}
		// UDP6 cleanup
		for k, u := range s.udp6 {
			u.mu.Lock()
			idle := now.Sub(u.lastAct)
			if idle > 60*time.Second {
				if u.conn != nil {
					_ = u.conn.Close()
				}
				delete(s.udp6, k)
			}
			u.mu.Unlock()
		}
		// Virtual TCP cleanup
		for k, vc := range s.virtTCP {
			if vc.State() == vtcp.StateClosed {
				delete(s.virtTCP, k)
			}
		}
		// Virtual TCP6 cleanup
		for k, vc := range s.virtTCP6 {
			if vc.State() == vtcp.StateClosed {
				delete(s.virtTCP6, k)
			}
		}
		s.mu.Unlock()
	}
}

// Utilities shared by TCP/UDP
// IPChecksum computes the Internet checksum (RFC 1071) over the given header bytes.
func IPChecksum(hdr []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(hdr); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(hdr[i : i+2]))
	}
	if len(hdr)%2 == 1 {
		sum += uint32(hdr[len(hdr)-1]) << 8
	}
	for (sum >> 16) != 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return ^uint16(sum)
}

// TCPChecksum computes the TCP checksum including the IPv4 pseudo-header.
func TCPChecksum(src, dst []byte, tcp []byte, payload []byte) uint16 {
	var sum uint32
	sum += uint32(binary.BigEndian.Uint16(src[0:2]))
	sum += uint32(binary.BigEndian.Uint16(src[2:4]))
	sum += uint32(binary.BigEndian.Uint16(dst[0:2]))
	sum += uint32(binary.BigEndian.Uint16(dst[2:4]))
	sum += uint32(6)
	sum += uint32(len(tcp) + len(payload))
	for i := 0; i+1 < len(tcp); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(tcp[i : i+2]))
	}
	if len(tcp)%2 == 1 {
		sum += uint32(tcp[len(tcp)-1]) << 8
	}
	for i := 0; i+1 < len(payload); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(payload[i : i+2]))
	}
	if len(payload)%2 == 1 {
		sum += uint32(payload[len(payload)-1]) << 8
	}
	for (sum >> 16) != 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return ^uint16(sum)
}

// UDPChecksum computes the UDP checksum including the IPv4 pseudo-header.
func UDPChecksum(src, dst []byte, udp []byte, payload []byte) uint16 {
	var sum uint32
	sum += uint32(binary.BigEndian.Uint16(src[0:2]))
	sum += uint32(binary.BigEndian.Uint16(src[2:4]))
	sum += uint32(binary.BigEndian.Uint16(dst[0:2]))
	sum += uint32(binary.BigEndian.Uint16(dst[2:4]))
	sum += uint32(17)
	sum += uint32(len(udp) + len(payload))
	for i := 0; i+1 < len(udp); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(udp[i : i+2]))
	}
	if len(udp)%2 == 1 {
		sum += uint32(udp[len(udp)-1]) << 8
	}
	for i := 0; i+1 < len(payload); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(payload[i : i+2]))
	}
	if len(payload)%2 == 1 {
		sum += uint32(payload[len(payload)-1]) << 8
	}
	for (sum >> 16) != 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return ^uint16(sum)
}

// SeqAfter reports whether TCP sequence number a is after b,
// handling 32-bit wraparound via signed comparison.
func SeqAfter(a, b uint32) bool {
	return int32(a-b) > 0
}

func itoaU16(v uint16) string {
	if v == 0 {
		return "0"
	}
	var b [8]byte
	i := len(b)
	for v > 0 {
		i--
		b[i] = byte('0' + v%10)
		v /= 10
	}
	return string(b[i:])
}

// RandUint32 returns a cryptographically random uint32.
func RandUint32() uint32 {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return uint32(time.Now().UnixNano())
	}
	return binary.BigEndian.Uint32(b[:])
}
