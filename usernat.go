package slirp

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"sync"
	"time"
)

// Writer is the callback used to emit full Ethernet frames back to the client.
type Writer func([]byte) error

type key struct {
	ns      uintptr
	srcIP   [4]byte
	srcPort uint16
	dstIP   [4]byte
	dstPort uint16
}

type Stack struct {
	mu        sync.RWMutex
	tcp       map[key]*tcpConn
	udp       map[key]*udpConn
	listeners map[listenerKey]*Listener
	virtTCP   map[key]*VirtualConn
}

func New() *Stack {
	s := &Stack{
		tcp:       make(map[key]*tcpConn),
		udp:       make(map[key]*udpConn),
		listeners: make(map[listenerKey]*Listener),
		virtTCP:   make(map[key]*VirtualConn),
	}
	go s.maintenance()
	return s
}

// HandlePacket processes an IP packet (starting at IP header).
// This handles traffic in both directions - there is no separate "inbound" handler.
// Currently supports IPv4; IPv6 support can be added in the future.
//
// Parameters:
//   - namespace: Identifier for connection isolation (use 0 for single namespace)
//   - clientMAC: MAC address of the endpoint that sent this packet (used as destination in responses)
//   - gwMAC: MAC address for this slirp instance (used as source in responses)
//   - packet: Raw IP packet data (must start at IP header, not Ethernet header)
//   - w: Writer callback for sending Ethernet frames back to the endpoint
func (s *Stack) HandlePacket(namespace uintptr, clientMAC [6]byte, gwMAC [6]byte, packet []byte, w Writer) error {
	if len(packet) < 20 {
		return errors.New("packet too short")
	}

	// Check IP version
	version := packet[0] >> 4
	switch version {
	case 4:
		return s.handleIPv4(namespace, clientMAC, gwMAC, packet, w)
	case 6:
		return errors.New("IPv6 not yet supported")
	default:
		return errors.New("unsupported IP version")
	}
}

func (s *Stack) handleIPv4(namespace uintptr, clientMAC [6]byte, gwMAC [6]byte, ip []byte, w Writer) error {
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
		if listener != nil && (flags&0x02) != 0 { // SYN to virtual listener
			// Create virtual connection
			k := key{ns: namespace, srcIP: srcIP, srcPort: srcPort, dstIP: dstIP, dstPort: dstPort}
			vc := s.virtTCP[k]
			if vc == nil {
				vc = newVirtualConn(dstIP, dstPort, srcIP, srcPort, clientMAC, gwMAC, w)
				vc.clientSeq = binary.BigEndian.Uint32(tcp[4:8]) + 1
				vc.ack = vc.clientSeq
				s.virtTCP[k] = vc

				// Send SYN-ACK
				pkt := buildTCPPacket(gwMAC, clientMAC, dstIP, srcIP, dstPort, srcPort, vc.seq, vc.ack, 0x12, nil)
				s.mu.Unlock()
				_ = w(pkt)

				// Queue connection for Accept()
				select {
				case listener.acceptCh <- vc:
				default:
					// Accept queue full, drop connection
				}
				return nil
			}
		}

		// Check if this is for an existing virtual connection
		k := key{ns: namespace, srcIP: srcIP, srcPort: srcPort, dstIP: dstIP, dstPort: dstPort}
		vc := s.virtTCP[k]
		if vc != nil {
			s.mu.Unlock()
			return vc.handleInbound(ip)
		}

		// Otherwise, create outbound connection
		c := s.tcp[k]
		if c == nil {
			c = newTCPConn(srcIP, srcPort, dstIP, dstPort, clientMAC, gwMAC, w)
			s.tcp[k] = c
		}
		s.mu.Unlock()
		return c.handleOutbound(ip)
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
			u, err = newUDPConn(srcIP, srcPort, dstIP, dstPort, clientMAC, gwMAC, w)
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
	for range ticker.C {
		now := time.Now()
		s.mu.Lock()
		// TCP cleanup
		for k, c := range s.tcp {
			c.mu.Lock()
			idle := now.Sub(c.lastAct)
			closed := c.closed
			if idle > 2*time.Minute || closed {
				if c.conn != nil {
					_ = c.conn.Close()
				}
				delete(s.tcp, k)
			}
			c.mu.Unlock()
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
		// Virtual TCP cleanup
		for k, vc := range s.virtTCP {
			vc.mu.Lock()
			idle := now.Sub(vc.lastAct)
			closed := vc.closed
			if idle > 2*time.Minute || closed {
				_ = vc.Close()
				delete(s.virtTCP, k)
			}
			vc.mu.Unlock()
		}
		s.mu.Unlock()
	}
}

// Utilities shared by TCP/UDP
func ipChecksum(hdr []byte) uint16 {
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

func tcpChecksum(src, dst []byte, tcp []byte, payload []byte) uint16 {
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

func udpChecksum(src, dst []byte, udp []byte, payload []byte) uint16 {
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

func randUint32() uint32 {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return uint32(time.Now().UnixNano())
	}
	return binary.BigEndian.Uint32(b[:])
}
