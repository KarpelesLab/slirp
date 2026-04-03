package vclient

import (
	"encoding/binary"
	"net"
	"time"

	"github.com/KarpelesLab/slirp"
	"github.com/KarpelesLab/slirp/vtcp"
)

// TCPConn is a virtual TCP connection implementing net.Conn.
// It wraps a vtcp.Conn and handles registration/unregistration
// with the parent Client.
type TCPConn struct {
	vc *vtcp.Conn
	c  *Client
	k  connKey
}

func (tc *TCPConn) Read(b []byte) (int, error)  { return tc.vc.Read(b) }
func (tc *TCPConn) Write(b []byte) (int, error) { return tc.vc.Write(b) }

func (tc *TCPConn) Close() error {
	err := tc.vc.Close()
	tc.c.tcpMu.Lock()
	delete(tc.c.tcpConns, tc.k)
	tc.c.tcpMu.Unlock()
	return err
}

func (tc *TCPConn) LocalAddr() net.Addr                { return tc.vc.LocalAddr() }
func (tc *TCPConn) RemoteAddr() net.Addr               { return tc.vc.RemoteAddr() }
func (tc *TCPConn) SetDeadline(t time.Time) error      { return tc.vc.SetDeadline(t) }
func (tc *TCPConn) SetReadDeadline(t time.Time) error  { return tc.vc.SetReadDeadline(t) }
func (tc *TCPConn) SetWriteDeadline(t time.Time) error { return tc.vc.SetWriteDeadline(t) }

func (tc *TCPConn) abort() {
	tc.vc.Abort()
}

// handleTCP dispatches incoming TCP segments to the appropriate connection.
func (c *Client) handleTCP(ip []byte, ihl int) error {
	tcp := ip[ihl:]
	if len(tcp) < 20 {
		return nil
	}
	srcPort := binary.BigEndian.Uint16(tcp[0:2])
	dstPort := binary.BigEndian.Uint16(tcp[2:4])
	var srcIP, dstIP [4]byte
	copy(srcIP[:], ip[12:16])
	copy(dstIP[:], ip[16:20])

	k := connKey{localPort: dstPort, remoteIP: srcIP, remotePort: srcPort}
	c.tcpMu.Lock()
	conn := c.tcpConns[k]
	c.tcpMu.Unlock()

	if conn != nil {
		seg, err := vtcp.ParseSegment(tcp)
		if err != nil {
			return nil
		}
		pkts := conn.vc.HandleSegment(seg)
		for _, pkt := range pkts {
			_ = conn.vc.Writer()(pkt)
		}
		return nil
	}

	// No existing connection — check for pure SYN to a listener
	flags := tcp[13]
	if flags&(vtcp.FlagSYN|vtcp.FlagACK) != vtcp.FlagSYN {
		return nil // not a pure SYN (reject SYN+ACK and non-SYN), drop
	}

	c.listenerMu.Lock()
	l := c.listeners[dstPort]
	c.listenerMu.Unlock()
	if l == nil {
		return nil // no listener on this port
	}

	seg, err := vtcp.ParseSegment(tcp)
	if err != nil {
		return nil
	}

	// Create a new vtcp.Conn for this incoming connection
	localAddr := &net.TCPAddr{IP: net.IP(dstIP[:]).To4(), Port: int(dstPort)}
	remoteAddr := &net.TCPAddr{IP: net.IP(srcIP[:]).To4(), Port: int(srcPort)}

	vc := vtcp.NewConn(vtcp.ConnConfig{
		LocalPort:  dstPort,
		RemotePort: srcPort,
		LocalAddr:  localAddr,
		RemoteAddr: remoteAddr,
		Writer: func(tcpSeg []byte) error {
			return c.sendPacket(buildIPv4Packet(dstIP, srcIP, tcpSeg))
		},
		MSS:       1460,
		Keepalive: true,
	})

	synAckPkts := vc.AcceptSYN(seg)
	tc := &TCPConn{vc: vc, c: c, k: k}

	c.tcpMu.Lock()
	c.tcpConns[k] = tc
	c.tcpMu.Unlock()

	// Send SYN-ACK
	for _, pkt := range synAckPkts {
		_ = vc.Writer()(pkt)
	}

	// Queue for Accept()
	select {
	case l.acceptCh <- tc:
	default:
		// Accept queue full — abort the connection and remove from map
		tc.vc.Abort()
		c.tcpMu.Lock()
		delete(c.tcpConns, k)
		c.tcpMu.Unlock()
	}

	return nil
}

// buildIPv4Packet builds an IPv4 packet containing a raw TCP segment.
func buildIPv4Packet(srcIP, dstIP [4]byte, tcpSeg []byte) []byte {
	ipHdr := make([]byte, 20)
	totalLen := 20 + len(tcpSeg)
	ipHdr[0] = 0x45
	binary.BigEndian.PutUint16(ipHdr[2:4], uint16(totalLen))
	ipHdr[8] = 64
	ipHdr[9] = 6 // TCP
	copy(ipHdr[12:16], srcIP[:])
	copy(ipHdr[16:20], dstIP[:])
	binary.BigEndian.PutUint16(ipHdr[10:12], 0)
	binary.BigEndian.PutUint16(ipHdr[10:12], slirp.IPChecksum(ipHdr))

	// Compute TCP checksum
	tcpCopy := make([]byte, len(tcpSeg))
	copy(tcpCopy, tcpSeg)
	if len(tcpCopy) >= 18 {
		binary.BigEndian.PutUint16(tcpCopy[16:18], 0)
		doff := int(tcpCopy[12]>>4) * 4
		if doff > 0 && doff <= len(tcpCopy) {
			hdr := tcpCopy[:doff]
			payload := tcpCopy[doff:]
			cs := slirp.TCPChecksum(ipHdr[12:16], ipHdr[16:20], hdr, payload)
			binary.BigEndian.PutUint16(tcpCopy[16:18], cs)
		}
	}

	pkt := make([]byte, len(ipHdr)+len(tcpCopy))
	copy(pkt, ipHdr)
	copy(pkt[len(ipHdr):], tcpCopy)
	return pkt
}
