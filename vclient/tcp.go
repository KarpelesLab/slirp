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

func (tc *TCPConn) LocalAddr() net.Addr             { return tc.vc.LocalAddr() }
func (tc *TCPConn) RemoteAddr() net.Addr            { return tc.vc.RemoteAddr() }
func (tc *TCPConn) SetDeadline(t time.Time) error     { return tc.vc.SetDeadline(t) }
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

	k := connKey{localPort: dstPort, remoteIP: [4]byte(ip[12:16]), remotePort: srcPort}
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
