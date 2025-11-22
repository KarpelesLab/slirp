package slirp

import (
	"encoding/binary"
	"net"
	"sync"
	"time"
)

type udpConn struct {
	mu        sync.Mutex
	cSrcIP    [4]byte
	cSrcPort  uint16
	rIP       [4]byte
	rPort     uint16
	clientMAC [6]byte
	gwMAC     [6]byte
	w         Writer
	conn      *net.UDPConn
	lastAct   time.Time
}

func newUDPConn(srcIP [4]byte, srcPort uint16, dstIP [4]byte, dstPort uint16, clientMAC, gwMAC [6]byte, w Writer) (*udpConn, error) {
	raddr := &net.UDPAddr{IP: net.IP(dstIP[:]), Port: int(dstPort)}
	c, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		return nil, err
	}
	u := &udpConn{
		cSrcIP: srcIP, cSrcPort: srcPort,
		rIP: dstIP, rPort: dstPort,
		clientMAC: clientMAC, gwMAC: gwMAC, w: w,
		conn:    c,
		lastAct: time.Now(),
	}
	go u.readLoop()
	return u, nil
}

func (u *udpConn) handleOutbound(ip []byte) error {
	ihl := int(ip[0]&0x0F) * 4
	udp := ip[ihl:]
	doff := 8
	if len(udp) < doff {
		return nil
	}
	payload := udp[doff:]
	if len(payload) > 0 {
		_, _ = u.conn.Write(payload)
	}
	u.mu.Lock()
	u.lastAct = time.Now()
	u.mu.Unlock()
	return nil
}

func (u *udpConn) readLoop() {
	buf := make([]byte, 2048)
	for {
		n, err := u.conn.Read(buf)
		if err != nil {
			return
		}
		if n <= 0 {
			continue
		}
		data := make([]byte, n)
		copy(data, buf[:n])
		// Build IPv4+UDP packet back to client
		ihl := 20
		uh := 8
		totalLen := ihl + uh + len(data)
		ip := make([]byte, ihl)
		ip[0] = (4 << 4) | 5
		binary.BigEndian.PutUint16(ip[2:4], uint16(totalLen))
		ip[8] = 64
		ip[9] = 17
		copy(ip[12:16], u.rIP[:])
		copy(ip[16:20], u.cSrcIP[:])
		binary.BigEndian.PutUint16(ip[10:12], 0)
		binary.BigEndian.PutUint16(ip[10:12], ipChecksum(ip))

		udp := make([]byte, uh)
		binary.BigEndian.PutUint16(udp[0:2], u.rPort)
		binary.BigEndian.PutUint16(udp[2:4], u.cSrcPort)
		binary.BigEndian.PutUint16(udp[4:6], uint16(uh+len(data)))
		binary.BigEndian.PutUint16(udp[6:8], 0)
		binary.BigEndian.PutUint16(udp[6:8], udpChecksum(ip[12:16], ip[16:20], udp, data))

		frame := make([]byte, 14+len(ip)+len(udp)+len(data))
		copy(frame[0:6], u.clientMAC[:])
		copy(frame[6:12], u.gwMAC[:])
		binary.BigEndian.PutUint16(frame[12:14], 0x0800)
		copy(frame[14:], ip)
		copy(frame[14+len(ip):], udp)
		copy(frame[14+len(ip)+len(udp):], data)
		_ = u.w(frame)
		u.mu.Lock()
		u.lastAct = time.Now()
		u.mu.Unlock()
	}
}
