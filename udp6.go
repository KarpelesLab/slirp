package slirp

import (
	"encoding/binary"
	"net"
	"sync"
	"time"
)

type udpConn6 struct {
	mu        sync.Mutex
	cSrcIP    [16]byte
	cSrcPort  uint16
	rIP       [16]byte
	rPort     uint16
	clientMAC [6]byte
	gwMAC     [6]byte
	w         Writer
	conn      *net.UDPConn
	lastAct   time.Time
}

func newUDPConn6(srcIP [16]byte, srcPort uint16, dstIP [16]byte, dstPort uint16, clientMAC, gwMAC [6]byte, w Writer) (*udpConn6, error) {
	raddr := &net.UDPAddr{IP: net.IP(dstIP[:]), Port: int(dstPort)}
	c, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		return nil, err
	}
	u := &udpConn6{
		cSrcIP: srcIP, cSrcPort: srcPort,
		rIP: dstIP, rPort: dstPort,
		clientMAC: clientMAC, gwMAC: gwMAC, w: w,
		conn:    c,
		lastAct: time.Now(),
	}
	go u.readLoop()
	return u, nil
}

func (u *udpConn6) handleOutbound(packet []byte) error {
	// IPv6 header is fixed 40 bytes, UDP starts at byte 40
	if len(packet) < 48 { // 40 byte IPv6 header + 8 byte UDP header
		return nil
	}
	udp := packet[40:]
	if len(udp) < 8 {
		return nil
	}
	payload := udp[8:]
	if len(payload) > 0 {
		_, _ = u.conn.Write(payload)
	}
	u.mu.Lock()
	u.lastAct = time.Now()
	u.mu.Unlock()
	return nil
}

func (u *udpConn6) readLoop() {
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

		// Build IPv6+UDP packet back to client
		uh := 8
		payloadLen := uh + len(data)

		// IPv6 header (40 bytes)
		ip := make([]byte, 40)
		ip[0] = 0x60 // Version 6
		binary.BigEndian.PutUint16(ip[4:6], uint16(payloadLen))
		ip[6] = 17 // Next Header: UDP
		ip[7] = 64 // Hop Limit
		copy(ip[8:24], u.rIP[:])
		copy(ip[24:40], u.cSrcIP[:])

		// UDP header
		udp := make([]byte, uh)
		binary.BigEndian.PutUint16(udp[0:2], u.rPort)
		binary.BigEndian.PutUint16(udp[2:4], u.cSrcPort)
		binary.BigEndian.PutUint16(udp[4:6], uint16(uh+len(data)))

		// Calculate UDP checksum with IPv6 pseudo-header
		var udpWithPayload []byte
		if len(data) > 0 {
			udpWithPayload = make([]byte, len(udp)+len(data))
			copy(udpWithPayload, udp)
			copy(udpWithPayload[len(udp):], data)
		} else {
			udpWithPayload = udp
		}
		binary.BigEndian.PutUint16(udp[6:8], 0)
		binary.BigEndian.PutUint16(udp[6:8], ipv6Checksum(u.rIP, u.cSrcIP, 17, uint32(len(udpWithPayload)), udpWithPayload))

		// Build Ethernet frame
		frame := make([]byte, 14+len(ip)+len(udp)+len(data))
		copy(frame[0:6], u.clientMAC[:])
		copy(frame[6:12], u.gwMAC[:])
		binary.BigEndian.PutUint16(frame[12:14], 0x86DD) // IPv6 EtherType
		copy(frame[14:], ip)
		copy(frame[14+len(ip):], udp)
		copy(frame[14+len(ip)+len(udp):], data)
		_ = u.w(frame)

		u.mu.Lock()
		u.lastAct = time.Now()
		u.mu.Unlock()
	}
}
