package slirp

import (
	"encoding/binary"
	"io"
	"log"
	"net"
	"sync"
	"time"
)

type tcpConn6 struct {
	mu sync.Mutex

	// client side
	cSrcIP   [16]byte
	cSrcPort uint16
	cSeq     uint32 // next expected client seq
	sAck     uint32 // what we acknowledge back to client
	recvWnd  uint16 // client's advertised receive window

	// server side (remote)
	rIP        [16]byte
	rPort      uint16
	sSeq       uint32 // our (server) seq next to send
	sUnacked   uint32 // bytes sent to client not yet acked
	sendQ      []byte // pending data to send
	finPending bool   // remote closed, send FIN when drained
	mss        int    // simple MSS

	clientMAC [6]byte
	gwMAC     [6]byte
	w         Writer

	conn        net.Conn
	established bool
	lastAct     time.Time
	closed      bool
	cond        *sync.Cond
}

func newTCPConn6(srcIP [16]byte, srcPort uint16, dstIP [16]byte, dstPort uint16, clientMAC, gwMAC [6]byte, w Writer) *tcpConn6 {
	t := &tcpConn6{
		cSrcIP:    srcIP,
		cSrcPort:  srcPort,
		rIP:       dstIP,
		rPort:     dstPort,
		clientMAC: clientMAC,
		gwMAC:     gwMAC,
		w:         w,
		mss:       1440, // Slightly smaller for IPv6 due to larger header
		lastAct:   time.Now(),
	}
	t.cond = sync.NewCond(&t.mu)
	return t
}

func (t *tcpConn6) handleOutbound(packet []byte) error {
	// IPv6 header is fixed 40 bytes, TCP starts at byte 40
	if len(packet) < 40 {
		return nil
	}
	tcp := packet[40:]
	if len(tcp) < 20 {
		return nil
	}

	doff := int((tcp[12]>>4)&0x0F) * 4
	if len(tcp) < doff {
		return nil
	}
	flags := tcp[13]
	seq := binary.BigEndian.Uint32(tcp[4:8])
	ack := binary.BigEndian.Uint32(tcp[8:12])
	payload := tcp[doff:]
	wnd := binary.BigEndian.Uint16(tcp[14:16])

	t.mu.Lock()
	defer t.mu.Unlock()
	t.lastAct = time.Now()
	if wnd != 0 {
		t.recvWnd = wnd
	}

	if t.conn == nil && (flags&0x02) != 0 { // SYN
		// initiate remote conn - net.IP handles both IPv4 and IPv6
		c, err := net.Dial("tcp", "["+net.IP(t.rIP[:]).String()+"]:"+itoaU16(t.rPort))
		if err != nil {
			log.Printf("usernat tcp6 dial failed: %v", err)
			return nil
		}
		t.conn = c
		t.cSeq = seq + 1
		t.sSeq = randUint32()
		t.sAck = t.cSeq
		// parse MSS option if present in SYN
		if doff > 20 {
			opts := tcp[20:doff]
			for i := 0; i < len(opts); {
				kind := opts[i]
				if kind == 0 {
					break
				}
				if kind == 1 {
					i++
					continue
				}
				if i+1 >= len(opts) {
					break
				}
				l := int(opts[i+1])
				if l < 2 || i+l > len(opts) {
					break
				}
				if kind == 2 && l == 4 {
					mss := binary.BigEndian.Uint16(opts[i+2 : i+4])
					if int(mss) < t.mss {
						t.mss = int(mss)
					}
				}
				i += l
			}
		}
		// send SYN-ACK
		pkt := buildTCPPacket6(t.gwMAC, t.clientMAC, t.rIP, t.cSrcIP, t.rPort, t.cSrcPort, t.sSeq, t.sAck, 0x12, nil)
		_ = t.w(pkt)
		// reader goroutine
		go t.readFromRemote()
		go t.maintenanceLoop()
		return nil
	}

	// ACK to complete handshake
	if t.conn != nil && !t.established && (flags&0x10) != 0 && ack == t.sSeq+1 {
		t.established = true
		t.sSeq += 1 // SYN consumed
		return nil
	}

	if t.conn != nil && len(payload) > 0 {
		// accept in-sequence data only
		if seq == t.cSeq {
			// write to remote
			_, _ = t.conn.Write(payload)
			t.cSeq += uint32(len(payload))
			// send ACK back
			pkt := buildTCPPacket6(t.gwMAC, t.clientMAC, t.rIP, t.cSrcIP, t.rPort, t.cSrcPort, t.sSeq, t.cSeq, 0x10, nil)
			_ = t.w(pkt)
			t.cond.Broadcast()
		}
		return nil
	}

	// Pure ACKs: advance unacked and flush queued data
	if (flags&0x10) != 0 && len(payload) == 0 {
		if ack > t.sAck {
			adv := ack - t.sAck
			if adv <= t.sUnacked {
				t.sUnacked -= adv
			} else {
				t.sUnacked = 0
			}
			t.sAck = ack
			t.flushSendQ()
			if t.finPending && len(t.sendQ) == 0 && t.sUnacked == 0 {
				pkt := buildTCPPacket6(t.gwMAC, t.clientMAC, t.rIP, t.cSrcIP, t.rPort, t.cSrcPort, t.sSeq, t.cSeq, 0x11, nil)
				_ = t.w(pkt)
				t.finPending = false
			}
		}
		return nil
	}

	// FIN
	if (flags & 0x01) != 0 {
		t.cSeq += 1
		if t.conn != nil {
			_ = t.conn.Close()
		}
		// send FIN-ACK
		pkt := buildTCPPacket6(t.gwMAC, t.clientMAC, t.rIP, t.cSrcIP, t.rPort, t.cSrcPort, t.sSeq, t.cSeq, 0x11, nil)
		_ = t.w(pkt)
		t.closed = true
		return nil
	}

	return nil
}

func (t *tcpConn6) readFromRemote() {
	buf := make([]byte, 4096)
	for {
		n, err := t.conn.Read(buf)
		if err != nil {
			if err != io.EOF {
				log.Printf("usernat tcp6 read: %v", err)
			}
			t.mu.Lock()
			if len(t.sendQ) == 0 && t.sUnacked == 0 {
				pkt := buildTCPPacket6(t.gwMAC, t.clientMAC, t.rIP, t.cSrcIP, t.rPort, t.cSrcPort, t.sSeq, t.cSeq, 0x11, nil)
				t.mu.Unlock()
				_ = t.w(pkt)
				return
			}
			t.finPending = true
			t.mu.Unlock()
			return
		}
		if n > 0 {
			t.mu.Lock()
			const maxBuf = 1 << 20
			for len(t.sendQ) >= maxBuf {
				t.cond.Wait()
			}
			t.sendQ = append(t.sendQ, buf[:n]...)
			t.flushSendQ()
			t.lastAct = time.Now()
			t.mu.Unlock()
		}
	}
}

func (t *tcpConn6) flushSendQ() {
	avail := int(t.recvWnd) - int(t.sUnacked)
	if avail <= 0 {
		return
	}
	for avail > 0 && len(t.sendQ) > 0 {
		seg := t.sendQ
		if len(seg) > t.mss {
			seg = seg[:t.mss]
		}
		if len(seg) > avail {
			seg = seg[:avail]
		}
		pkt := buildTCPPacket6(t.gwMAC, t.clientMAC, t.rIP, t.cSrcIP, t.rPort, t.cSrcPort, t.sSeq, t.cSeq, 0x18, seg)
		_ = t.w(pkt)
		t.sSeq += uint32(len(seg))
		t.sUnacked += uint32(len(seg))
		t.sendQ = t.sendQ[len(seg):]
		avail -= len(seg)
	}
	t.cond.Broadcast()
}

func (t *tcpConn6) maintenanceLoop() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		t.mu.Lock()
		if t.closed {
			t.mu.Unlock()
			return
		}
		if (len(t.sendQ) > 0 || t.sUnacked > 0) && (int(t.recvWnd)-int(t.sUnacked) <= 0) {
			pkt := buildTCPPacket6(t.gwMAC, t.clientMAC, t.rIP, t.cSrcIP, t.rPort, t.cSrcPort, t.sSeq-1, t.cSeq, 0x10, nil)
			_ = t.w(pkt)
		}
		t.mu.Unlock()
	}
}

func buildTCPPacket6(srcMAC, dstMAC [6]byte, srcIP, dstIP [16]byte, srcPort, dstPort uint16, seq, ack uint32, flags uint8, payload []byte) []byte {
	// IPv6 header (40 bytes)
	thl := 20
	payloadLen := thl + len(payload)
	ip := make([]byte, 40)

	// Version (4 bits) = 6, Traffic Class (8 bits) = 0, Flow Label (20 bits) = 0
	ip[0] = 0x60

	// Payload Length (16 bits)
	binary.BigEndian.PutUint16(ip[4:6], uint16(payloadLen))

	// Next Header (8 bits) = TCP (6)
	ip[6] = 6

	// Hop Limit (8 bits) = 64
	ip[7] = 64

	// Source Address (128 bits)
	copy(ip[8:24], srcIP[:])

	// Destination Address (128 bits)
	copy(ip[24:40], dstIP[:])

	// TCP header
	tcp := make([]byte, thl)
	binary.BigEndian.PutUint16(tcp[0:2], srcPort)
	binary.BigEndian.PutUint16(tcp[2:4], dstPort)
	binary.BigEndian.PutUint32(tcp[4:8], seq)
	binary.BigEndian.PutUint32(tcp[8:12], ack)
	tcp[12] = (5 << 4)
	tcp[13] = flags
	binary.BigEndian.PutUint16(tcp[14:16], 65535)

	// Calculate TCP checksum with IPv6 pseudo-header
	var tcpWithPayload []byte
	if len(payload) > 0 {
		tcpWithPayload = make([]byte, len(tcp)+len(payload))
		copy(tcpWithPayload, tcp)
		copy(tcpWithPayload[len(tcp):], payload)
	} else {
		tcpWithPayload = tcp
	}
	binary.BigEndian.PutUint16(tcp[16:18], 0)
	binary.BigEndian.PutUint16(tcp[16:18], ipv6Checksum(srcIP, dstIP, 6, uint32(len(tcpWithPayload)), tcpWithPayload))

	// Build Ethernet frame
	frame := make([]byte, 14+len(ip)+len(tcp)+len(payload))
	copy(frame[0:6], dstMAC[:])
	copy(frame[6:12], srcMAC[:])
	binary.BigEndian.PutUint16(frame[12:14], 0x86DD) // IPv6 EtherType
	copy(frame[14:], ip)
	copy(frame[14+len(ip):], tcp)
	copy(frame[14+len(ip)+len(tcp):], payload)
	return frame
}
