package slirp

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

type listenerKey6 struct {
	ip   [16]byte
	port uint16
}

// Listener6 is a virtual network listener for IPv6 TCP connections within the slirp stack.
type Listener6 struct {
	s         *Stack
	addr      *net.TCPAddr
	acceptCh  chan *VirtualConn6
	closeCh   chan struct{}
	closeOnce sync.Once
}

// VirtualConn6 represents a virtual IPv6 TCP connection within the slirp stack.
type VirtualConn6 struct {
	localAddr  *net.TCPAddr
	remoteAddr *net.TCPAddr

	// Server->Client communication
	sendMu   sync.Mutex
	sendBuf  []byte
	sendCond *sync.Cond

	// Client->Server communication
	recvMu   sync.Mutex
	recvBuf  []byte
	recvCond *sync.Cond

	// Connection state
	mu         sync.Mutex
	closed     atomic.Bool
	clientMAC  [6]byte
	gwMAC      [6]byte
	w          Writer
	seq        uint32 // Server's sequence number
	ack        uint32 // Server's acknowledgment number
	clientSeq  uint32 // Expected client sequence
	clientWnd  uint16 // Client's receive window
	lastAct    time.Time
	established bool
}

func newVirtualConn6(localIP [16]byte, localPort uint16, remoteIP [16]byte, remotePort uint16, clientMAC, gwMAC [6]byte, w Writer) *VirtualConn6 {
	vc := &VirtualConn6{
		localAddr:  &net.TCPAddr{IP: net.IP(localIP[:]), Port: int(localPort)},
		remoteAddr: &net.TCPAddr{IP: net.IP(remoteIP[:]), Port: int(remotePort)},
		clientMAC:  clientMAC,
		gwMAC:      gwMAC,
		w:          w,
		seq:        RandUint32(),
		clientWnd:  65535,
		lastAct:    time.Now(),
	}
	vc.sendCond = sync.NewCond(&vc.sendMu)
	vc.recvCond = sync.NewCond(&vc.recvMu)
	return vc
}

// Read reads data from the connection (data received from the client).
func (vc *VirtualConn6) Read(b []byte) (int, error) {
	vc.recvMu.Lock()
	defer vc.recvMu.Unlock()

	for len(vc.recvBuf) == 0 {
		if vc.closed.Load() {
			return 0, io.EOF
		}
		vc.recvCond.Wait()
	}

	n := copy(b, vc.recvBuf)
	vc.recvBuf = vc.recvBuf[n:]
	return n, nil
}

// Write writes data to the connection (data to send to the client).
func (vc *VirtualConn6) Write(b []byte) (int, error) {
	if vc.closed.Load() {
		return 0, errors.New("connection closed")
	}

	vc.sendMu.Lock()
	vc.sendBuf = append(vc.sendBuf, b...)
	vc.sendMu.Unlock()

	// Trigger sending
	go vc.flush()

	return len(b), nil
}

// flush sends queued data to the client.
func (vc *VirtualConn6) flush() {
	vc.mu.Lock()
	if !vc.established {
		vc.mu.Unlock()
		return
	}

	vc.sendMu.Lock()
	var pkts [][]byte
	const maxSegment = 1440
	for len(vc.sendBuf) > 0 {
		segment := vc.sendBuf
		if len(segment) > maxSegment {
			segment = segment[:maxSegment]
		}

		var localIP, remoteIP [16]byte
		copy(localIP[:], vc.localAddr.IP)
		copy(remoteIP[:], vc.remoteAddr.IP)

		pkt := BuildTCPPacket6(vc.gwMAC, vc.clientMAC,
			localIP, remoteIP,
			uint16(vc.localAddr.Port), uint16(vc.remoteAddr.Port),
			vc.seq, vc.ack, 0x18, segment)

		pkts = append(pkts, pkt)
		vc.seq += uint32(len(segment))
		vc.sendBuf = vc.sendBuf[len(segment):]
	}
	vc.sendMu.Unlock()
	vc.mu.Unlock()

	for _, pkt := range pkts {
		_ = vc.w(pkt)
	}
	vc.sendCond.Broadcast()
}

// handleInbound processes an incoming IPv6 packet from the client.
func (vc *VirtualConn6) handleInbound(packet []byte) error {
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
	wnd := binary.BigEndian.Uint16(tcp[14:16])
	payload := tcp[doff:]

	var outgoing [][]byte
	var signalRecv, signalClose bool

	vc.mu.Lock()

	vc.lastAct = time.Now()
	vc.clientWnd = wnd

	if (flags & 0x04) != 0 {
		vc.closed.Store(true)
		vc.mu.Unlock()
		vc.recvMu.Lock()
		vc.recvCond.Broadcast()
		vc.recvMu.Unlock()
		vc.sendMu.Lock()
		vc.sendCond.Broadcast()
		vc.sendMu.Unlock()
		return nil
	}

	if !vc.established && (flags&0x10) != 0 {
		if ack == vc.seq+1 {
			vc.established = true
			vc.seq += 1
		}
		vc.mu.Unlock()
		return nil
	}

	if len(payload) > 0 && seq == vc.clientSeq {
		vc.recvMu.Lock()
		vc.recvBuf = append(vc.recvBuf, payload...)
		vc.recvMu.Unlock()
		signalRecv = true

		vc.clientSeq += uint32(len(payload))
		vc.ack = vc.clientSeq

		var localIP, remoteIP [16]byte
		copy(localIP[:], vc.localAddr.IP)
		copy(remoteIP[:], vc.remoteAddr.IP)
		pkt := BuildTCPPacket6(vc.gwMAC, vc.clientMAC,
			localIP, remoteIP,
			uint16(vc.localAddr.Port), uint16(vc.remoteAddr.Port),
			vc.seq, vc.ack, 0x10, nil)
		outgoing = append(outgoing, pkt)
	}

	if (flags & 0x01) != 0 {
		vc.clientSeq += 1
		vc.ack = vc.clientSeq
		vc.closed.Store(true)
		signalClose = true

		var localIP, remoteIP [16]byte
		copy(localIP[:], vc.localAddr.IP)
		copy(remoteIP[:], vc.remoteAddr.IP)
		pkt := BuildTCPPacket6(vc.gwMAC, vc.clientMAC,
			localIP, remoteIP,
			uint16(vc.localAddr.Port), uint16(vc.remoteAddr.Port),
			vc.seq, vc.ack, 0x11, nil)
		outgoing = append(outgoing, pkt)
	}

	vc.mu.Unlock()

	for _, pkt := range outgoing {
		_ = vc.w(pkt)
	}
	if signalRecv || signalClose {
		vc.recvMu.Lock()
		vc.recvCond.Broadcast()
		vc.recvMu.Unlock()
	}
	if signalClose {
		vc.sendMu.Lock()
		vc.sendCond.Broadcast()
		vc.sendMu.Unlock()
	}

	return nil
}

// Close closes the connection.
func (vc *VirtualConn6) Close() error {
	vc.mu.Lock()
	if vc.closed.Load() {
		vc.mu.Unlock()
		return nil
	}
	vc.closed.Store(true)
	shouldFin := vc.established
	seq, ack := vc.seq, vc.ack
	vc.mu.Unlock()

	// Send FIN using captured values
	if shouldFin {
		var localIP, remoteIP [16]byte
		copy(localIP[:], vc.localAddr.IP)
		copy(remoteIP[:], vc.remoteAddr.IP)

		pkt := BuildTCPPacket6(vc.gwMAC, vc.clientMAC,
			localIP, remoteIP,
			uint16(vc.localAddr.Port), uint16(vc.remoteAddr.Port),
			seq, ack, 0x11, nil) // FIN+ACK
		_ = vc.w(pkt)
	}

	// Broadcast under the respective locks to prevent missed wakeups
	vc.recvMu.Lock()
	vc.recvCond.Broadcast()
	vc.recvMu.Unlock()

	vc.sendMu.Lock()
	vc.sendCond.Broadcast()
	vc.sendMu.Unlock()
	return nil
}

// LocalAddr returns the local network address.
func (vc *VirtualConn6) LocalAddr() net.Addr {
	return vc.localAddr
}

// RemoteAddr returns the remote network address.
func (vc *VirtualConn6) RemoteAddr() net.Addr {
	return vc.remoteAddr
}

// SetDeadline sets the read and write deadlines (not implemented).
func (vc *VirtualConn6) SetDeadline(t time.Time) error {
	return nil // Not implemented for now
}

// SetReadDeadline sets the read deadline (not implemented).
func (vc *VirtualConn6) SetReadDeadline(t time.Time) error {
	return nil // Not implemented for now
}

// SetWriteDeadline sets the write deadline (not implemented).
func (vc *VirtualConn6) SetWriteDeadline(t time.Time) error {
	return nil // Not implemented for now
}
