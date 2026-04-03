package vclient

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/KarpelesLab/slirp"
)

type tcpState int

const (
	tcpClosed tcpState = iota
	tcpSynSent
	tcpEstablished
	tcpFinWait1
	tcpFinWait2
	tcpCloseWait
	tcpLastAck
	tcpTimeWait
)

// TCPConn is a virtual TCP connection implementing net.Conn.
type TCPConn struct {
	mu sync.Mutex

	localIP    [4]byte
	localPort  uint16
	remoteIP   [4]byte
	remotePort uint16

	mac   [6]byte // our MAC
	gwMAC [6]byte // gateway MAC for sending
	c     *Client

	// TCP state (RFC 793)
	state  tcpState
	sndNxt uint32 // next sequence number to send
	sndUna uint32 // oldest unacknowledged sequence number
	sndWnd uint16 // remote advertised window
	rcvNxt uint32 // next sequence number expected from remote
	mss    int    // max segment size

	// Send buffers
	sendBuf   []byte // sent but unacked data (for retransmission)
	sendQueue []byte // queued but unsent data
	sendCond  *sync.Cond

	// Outgoing packet queue — flushed outside the lock to avoid deadlocks
	// when Pipe synchronously delivers responses back to handleSegment.
	outgoing [][]byte

	// Receive buffer
	recvMu   sync.Mutex
	recvBuf  []byte
	recvCond *sync.Cond

	// Retransmission (RFC 6298)
	rto      time.Duration
	srtt     time.Duration
	rttvar   time.Duration
	rtoTimer *time.Timer
	rttStart time.Time // when the currently-timed segment was sent
	rttSeq   uint32    // seq of the segment being timed
	retries  int

	// Keepalive
	lastRecv      time.Time // last time a segment was received
	keepaliveSent int       // unanswered keepalive probes

	// Lifecycle
	closed          atomic.Bool
	established     chan struct{} // closed when handshake completes
	establishedOnce sync.Once
	finRecvd        chan struct{} // closed when FIN received from remote
	finRecvdOnce    sync.Once

	// Deadlines
	readDeadline  atomic.Value // time.Time
	writeDeadline atomic.Value // time.Time
}

func newTCPConn(c *Client, localIP [4]byte, localPort uint16, remoteIP [4]byte, remotePort uint16, gwMAC [6]byte) *TCPConn {
	tc := &TCPConn{
		localIP:     localIP,
		localPort:   localPort,
		remoteIP:    remoteIP,
		remotePort:  remotePort,
		mac:         c.mac,
		gwMAC:       gwMAC,
		c:           c,
		state:       tcpClosed,
		mss:         1460,
		sndWnd:      65535,
		rto:         time.Second,
		lastRecv:    time.Now(),
		established: make(chan struct{}),
		finRecvd:    make(chan struct{}),
	}
	tc.sendCond = sync.NewCond(&tc.mu)
	tc.recvCond = sync.NewCond(&tc.recvMu)
	return tc
}

// queueSend adds a packet to the outgoing queue. Must hold tc.mu.
func (tc *TCPConn) queueSend(pkt []byte) {
	tc.outgoing = append(tc.outgoing, pkt)
}

// drainOutgoing returns and clears the outgoing packet queue. Must hold tc.mu.
func (tc *TCPConn) drainOutgoing() [][]byte {
	pkts := tc.outgoing
	tc.outgoing = nil
	return pkts
}

// flushPackets sends packets outside the lock.
func (tc *TCPConn) flushPackets(pkts [][]byte) {
	for _, pkt := range pkts {
		_ = tc.c.sendIPv4(tc.gwMAC, pkt)
	}
}

// connect initiates the TCP handshake by sending a SYN.
func (tc *TCPConn) connect() {
	tc.mu.Lock()
	tc.sndNxt = slirp.RandUint32()
	tc.sndUna = tc.sndNxt
	tc.state = tcpSynSent
	tc.rttStart = time.Now()
	tc.buildSYN()
	tc.startRTO()
	pkts := tc.drainOutgoing()
	tc.mu.Unlock()

	tc.flushPackets(pkts)
}

// buildSYN queues a SYN packet. Must hold tc.mu.
func (tc *TCPConn) buildSYN() {
	tcpHdr := make([]byte, 24) // 20 base + 4 MSS option
	binary.BigEndian.PutUint16(tcpHdr[0:2], tc.localPort)
	binary.BigEndian.PutUint16(tcpHdr[2:4], tc.remotePort)
	binary.BigEndian.PutUint32(tcpHdr[4:8], tc.sndNxt)
	tcpHdr[12] = 6 << 4 // data offset = 6
	tcpHdr[13] = 0x02   // SYN
	binary.BigEndian.PutUint16(tcpHdr[14:16], 65535)
	tcpHdr[20] = 2 // MSS option kind
	tcpHdr[21] = 4 // MSS option length
	binary.BigEndian.PutUint16(tcpHdr[22:24], uint16(tc.mss))

	tc.queueSend(tc.buildIPPacket(tcpHdr, nil))
}

// handleSegment processes an incoming TCP segment for this connection.
func (tc *TCPConn) handleSegment(ip []byte, ihl int) {
	tcp := ip[ihl:]
	if len(tcp) < 20 {
		return
	}
	doff := int((tcp[12]>>4)&0x0F) * 4
	if len(tcp) < doff {
		return
	}

	flags := tcp[13]
	seq := binary.BigEndian.Uint32(tcp[4:8])
	ack := binary.BigEndian.Uint32(tcp[8:12])
	wnd := binary.BigEndian.Uint16(tcp[14:16])
	payload := tcp[doff:]

	// Signals to fire after releasing the lock
	var signalEstablished, signalFinRecvd, signalRecv, signalSend, needUnregister bool

	tc.mu.Lock()

	tc.lastRecv = time.Now()
	tc.keepaliveSent = 0

	// RST — tear down immediately
	if (flags & 0x04) != 0 {
		tc.state = tcpClosed
		tc.closed.Store(true)
		tc.stopRTO()
		tc.mu.Unlock()
		tc.unregister()
		tc.recvCond.Broadcast()
		tc.sendCond.Broadcast()
		tc.safeCloseEstablished()
		tc.safeCloseFinRecvd()
		return
	}

	switch tc.state {
	case tcpSynSent:
		if (flags&0x12) == 0x12 && ack == tc.sndNxt+1 {
			tc.sndUna = ack
			tc.sndNxt = ack
			tc.rcvNxt = seq + 1
			tc.sndWnd = wnd
			tc.state = tcpEstablished
			tc.retries = 0
			tc.stopRTO()

			if doff > 20 {
				tc.parseMSS(tcp[20:doff])
			}
			if !tc.rttStart.IsZero() {
				tc.updateRTO(time.Since(tc.rttStart))
				tc.rttStart = time.Time{}
			}

			tc.buildACK()
			tc.flushSendQueue()
			signalEstablished = true
		}

	case tcpEstablished, tcpFinWait1, tcpFinWait2:
		if (flags & 0x10) != 0 {
			tc.processACK(ack)
		}
		tc.sndWnd = wnd

		if len(payload) > 0 && seq == tc.rcvNxt {
			tc.rcvNxt += uint32(len(payload))

			tc.recvMu.Lock()
			tc.recvBuf = append(tc.recvBuf, payload...)
			tc.recvMu.Unlock()
			signalRecv = true

			tc.buildACK()
		}

		if (flags & 0x01) != 0 {
			tc.rcvNxt += 1
			tc.buildACK()

			switch tc.state {
			case tcpEstablished:
				tc.state = tcpCloseWait
				signalFinRecvd = true
				signalRecv = true
			case tcpFinWait1:
				if (flags&0x10) != 0 && ack == tc.sndNxt {
					tc.state = tcpTimeWait
				} else {
					tc.state = tcpCloseWait
				}
				signalFinRecvd = true
				signalRecv = true
			case tcpFinWait2:
				tc.state = tcpTimeWait
				signalFinRecvd = true
				signalRecv = true
			}
		} else if tc.state == tcpFinWait1 && (flags&0x10) != 0 && ack == tc.sndNxt {
			tc.state = tcpFinWait2
		}

	case tcpCloseWait:
		if (flags & 0x10) != 0 {
			tc.processACK(ack)
			signalSend = true
		}

	case tcpLastAck:
		if (flags&0x10) != 0 && ack == tc.sndNxt {
			tc.state = tcpClosed
			tc.closed.Store(true)
			tc.stopRTO()
			signalRecv = true
			signalSend = true
			needUnregister = true
		}
	}

	pkts := tc.drainOutgoing()
	needTimeWait := tc.state == tcpTimeWait
	tc.mu.Unlock()

	// All sends happen outside the lock
	tc.flushPackets(pkts)

	if needUnregister {
		tc.unregister()
	}
	// Signal condition variables
	if signalRecv {
		tc.recvCond.Broadcast()
	}
	if signalSend {
		tc.sendCond.Broadcast()
	}
	if signalEstablished {
		tc.safeCloseEstablished()
		go tc.keepaliveLoop()
	}
	if signalFinRecvd {
		tc.safeCloseFinRecvd()
	}
	if needTimeWait {
		go tc.timeWait()
	}
}

// processACK handles an incoming ACK number. Must hold tc.mu.
func (tc *TCPConn) processACK(ack uint32) {
	if !slirp.SeqAfter(ack, tc.sndUna) {
		return
	}
	if slirp.SeqAfter(ack, tc.sndNxt) {
		return
	}

	acked := ack - tc.sndUna
	tc.retries = 0

	if uint32(len(tc.sendBuf)) >= acked {
		tc.sendBuf = tc.sendBuf[acked:]
	} else {
		tc.sendBuf = nil
	}
	tc.sndUna = ack

	if !tc.rttStart.IsZero() && slirp.SeqAfter(ack, tc.rttSeq) {
		tc.updateRTO(time.Since(tc.rttStart))
		tc.rttStart = time.Time{}
	}

	if len(tc.sendBuf) > 0 {
		tc.startRTO()
	} else {
		tc.stopRTO()
	}

	tc.flushSendQueue()
}

// flushSendQueue sends queued data respecting the remote window. Must hold tc.mu.
func (tc *TCPConn) flushSendQueue() {
	for len(tc.sendQueue) > 0 {
		avail := int(tc.sndWnd) - len(tc.sendBuf)
		if avail <= 0 {
			break
		}
		seg := tc.sendQueue
		if len(seg) > tc.mss {
			seg = seg[:tc.mss]
		}
		if len(seg) > avail {
			seg = seg[:avail]
		}

		tc.buildDataSegment(seg)
		tc.sendBuf = append(tc.sendBuf, seg...)
		tc.sendQueue = tc.sendQueue[len(seg):]

		if tc.rttStart.IsZero() {
			tc.rttStart = time.Now()
			tc.rttSeq = tc.sndNxt
		}
		tc.sndNxt += uint32(len(seg))

		if tc.rtoTimer == nil {
			tc.startRTO()
		}
	}
}

// buildDataSegment queues a TCP data segment. Must hold tc.mu.
func (tc *TCPConn) buildDataSegment(payload []byte) {
	tcpHdr := make([]byte, 20)
	binary.BigEndian.PutUint16(tcpHdr[0:2], tc.localPort)
	binary.BigEndian.PutUint16(tcpHdr[2:4], tc.remotePort)
	binary.BigEndian.PutUint32(tcpHdr[4:8], tc.sndNxt)
	binary.BigEndian.PutUint32(tcpHdr[8:12], tc.rcvNxt)
	tcpHdr[12] = 5 << 4
	tcpHdr[13] = 0x18 // PSH+ACK
	binary.BigEndian.PutUint16(tcpHdr[14:16], 65535)
	tc.queueSend(tc.buildIPPacket(tcpHdr, payload))
}

// buildACK queues a bare ACK. Must hold tc.mu.
func (tc *TCPConn) buildACK() {
	tcpHdr := make([]byte, 20)
	binary.BigEndian.PutUint16(tcpHdr[0:2], tc.localPort)
	binary.BigEndian.PutUint16(tcpHdr[2:4], tc.remotePort)
	binary.BigEndian.PutUint32(tcpHdr[4:8], tc.sndNxt)
	binary.BigEndian.PutUint32(tcpHdr[8:12], tc.rcvNxt)
	tcpHdr[12] = 5 << 4
	tcpHdr[13] = 0x10 // ACK
	binary.BigEndian.PutUint16(tcpHdr[14:16], 65535)
	tc.queueSend(tc.buildIPPacket(tcpHdr, nil))
}

// buildFIN queues a FIN+ACK. Must hold tc.mu.
func (tc *TCPConn) buildFIN() {
	tcpHdr := make([]byte, 20)
	binary.BigEndian.PutUint16(tcpHdr[0:2], tc.localPort)
	binary.BigEndian.PutUint16(tcpHdr[2:4], tc.remotePort)
	binary.BigEndian.PutUint32(tcpHdr[4:8], tc.sndNxt)
	binary.BigEndian.PutUint32(tcpHdr[8:12], tc.rcvNxt)
	tcpHdr[12] = 5 << 4
	tcpHdr[13] = 0x11 // FIN+ACK
	binary.BigEndian.PutUint16(tcpHdr[14:16], 65535)
	tc.queueSend(tc.buildIPPacket(tcpHdr, nil))
	tc.sndNxt += 1 // FIN consumes a sequence number
}

// buildIPPacket builds a complete IP+TCP packet. Must hold tc.mu (reads seq/ack state).
func (tc *TCPConn) buildIPPacket(tcpHdr []byte, payload []byte) []byte {
	ipHdr := make([]byte, 20)
	totalLen := 20 + len(tcpHdr) + len(payload)
	ipHdr[0] = 0x45
	binary.BigEndian.PutUint16(ipHdr[2:4], uint16(totalLen))
	ipHdr[8] = 64
	ipHdr[9] = 6
	copy(ipHdr[12:16], tc.localIP[:])
	copy(ipHdr[16:20], tc.remoteIP[:])
	binary.BigEndian.PutUint16(ipHdr[10:12], 0)
	binary.BigEndian.PutUint16(ipHdr[10:12], slirp.IPChecksum(ipHdr))

	binary.BigEndian.PutUint16(tcpHdr[16:18], 0)
	binary.BigEndian.PutUint16(tcpHdr[16:18], slirp.TCPChecksum(ipHdr[12:16], ipHdr[16:20], tcpHdr, payload))

	pkt := make([]byte, len(ipHdr)+len(tcpHdr)+len(payload))
	copy(pkt, ipHdr)
	copy(pkt[len(ipHdr):], tcpHdr)
	copy(pkt[len(ipHdr)+len(tcpHdr):], payload)
	return pkt
}

// parseMSS extracts MSS from TCP options.
func (tc *TCPConn) parseMSS(opts []byte) {
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
			if int(mss) < tc.mss {
				tc.mss = int(mss)
			}
		}
		i += l
	}
}

// RTO timer management

func (tc *TCPConn) startRTO() {
	tc.stopRTO()
	rto := tc.rto
	tc.rtoTimer = time.AfterFunc(rto, tc.onRTOTimeout)
}

func (tc *TCPConn) stopRTO() {
	if tc.rtoTimer != nil {
		tc.rtoTimer.Stop()
		tc.rtoTimer = nil
	}
}

func (tc *TCPConn) onRTOTimeout() {
	tc.mu.Lock()
	if tc.closed.Load() || tc.state == tcpClosed {
		tc.mu.Unlock()
		return
	}

	tc.retries++
	if tc.retries > 8 {
		tc.state = tcpClosed
		tc.closed.Store(true)
		tc.stopRTO()
		tc.mu.Unlock()
		tc.unregister()
		tc.recvCond.Broadcast()
		tc.sendCond.Broadcast()
		tc.safeCloseEstablished()
		return
	}

	tc.rto *= 2
	if tc.rto > 60*time.Second {
		tc.rto = 60 * time.Second
	}
	tc.rttStart = time.Time{} // Karn's algorithm

	switch tc.state {
	case tcpSynSent:
		tc.buildSYN()
	case tcpEstablished, tcpCloseWait:
		if len(tc.sendBuf) > 0 {
			seg := tc.sendBuf
			if len(seg) > tc.mss {
				seg = seg[:tc.mss]
			}
			// Retransmit from sndUna
			tcpHdr := make([]byte, 20)
			binary.BigEndian.PutUint16(tcpHdr[0:2], tc.localPort)
			binary.BigEndian.PutUint16(tcpHdr[2:4], tc.remotePort)
			binary.BigEndian.PutUint32(tcpHdr[4:8], tc.sndUna) // retransmit from oldest unacked
			binary.BigEndian.PutUint32(tcpHdr[8:12], tc.rcvNxt)
			tcpHdr[12] = 5 << 4
			tcpHdr[13] = 0x18
			binary.BigEndian.PutUint16(tcpHdr[14:16], 65535)
			tc.queueSend(tc.buildIPPacket(tcpHdr, seg))
		}
	case tcpFinWait1, tcpLastAck:
		tc.buildFIN()
		tc.sndNxt -= 1 // buildFIN already incremented, undo for retransmit
	}

	tc.startRTO()
	pkts := tc.drainOutgoing()
	tc.mu.Unlock()

	tc.flushPackets(pkts)
}

func (tc *TCPConn) updateRTO(rtt time.Duration) {
	if tc.srtt == 0 {
		tc.srtt = rtt
		tc.rttvar = rtt / 2
	} else {
		diff := tc.srtt - rtt
		if diff < 0 {
			diff = -diff
		}
		tc.rttvar = (3*tc.rttvar + diff) / 4
		tc.srtt = (7*tc.srtt + rtt) / 8
	}
	tc.rto = tc.srtt + 4*tc.rttvar
	if tc.rto < 200*time.Millisecond {
		tc.rto = 200 * time.Millisecond
	}
	if tc.rto > 60*time.Second {
		tc.rto = 60 * time.Second
	}
}

func (tc *TCPConn) timeWait() {
	time.Sleep(2 * time.Second)
	tc.mu.Lock()
	tc.state = tcpClosed
	tc.closed.Store(true)
	tc.mu.Unlock()
	tc.unregister()
	tc.recvCond.Broadcast()
}

// keepaliveLoop sends periodic keepalive probes for idle connections.
func (tc *TCPConn) keepaliveLoop() {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		tc.mu.Lock()
		if tc.closed.Load() || tc.state == tcpClosed {
			tc.mu.Unlock()
			return
		}
		if tc.state != tcpEstablished && tc.state != tcpCloseWait {
			tc.mu.Unlock()
			return
		}
		if time.Since(tc.lastRecv) > 30*time.Second {
			if tc.keepaliveSent >= 3 {
				// No response after 3 probes — abort
				tc.state = tcpClosed
				tc.closed.Store(true)
				tc.stopRTO()
				tc.mu.Unlock()
				tc.unregister()
				tc.recvCond.Broadcast()
				tc.sendCond.Broadcast()
				tc.safeCloseEstablished()
				tc.safeCloseFinRecvd()
				return
			}
			// Send keepalive probe: ACK with seq-1
			tc.buildKeepaliveProbe()
			tc.keepaliveSent++
			pkts := tc.drainOutgoing()
			tc.mu.Unlock()
			tc.flushPackets(pkts)
		} else {
			tc.mu.Unlock()
		}
	}
}

// buildKeepaliveProbe queues a keepalive probe (ACK with seq-1). Must hold tc.mu.
func (tc *TCPConn) buildKeepaliveProbe() {
	tcpHdr := make([]byte, 20)
	binary.BigEndian.PutUint16(tcpHdr[0:2], tc.localPort)
	binary.BigEndian.PutUint16(tcpHdr[2:4], tc.remotePort)
	binary.BigEndian.PutUint32(tcpHdr[4:8], tc.sndNxt-1) // seq-1 is the keepalive signal
	binary.BigEndian.PutUint32(tcpHdr[8:12], tc.rcvNxt)
	tcpHdr[12] = 5 << 4
	tcpHdr[13] = 0x10 // ACK
	binary.BigEndian.PutUint16(tcpHdr[14:16], 65535)
	tc.queueSend(tc.buildIPPacket(tcpHdr, nil))
}

func (tc *TCPConn) safeCloseEstablished() {
	tc.establishedOnce.Do(func() { close(tc.established) })
}

func (tc *TCPConn) safeCloseFinRecvd() {
	tc.finRecvdOnce.Do(func() { close(tc.finRecvd) })
}

func (tc *TCPConn) abort() {
	tc.closed.Store(true)
	tc.mu.Lock()
	tc.state = tcpClosed
	tc.stopRTO()
	tc.mu.Unlock()
	// Note: callers (Client.Close, dialTCP) handle map removal themselves.
	tc.recvCond.Broadcast()
	tc.sendCond.Broadcast()
	tc.safeCloseEstablished()
	tc.safeCloseFinRecvd()
}

// net.Conn implementation

func (tc *TCPConn) Read(b []byte) (int, error) {
	tc.recvMu.Lock()
	defer tc.recvMu.Unlock()

	for len(tc.recvBuf) == 0 {
		if tc.closed.Load() {
			return 0, io.EOF
		}
		if dl, ok := tc.readDeadline.Load().(time.Time); ok && !dl.IsZero() {
			if time.Now().After(dl) {
				return 0, &net.OpError{Op: "read", Err: errors.New("i/o timeout")}
			}
			timer := time.AfterFunc(time.Until(dl), func() { tc.recvCond.Broadcast() })
			tc.recvCond.Wait()
			timer.Stop()
		} else {
			tc.recvCond.Wait()
		}
	}

	n := copy(b, tc.recvBuf)
	tc.recvBuf = tc.recvBuf[n:]
	return n, nil
}

func (tc *TCPConn) Write(b []byte) (int, error) {
	if tc.closed.Load() {
		return 0, errors.New("connection closed")
	}

	tc.mu.Lock()
	if tc.state != tcpEstablished && tc.state != tcpCloseWait {
		tc.mu.Unlock()
		return 0, errors.New("connection not established")
	}
	tc.sendQueue = append(tc.sendQueue, b...)
	tc.flushSendQueue()
	pkts := tc.drainOutgoing()
	tc.mu.Unlock()

	tc.flushPackets(pkts)
	return len(b), nil
}

func (tc *TCPConn) Close() error {
	if tc.closed.Load() {
		return nil
	}

	tc.mu.Lock()
	var pkts [][]byte
	switch tc.state {
	case tcpEstablished:
		tc.flushSendQueue()
		tc.state = tcpFinWait1
		tc.buildFIN()
		tc.startRTO()
		pkts = tc.drainOutgoing()
	case tcpCloseWait:
		tc.state = tcpLastAck
		tc.buildFIN()
		tc.startRTO()
		pkts = tc.drainOutgoing()
	default:
		tc.closed.Store(true)
		tc.state = tcpClosed
		tc.stopRTO()
	}
	isClosed := tc.state == tcpClosed
	tc.mu.Unlock()

	tc.flushPackets(pkts)

	// Only remove from connection map when fully closed; active FIN
	// handshakes still need to receive ACKs/FINs from the remote.
	if isClosed {
		tc.unregister()
	}

	tc.recvCond.Broadcast()
	tc.sendCond.Broadcast()
	return nil
}

// unregister removes this connection from the client's dispatch map.
func (tc *TCPConn) unregister() {
	tc.c.tcpMu.Lock()
	delete(tc.c.tcpConns, connKey{
		localPort:  tc.localPort,
		remoteIP:   tc.remoteIP,
		remotePort: tc.remotePort,
	})
	tc.c.tcpMu.Unlock()
}

func (tc *TCPConn) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.IP(tc.localIP[:]).To4(), Port: int(tc.localPort)}
}

func (tc *TCPConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.IP(tc.remoteIP[:]).To4(), Port: int(tc.remotePort)}
}

func (tc *TCPConn) SetDeadline(t time.Time) error {
	tc.readDeadline.Store(t)
	tc.writeDeadline.Store(t)
	tc.recvCond.Broadcast()
	return nil
}

func (tc *TCPConn) SetReadDeadline(t time.Time) error {
	tc.readDeadline.Store(t)
	tc.recvCond.Broadcast()
	return nil
}

func (tc *TCPConn) SetWriteDeadline(t time.Time) error {
	tc.writeDeadline.Store(t)
	return nil
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
		conn.handleSegment(ip, ihl)
	}
	return nil
}
