package vtcp

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// ConnConfig holds configuration for a new Conn.
type ConnConfig struct {
	LocalAddr  net.Addr
	RemoteAddr net.Addr
	LocalPort  uint16
	RemotePort uint16
	Writer     SegmentWriter
	MSS        int

	// RFC 7323
	NoWindowScaling  bool // set true to disable window scaling (enabled by default)
	EnableTimestamps bool

	// RFC 2018
	EnableSACK bool

	// Congestion control: "newreno" or "highspeed" (default: "highspeed")
	CongestionControl string

	// RFC 1122 keepalive
	Keepalive         bool
	KeepaliveIdle     time.Duration
	KeepaliveInterval time.Duration
	KeepaliveCount    int

	SendBufSize int
	RecvBufSize int
}

func newCongestionController(name string, mss uint32) CongestionController {
	switch name {
	case "newreno":
		return NewNewReno(mss)
	default: // "highspeed" or empty
		return NewHighSpeed(mss)
	}
}

func (cfg *ConnConfig) mss() int {
	if cfg.MSS > 0 {
		return cfg.MSS
	}
	return DefaultMSS
}

func (cfg *ConnConfig) recvBufSize() int {
	if cfg.RecvBufSize > 0 {
		return cfg.RecvBufSize
	}
	return DefaultRecvBuf
}

// Conn is a single TCP connection implementing net.Conn.
// It runs the full TCP state machine (RFC 793) with congestion control
// (RFC 5681), retransmission (RFC 6298), and optional modern extensions.
//
// Callers interact with Conn from two sides:
//   - Network side: HandleSegment (inbound), returned packets (outbound)
//   - Application side: Read, Write, Close (net.Conn interface)
//
// All outgoing packets are returned from methods (never sent while holding
// the internal mutex), making Conn safe for synchronous delivery patterns.
type Conn struct {
	mu sync.Mutex

	// Identity
	localPort  uint16
	remotePort uint16
	localAddr  net.Addr
	remoteAddr net.Addr
	writer     SegmentWriter

	// State machine
	state State

	// Send side
	sendBuf *SendBuf
	sndWnd  uint32 // remote advertised window (scaled)
	mss     int

	// Receive side
	recvMu     sync.Mutex
	recvBuf    *RecvBuf
	recvCond   *sync.Cond
	recvBufCap int

	// Congestion control
	cc CongestionController

	// RTO
	rto      *RTOCalculator
	rtoTimer *time.Timer
	retries  int

	// Window scaling (RFC 7323)
	sndWndShift uint8 // shift count for remote's window
	rcvWndShift uint8 // our window shift (advertised in SYN)
	wscaleOK    bool  // both sides negotiated window scaling

	// Timestamps (RFC 7323)
	tsEnabled bool
	tsRecent  uint32 // most recent TSval from remote
	tsOffset  uint32 // our timestamp base (monotonic)

	// SACK (RFC 2018)
	sackEnabled bool
	sackOK      bool // both sides negotiated SACK

	// Persist timer (RFC 9293 §3.7.7 — zero-window probing)
	persistTimer   *time.Timer
	persistBackoff time.Duration

	// Keepalive
	keepalive      bool
	keepaliveIdle  time.Duration
	keepaliveIntv  time.Duration
	keepaliveMax   int
	keepaliveSent  int
	lastRecv       time.Time
	keepaliveTimer *time.Timer

	// Outgoing packet queue (drain outside mutex)
	outgoing [][]byte

	// Lifecycle
	closed          atomic.Bool
	established     chan struct{}
	establishedOnce sync.Once
	finRecvd        chan struct{}
	finRecvdOnce    sync.Once

	// Deadlines
	readDeadline  atomic.Value // time.Time
	writeDeadline atomic.Value // time.Time

	// App-side write coordination
	sendCond *sync.Cond // shares mu
}

// NewConn creates a new TCP connection in the CLOSED state.
func NewConn(cfg ConnConfig) *Conn {
	recvBufCap := cfg.recvBufSize()

	// Auto-compute window scale: smallest shift so that bufSize >> shift fits in 16 bits.
	// RFC 7323: shift count 0-14.
	var rcvWndShift uint8
	if !cfg.NoWindowScaling {
		for s := uint8(0); s <= 14; s++ {
			if recvBufCap>>s <= 65535 {
				rcvWndShift = s
				break
			}
			rcvWndShift = s // keep going until it fits
		}
	}

	c := &Conn{
		localPort:   cfg.LocalPort,
		remotePort:  cfg.RemotePort,
		localAddr:   cfg.LocalAddr,
		remoteAddr:  cfg.RemoteAddr,
		writer:      cfg.Writer,
		state:       StateClosed,
		mss:         cfg.mss(),
		sndWnd:      DefaultWindowSize,
		cc:          newCongestionController(cfg.CongestionControl, uint32(cfg.mss())),
		rto:         NewRTOCalculator(),
		lastRecv:    time.Now(),
		recvBufCap:  recvBufCap,
		established: make(chan struct{}),
		finRecvd:    make(chan struct{}),

		// Options config (negotiated during handshake)
		rcvWndShift: rcvWndShift,
		tsEnabled:   cfg.EnableTimestamps,
		sackEnabled: cfg.EnableSACK,

		// Keepalive
		keepalive:     cfg.Keepalive,
		keepaliveIdle: cfg.KeepaliveIdle,
		keepaliveIntv: cfg.KeepaliveInterval,
		keepaliveMax:  cfg.KeepaliveCount,
	}
	if c.keepaliveIdle == 0 {
		c.keepaliveIdle = DefaultKeepaliveIdle
	}
	if c.keepaliveIntv == 0 {
		c.keepaliveIntv = DefaultKeepaliveInterval
	}
	if c.keepaliveMax == 0 {
		c.keepaliveMax = DefaultKeepaliveCount
	}

	c.sendCond = sync.NewCond(&c.mu)
	c.recvCond = sync.NewCond(&c.recvMu)
	return c
}

// State returns the current TCP state.
func (c *Conn) State() State {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.state
}

// --- Outgoing packet helpers ---

func (c *Conn) queueSeg(seg Segment) {
	c.outgoing = append(c.outgoing, seg.Marshal())
}

func (c *Conn) drainOutgoing() [][]byte {
	pkts := c.outgoing
	c.outgoing = nil
	return pkts
}

func (c *Conn) flushPackets(pkts [][]byte) {
	for _, pkt := range pkts {
		if c.writer != nil {
			_ = c.writer(pkt)
		}
	}
}

// --- Segment builders ---

func (c *Conn) rcvWindow() uint16 {
	// Advertise available receive buffer space, scaled by our shift factor.
	c.recvMu.Lock()
	used := 0
	if c.recvBuf != nil {
		used = c.recvBuf.Readable()
	}
	c.recvMu.Unlock()

	avail := c.recvBufSize() - used
	if avail < 0 {
		avail = 0
	}
	if c.wscaleOK {
		avail >>= c.rcvWndShift
	}
	if avail > 65535 {
		avail = 65535
	}
	return uint16(avail)
}

func (c *Conn) recvBufSize() int {
	if c.recvBufCap > 0 {
		return c.recvBufCap
	}
	return DefaultRecvBuf
}

func (c *Conn) buildSYNOptions() []Option {
	opts := []Option{MSSOption(uint16(c.mss))}
	// Always offer window scaling (shift 0 is valid and means "I support it")
	opts = append(opts, WScaleOption(c.rcvWndShift))
	if c.sackEnabled {
		opts = append(opts, SACKPermOption())
	}
	if c.tsEnabled {
		opts = append(opts, TimestampOption(c.tsNow(), 0))
	}
	return opts
}

func (c *Conn) tsNow() uint32 {
	// Monotonic millisecond timestamp
	return uint32(time.Now().UnixMilli()) - c.tsOffset
}

// --- Active open ---

// Connect initiates a TCP handshake (active open).
// Sends SYN and blocks until the handshake completes or ctx is cancelled.
func (c *Conn) Connect(ctx context.Context) error {
	c.mu.Lock()
	if c.state != StateClosed {
		c.mu.Unlock()
		return errors.New("connection not in CLOSED state")
	}

	// Initialize sequence number
	iss := randUint32()
	c.sendBuf = NewSendBuf(c.sendBufSize(), iss)
	c.recvBuf = NewRecvBuf(0, c.recvBufCap) // RCV.NXT set when SYN-ACK arrives

	c.state = StateSynSent

	// Build SYN
	syn := Segment{
		SrcPort: c.localPort,
		DstPort: c.remotePort,
		Seq:     iss,
		Flags:   FlagSYN,
		Window:  c.rcvWindow(),
		Options: c.buildSYNOptions(),
	}
	c.queueSeg(syn)
	c.sendBuf.AdvanceSent(1) // SYN consumes 1 seq

	c.rto.StartTiming(iss)
	c.startRTO()

	pkts := c.drainOutgoing()
	c.mu.Unlock()
	c.flushPackets(pkts)

	// Wait for handshake
	select {
	case <-c.established:
		return nil
	case <-ctx.Done():
		c.Abort()
		return ctx.Err()
	}
}

func (c *Conn) sendBufSize() int {
	// Check if we have a configured size
	if c.sendBuf != nil {
		return c.sendBuf.cap
	}
	return DefaultSendBuf
}

// --- Passive open ---

// AcceptSYN processes an incoming SYN for passive open.
// Sets up connection state, queues a SYN-ACK, and returns packets to send.
func (c *Conn) AcceptSYN(syn Segment) [][]byte {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.state != StateClosed && c.state != StateListen {
		return nil
	}

	// Parse SYN options
	if mss := GetMSS(syn.Options); mss > 0 && int(mss) < c.mss {
		c.mss = int(mss)
	}
	c.negotiateOptions(syn.Options)

	// Initialize sequence numbers
	iss := randUint32()
	c.sendBuf = NewSendBuf(DefaultSendBuf, iss)
	c.recvBuf = NewRecvBuf(syn.Seq+1, c.recvBufCap) // SYN consumed 1 seq

	c.state = StateSynReceived

	// Build SYN-ACK
	synack := Segment{
		SrcPort: c.localPort,
		DstPort: c.remotePort,
		Seq:     iss,
		Ack:     c.recvBuf.Nxt(),
		Flags:   FlagSYN | FlagACK,
		Window:  c.rcvWindow(),
		Options: c.buildSYNOptions(),
	}
	c.queueSeg(synack)
	c.sendBuf.AdvanceSent(1) // SYN consumes 1 seq

	// Fix 7A: buffer any data in the SYN (RFC 9293 §3.10.7.2)
	if len(syn.Payload) > 0 {
		c.recvBuf.Insert(syn.Seq+1, syn.Payload)
	}

	c.startRTO()

	return c.drainOutgoing()
}

func (c *Conn) negotiateOptions(remoteOpts []Option) {
	// Window scaling: enabled if both sides offered WScale in their SYN.
	// We always offer it unless NoWindowScaling was set (rcvWndShift stays 0
	// but we still send WScale(0) in the SYN options).
	if ws := GetWScale(remoteOpts); ws >= 0 {
		c.sndWndShift = uint8(ws)
		c.wscaleOK = true
	}
	// SACK
	if c.sackEnabled && HasSACKPerm(remoteOpts) {
		c.sackOK = true
	}
	// Timestamps
	if c.tsEnabled {
		if tsVal, _, ok := GetTimestamp(remoteOpts); ok {
			c.tsRecent = tsVal
		}
	}
}

// --- Segment validation (RFC 9293 §3.10.7.4) ---

// segmentAcceptable implements RFC 9293 Table 5.
// Must hold c.mu. Requires c.recvBuf to be initialized.
func (c *Conn) segmentAcceptable(seg Segment) bool {
	if c.recvBuf == nil {
		return true // no recv state yet (pre-handshake)
	}
	c.recvMu.Lock()
	rcvNxt := c.recvBuf.Nxt()
	c.recvMu.Unlock()
	// Use the full buffer capacity as the acceptance window.
	// The advertised window (rcvWindow) controls sender rate;
	// the acceptability window should be as large as possible
	// to avoid dropping useful out-of-order data.
	rcvWnd := uint32(c.recvBufCap)
	if rcvWnd == 0 {
		rcvWnd = DefaultRecvBuf
	}
	segLen := seg.SegLen()

	if segLen == 0 {
		if rcvWnd == 0 {
			return seg.Seq == rcvNxt
		}
		return SeqInRange(seg.Seq, rcvNxt, rcvNxt+rcvWnd)
	}
	// segLen > 0
	if rcvWnd == 0 {
		return false // not acceptable
	}
	segEnd := seg.Seq + segLen - 1
	return SeqInRange(seg.Seq, rcvNxt, rcvNxt+rcvWnd) ||
		SeqInRange(segEnd, rcvNxt, rcvNxt+rcvWnd)
}

// validateRST implements RFC 9293 §3.10.7.4 second check + RFC 5961.
// Returns true if the RST should be accepted. Must hold c.mu.
func (c *Conn) validateRST(seg Segment) (accept bool, challengeACK bool) {
	switch c.state {
	case StateSynSent:
		// In SYN-SENT: RST valid only if ACK present and SEG.ACK == SND.NXT
		if seg.HasFlag(FlagACK) && seg.Ack == c.sendBuf.NXT() {
			return true, false
		}
		return false, false
	default:
		// RFC 5961 §3.2: RST is valid only if SEG.SEQ == RCV.NXT exactly.
		// If in-window but not exact, send challenge ACK.
		if c.recvBuf == nil {
			return true, false
		}
		rcvNxt := c.recvBuf.Nxt()
		if seg.Seq == rcvNxt {
			return true, false
		}
		rcvWnd := c.recvBuf.Window()
		if SeqInRange(seg.Seq, rcvNxt, rcvNxt+rcvWnd) {
			return false, true // in-window but not exact → challenge ACK
		}
		return false, false // out of window → ignore
	}
}

// --- Network-side I/O ---

// HandleSegment processes an incoming TCP segment following RFC 9293 §3.10.7.4.
// Returns packets to send in response. The caller MUST send these.
func (c *Conn) HandleSegment(seg Segment) [][]byte {
	c.mu.Lock()

	c.lastRecv = time.Now()
	c.keepaliveSent = 0

	var pkts [][]byte

	switch c.state {
	case StateClosed:
		// Fix 7B: RST for segments arriving at CLOSED (RFC 9293 §3.10.7.1)
		pkts = c.handleClosed(seg)

	case StateSynSent:
		// SYN-SENT has its own processing order (RFC 9293 §3.10.7.2)
		pkts = c.handleSynSent(seg)

	case StateSynReceived, StateEstablished, StateFinWait1, StateFinWait2,
		StateCloseWait, StateClosing, StateLastAck, StateTimeWait:
		// All synchronized states follow RFC 9293 §3.10.7.4 check order:
		// 1. Sequence number check
		// 2. RST check
		// 3. (Security — skipped)
		// 4. SYN check
		// 5. ACK check
		// 6-8. Process data, FIN, etc.
		pkts = c.handleSynchronized(seg)
	}

	c.mu.Unlock()
	return pkts
}

// handleClosed generates RST for segments arriving at a CLOSED connection.
// RFC 9293 §3.10.7.1.
func (c *Conn) handleClosed(seg Segment) [][]byte {
	if seg.HasFlag(FlagRST) {
		return nil // ignore RST to CLOSED
	}
	if seg.HasFlag(FlagACK) {
		// RST with SEQ = SEG.ACK
		rst := Segment{
			SrcPort: c.localPort,
			DstPort: c.remotePort,
			Seq:     seg.Ack,
			Flags:   FlagRST,
		}
		c.queueSeg(rst)
	} else {
		// RST+ACK with SEQ=0, ACK = SEG.SEQ + SEG.LEN
		rst := Segment{
			SrcPort: c.localPort,
			DstPort: c.remotePort,
			Seq:     0,
			Ack:     seg.Seq + seg.SegLen(),
			Flags:   FlagRST | FlagACK,
		}
		c.queueSeg(rst)
	}
	return c.drainOutgoing()
}

// handleSynchronized implements RFC 9293 §3.10.7.4 for all synchronized states.
func (c *Conn) handleSynchronized(seg Segment) [][]byte {
	// --- First check: sequence number (RFC 9293 §3.10.7.4 step 1) ---
	if !c.segmentAcceptable(seg) {
		// Special case: in SYN-RECEIVED during simultaneous open, the peer's
		// SYN-ACK retransmits the SYN (SEQ == RCV.NXT-1). Accept if ACK is valid.
		synRcvdOK := c.state == StateSynReceived && seg.HasFlag(FlagSYN) &&
			seg.HasFlag(FlagACK) && seg.Ack == c.sendBuf.NXT()
		if !synRcvdOK {
			if !seg.HasFlag(FlagRST) {
				c.queueACK()
			}
			return c.drainOutgoing()
		}
	}

	// --- Second check: RST (RFC 9293 §3.10.7.4 step 2 + RFC 5961) ---
	if seg.HasFlag(FlagRST) {
		accept, challenge := c.validateRST(seg)
		if challenge {
			c.queueACK() // challenge ACK per RFC 5961
			return c.drainOutgoing()
		}
		if !accept {
			return c.drainOutgoing() // silently ignore
		}
		// Valid RST — tear down
		c.state = StateClosed
		c.closed.Store(true)
		c.stopRTO()
		c.stopPersist()
		c.stopKeepalive()
		c.stopPersist()
		c.recvCond.Broadcast()
		c.sendCond.Broadcast()
		c.safeCloseEstablished()
		c.safeCloseFinRecvd()
		return c.drainOutgoing()
	}

	// --- Third check: security/precedence — skipped ---

	// --- Fourth check: SYN (RFC 9293 §3.10.7.4 step 4 + RFC 5961 §4) ---
	if seg.HasFlag(FlagSYN) && c.state != StateSynReceived {
		// SYN in a synchronized state (other than SYN-RECEIVED) is an error.
		// Per RFC 5961 §4, send a challenge ACK (mitigates blind SYN attacks).
		// SYN-RECEIVED is exempt because simultaneous open sends SYN-ACK here.
		c.queueACK()
		return c.drainOutgoing()
	}

	// --- Fifth check: ACK required (RFC 9293 §3.10.7.4 step 5) ---
	if !seg.HasFlag(FlagACK) {
		// Drop segment without ACK (except RST, already handled above)
		return c.drainOutgoing()
	}

	// --- Dispatch to per-state handler for ACK/data/FIN processing ---
	switch c.state {
	case StateSynReceived:
		return c.handleSynReceived(seg)
	case StateEstablished:
		return c.handleEstablished(seg)
	case StateFinWait1:
		return c.handleFinWait1(seg)
	case StateFinWait2:
		return c.handleFinWait2(seg)
	case StateCloseWait:
		return c.handleCloseWait(seg)
	case StateClosing:
		return c.handleClosing(seg)
	case StateLastAck:
		return c.handleLastAck(seg)
	case StateTimeWait:
		c.queueACK()
		return c.drainOutgoing()
	}
	return c.drainOutgoing()
}

// --- State handlers ---

// handleSynSent implements RFC 9293 §3.10.7.2 (SYN-SENT state processing).
// Handles SYN-ACK (normal), bare SYN (simultaneous open), and RST.
func (c *Conn) handleSynSent(seg Segment) [][]byte {
	// RFC 9293 §3.10.7.2 step 1: check ACK
	if seg.HasFlag(FlagACK) {
		if SeqBeforeEq(seg.Ack, c.sendBuf.UNA()) || SeqAfter(seg.Ack, c.sendBuf.NXT()) {
			// Unacceptable ACK
			if !seg.HasFlag(FlagRST) {
				// Send RST with SEQ = SEG.ACK
				rst := Segment{SrcPort: c.localPort, DstPort: c.remotePort, Seq: seg.Ack, Flags: FlagRST}
				c.queueSeg(rst)
			}
			return c.drainOutgoing()
		}
	}

	// RFC 9293 §3.10.7.2 step 2: check RST
	if seg.HasFlag(FlagRST) {
		if seg.HasFlag(FlagACK) {
			// ACK was acceptable (checked above), RST is valid
			c.state = StateClosed
			c.closed.Store(true)
			c.stopRTO()
			c.safeCloseEstablished()
			c.safeCloseFinRecvd()
		}
		// No ACK → ignore RST
		return c.drainOutgoing()
	}

	// RFC 9293 §3.10.7.2 step 3: check SYN
	if !seg.HasFlag(FlagSYN) {
		return c.drainOutgoing() // no SYN → drop
	}

	// SYN is set. Negotiate options.
	if mss := GetMSS(seg.Options); mss > 0 && int(mss) < c.mss {
		c.mss = int(mss)
	}
	c.negotiateOptions(seg.Options)

	if seg.HasFlag(FlagACK) {
		// SYN-ACK: normal active open completion
		c.sendBuf.Acknowledge(seg.Ack)
		c.retries = 0
		c.stopRTO()

		c.recvBuf = NewRecvBuf(seg.Seq+1, c.recvBufCap)
		c.sndWnd = uint32(seg.Window) << c.sndWndShift
		c.cc = NewHighSpeed(uint32(c.mss))
		c.rto.AckReceived(seg.Ack)
		c.state = StateEstablished

		// Fix 7A: buffer any data in the SYN-ACK
		if len(seg.Payload) > 0 {
			c.recvMu.Lock()
			c.recvBuf.Insert(seg.Seq+1, seg.Payload)
			c.recvMu.Unlock()
			c.recvCond.Broadcast()
		}

		c.queueACK()
		c.flushSendQueue()
		if c.keepalive {
			c.startKeepalive()
		}
		pkts := c.drainOutgoing()
		c.safeCloseEstablished()
		return pkts
	}

	// Fix 5: Bare SYN without ACK — simultaneous open (RFC 9293 §3.10.7.2)
	c.recvBuf = NewRecvBuf(seg.Seq+1, c.recvBufCap)
	c.sndWnd = uint32(seg.Window) << c.sndWndShift
	c.state = StateSynReceived
	c.retries = 0
	c.stopRTO()

	// Buffer any data in the SYN
	if len(seg.Payload) > 0 {
		c.recvMu.Lock()
		c.recvBuf.Insert(seg.Seq+1, seg.Payload)
		c.recvMu.Unlock()
	}

	// Send SYN-ACK (our ISN is already in sendBuf.UNA)
	synack := Segment{
		SrcPort: c.localPort,
		DstPort: c.remotePort,
		Seq:     c.sendBuf.UNA(),
		Ack:     c.recvBuf.Nxt(),
		Flags:   FlagSYN | FlagACK,
		Window:  c.rcvWindow(),
		Options: c.buildSYNOptions(),
	}
	c.queueSeg(synack)
	c.startRTO()
	return c.drainOutgoing()
}

func (c *Conn) handleSynReceived(seg Segment) [][]byte {
	// ACK flag is guaranteed by handleSynchronized (fifth check).
	if seg.Ack != c.sendBuf.NXT() {
		// Bad ACK: send RST with SEQ = SEG.ACK (RFC 9293 §3.10.7.4)
		rst := Segment{SrcPort: c.localPort, DstPort: c.remotePort, Seq: seg.Ack, Flags: FlagRST}
		c.queueSeg(rst)
		return c.drainOutgoing()
	}

	c.sendBuf.Acknowledge(seg.Ack)
	c.retries = 0
	c.stopRTO()
	c.sndWnd = uint32(seg.Window) << c.sndWndShift

	c.state = StateEstablished

	if c.keepalive {
		c.startKeepalive()
	}

	c.safeCloseEstablished()

	// Process any data in this ACK segment
	if len(seg.Payload) > 0 {
		c.processData(seg)
	}

	return c.drainOutgoing()
}

func (c *Conn) handleEstablished(seg Segment) [][]byte {
	return c.handleDataState(seg)
}

func (c *Conn) handleDataState(seg Segment) [][]byte {
	needACK := false

	// Process ACK
	if seg.HasFlag(FlagACK) {
		c.processACK(seg.Ack)
		c.sndWnd = uint32(seg.Window) << c.sndWndShift
	}

	// Process data
	if len(seg.Payload) > 0 {
		c.processData(seg)
		needACK = true
	}

	// Process FIN
	if seg.HasFlag(FlagFIN) {
		c.recvMu.Lock()
		finSeq := seg.Seq + seg.DataLen()
		if finSeq == c.recvBuf.Nxt() {
			c.recvBuf.nxt++
		}
		c.recvMu.Unlock()
		needACK = true

		switch c.state {
		case StateEstablished:
			c.state = StateCloseWait
			c.safeCloseFinRecvd()
		case StateFinWait1:
			if seg.HasFlag(FlagACK) && seg.Ack == c.sendBuf.NXT() {
				// Simultaneous FIN+ACK of our FIN
				c.state = StateTimeWait
				c.stopRTO()
				c.startTimeWait()
			} else {
				c.state = StateClosing
			}
			c.safeCloseFinRecvd()
		case StateFinWait2:
			c.state = StateTimeWait
			c.stopRTO()
			c.startTimeWait()
			c.safeCloseFinRecvd()
		}
	} else if c.state == StateFinWait1 && seg.HasFlag(FlagACK) && seg.Ack == c.sendBuf.NXT() {
		c.state = StateFinWait2
	}

	if needACK {
		c.queueACK()
	}

	return c.drainOutgoing()
}

func (c *Conn) handleFinWait1(seg Segment) [][]byte {
	return c.handleDataState(seg)
}

func (c *Conn) handleFinWait2(seg Segment) [][]byte {
	return c.handleDataState(seg)
}

func (c *Conn) handleCloseWait(seg Segment) [][]byte {
	// Only process ACKs (for data we're still sending)
	if seg.HasFlag(FlagACK) {
		c.processACK(seg.Ack)
	}
	return c.drainOutgoing()
}

func (c *Conn) handleClosing(seg Segment) [][]byte {
	// Waiting for ACK of our FIN
	if seg.HasFlag(FlagACK) && seg.Ack == c.sendBuf.NXT() {
		c.state = StateTimeWait
		c.stopRTO()
		c.startTimeWait()
	}
	return c.drainOutgoing()
}

func (c *Conn) handleLastAck(seg Segment) [][]byte {
	if seg.HasFlag(FlagACK) && seg.Ack == c.sendBuf.NXT() {
		c.state = StateClosed
		c.closed.Store(true)
		c.stopRTO()
		c.stopKeepalive()
		c.stopPersist()
		c.recvCond.Broadcast()
		c.sendCond.Broadcast()
	}
	return c.drainOutgoing()
}

// --- Data processing ---

func (c *Conn) processData(seg Segment) {
	c.recvMu.Lock()
	n := c.recvBuf.Insert(seg.Seq, seg.Payload)
	c.recvMu.Unlock()
	if n > 0 {
		c.recvCond.Broadcast()
	}
}

func (c *Conn) processACK(ack uint32) {
	if !SeqAfter(ack, c.sendBuf.UNA()) {
		// Duplicate ACK
		if c.cc.OnDupACK() {
			// Fast retransmit
			c.cc.OnFastRetransmit(uint32(c.sendBuf.Unacked()))
			c.retransmit()
		}
		return
	}
	if SeqAfter(ack, c.sendBuf.NXT()) {
		return // ACK beyond what we've sent
	}

	acked := c.sendBuf.Acknowledge(ack)
	c.retries = 0
	c.cc.OnACK(acked)

	// Stop persist timer if window has opened
	if c.sndWnd > 0 && c.persistTimer != nil {
		c.stopPersist()
	}

	// RTT sample (Karn's: only for non-retransmitted)
	c.rto.AckReceived(ack)

	// Check if we're exiting fast recovery
	if c.cc.InRecovery() && SeqAfterEq(ack, c.sendBuf.NXT()) {
		c.cc.ExitRecovery()
	}

	// Restart/stop RTO
	if c.sendBuf.Unacked() > 0 {
		c.startRTO()
	} else {
		c.stopRTO()
	}

	// Try to send more data
	c.flushSendQueue()

	c.sendCond.Broadcast()
}

func (c *Conn) retransmit() {
	data := c.sendBuf.RetransmitData(c.mss)
	if len(data) == 0 {
		return
	}
	seg := Segment{
		SrcPort: c.localPort,
		DstPort: c.remotePort,
		Seq:     c.sendBuf.UNA(),
		Ack:     c.recvBuf.Nxt(),
		Flags:   FlagACK | FlagPSH,
		Window:  c.rcvWindow(),
		Payload: data,
	}
	c.queueSeg(seg)
	c.rto.InvalidateTiming() // Karn's algorithm
	c.startRTO()
}

// flushSendQueue sends queued data respecting both remote window and cwnd.
func (c *Conn) flushSendQueue() {
	for c.sendBuf.Pending() > 0 {
		// Effective window = min(sndWnd, cwnd) - unacked
		effWnd := c.sndWnd
		if ccWnd := c.cc.SendWindow(); ccWnd < effWnd {
			effWnd = ccWnd
		}
		avail := int(effWnd) - c.sendBuf.Unacked()
		if avail <= 0 {
			break
		}

		n := min(avail, c.mss, c.sendBuf.Pending())
		data := c.sendBuf.PeekUnsent(n)
		if len(data) == 0 {
			break
		}

		seg := Segment{
			SrcPort: c.localPort,
			DstPort: c.remotePort,
			Seq:     c.sendBuf.NXT(),
			Ack:     c.recvBuf.Nxt(),
			Flags:   FlagACK | FlagPSH,
			Window:  c.rcvWindow(),
			Payload: data,
		}
		c.queueSeg(seg)
		c.sendBuf.AdvanceSent(len(data))

		c.rto.StartTiming(seg.Seq)

		if c.sendBuf.Unacked() > 0 && c.rtoTimer == nil {
			c.startRTO()
		}
	}

	// Fix 6: Start persist timer if window is zero and data is pending
	// (RFC 9293 §3.7.7 — zero-window probing)
	if c.sendBuf.Pending() > 0 && c.sndWnd == 0 && c.persistTimer == nil {
		c.startPersist()
	}
}

func (c *Conn) queueACK() {
	seg := Segment{
		SrcPort: c.localPort,
		DstPort: c.remotePort,
		Seq:     c.sendBuf.NXT(),
		Ack:     c.recvBuf.Nxt(),
		Flags:   FlagACK,
		Window:  c.rcvWindow(),
	}
	c.queueSeg(seg)
}

// --- Timer management ---

func (c *Conn) startRTO() {
	c.stopRTO()
	rto := c.rto.RTO()
	c.rtoTimer = time.AfterFunc(rto, c.onRTOTimeout)
}

func (c *Conn) stopRTO() {
	if c.rtoTimer != nil {
		c.rtoTimer.Stop()
		c.rtoTimer = nil
	}
}

// --- Persist timer (RFC 9293 §3.7.7) ---

func (c *Conn) startPersist() {
	c.stopPersist()
	if c.persistBackoff == 0 {
		c.persistBackoff = c.rto.RTO()
	}
	c.persistTimer = time.AfterFunc(c.persistBackoff, c.onPersistTimeout)
}

func (c *Conn) stopPersist() {
	if c.persistTimer != nil {
		c.persistTimer.Stop()
		c.persistTimer = nil
	}
	c.persistBackoff = 0
}

func (c *Conn) onPersistTimeout() {
	c.mu.Lock()
	if c.closed.Load() || c.state == StateClosed {
		c.mu.Unlock()
		return
	}

	// If window opened, stop persisting and flush normally
	if c.sndWnd > 0 {
		c.stopPersist()
		c.flushSendQueue()
		pkts := c.drainOutgoing()
		c.mu.Unlock()
		c.flushPackets(pkts)
		return
	}

	// Window still zero: send a 1-byte window probe
	if c.sendBuf.Pending() > 0 {
		data := c.sendBuf.PeekUnsent(1)
		if len(data) > 0 {
			seg := Segment{
				SrcPort: c.localPort,
				DstPort: c.remotePort,
				Seq:     c.sendBuf.NXT(),
				Ack:     c.recvBuf.Nxt(),
				Flags:   FlagACK,
				Window:  c.rcvWindow(),
				Payload: data,
			}
			c.queueSeg(seg)
			c.sendBuf.AdvanceSent(len(data))
		}
	}

	// Exponential backoff, capped at 60s
	c.persistBackoff *= 2
	if c.persistBackoff > MaxRTO {
		c.persistBackoff = MaxRTO
	}
	c.persistTimer = time.AfterFunc(c.persistBackoff, c.onPersistTimeout)

	pkts := c.drainOutgoing()
	c.mu.Unlock()
	c.flushPackets(pkts)
}

// --- RTO timer ---

func (c *Conn) onRTOTimeout() {
	c.mu.Lock()
	if c.closed.Load() || c.state == StateClosed {
		c.mu.Unlock()
		return
	}

	c.retries++
	if c.retries > MaxRetries {
		c.state = StateClosed
		c.closed.Store(true)
		c.stopRTO()
		c.stopKeepalive()
		c.stopPersist()
		c.mu.Unlock()
		c.recvCond.Broadcast()
		c.sendCond.Broadcast()
		c.safeCloseEstablished()
		return
	}

	c.rto.Backoff()
	c.rto.InvalidateTiming() // Karn's algorithm
	c.cc.OnTimeout()

	switch c.state {
	case StateSynSent:
		// Retransmit SYN
		syn := Segment{
			SrcPort: c.localPort,
			DstPort: c.remotePort,
			Seq:     c.sendBuf.UNA(),
			Flags:   FlagSYN,
			Window:  c.rcvWindow(),
			Options: c.buildSYNOptions(),
		}
		c.queueSeg(syn)

	case StateSynReceived:
		// Retransmit SYN-ACK
		synack := Segment{
			SrcPort: c.localPort,
			DstPort: c.remotePort,
			Seq:     c.sendBuf.UNA(),
			Ack:     c.recvBuf.Nxt(),
			Flags:   FlagSYN | FlagACK,
			Window:  c.rcvWindow(),
			Options: c.buildSYNOptions(),
		}
		c.queueSeg(synack)

	case StateEstablished, StateCloseWait:
		c.retransmit()

	case StateFinWait1, StateLastAck:
		// Retransmit FIN
		c.queueFIN()
	}

	c.startRTO()
	pkts := c.drainOutgoing()
	c.mu.Unlock()
	c.flushPackets(pkts)
}

func (c *Conn) startTimeWait() {
	time.AfterFunc(TimeWaitDuration, func() {
		c.mu.Lock()
		c.state = StateClosed
		c.closed.Store(true)
		c.stopKeepalive()
		c.stopPersist()
		c.mu.Unlock()
		c.recvCond.Broadcast()
		c.sendCond.Broadcast()
	})
}

// --- Keepalive ---

func (c *Conn) startKeepalive() {
	c.stopKeepalive()
	c.stopPersist()
	c.keepaliveTimer = time.AfterFunc(c.keepaliveIntv, c.onKeepalive)
}

func (c *Conn) stopKeepalive() {
	if c.keepaliveTimer != nil {
		c.keepaliveTimer.Stop()
		c.keepaliveTimer = nil
	}
}

func (c *Conn) onKeepalive() {
	c.mu.Lock()
	if c.closed.Load() || c.state == StateClosed {
		c.mu.Unlock()
		return
	}
	if c.state != StateEstablished && c.state != StateCloseWait {
		c.mu.Unlock()
		return
	}

	if time.Since(c.lastRecv) > c.keepaliveIdle {
		if c.keepaliveSent >= c.keepaliveMax {
			// Abort
			c.state = StateClosed
			c.closed.Store(true)
			c.stopRTO()
			c.mu.Unlock()
			c.recvCond.Broadcast()
			c.sendCond.Broadcast()
			c.safeCloseEstablished()
			c.safeCloseFinRecvd()
			return
		}
		// Send keepalive probe (ACK with seq-1)
		seg := Segment{
			SrcPort: c.localPort,
			DstPort: c.remotePort,
			Seq:     c.sendBuf.NXT() - 1,
			Ack:     c.recvBuf.Nxt(),
			Flags:   FlagACK,
			Window:  c.rcvWindow(),
		}
		c.queueSeg(seg)
		c.keepaliveSent++
	}

	c.startKeepalive()
	pkts := c.drainOutgoing()
	c.mu.Unlock()
	c.flushPackets(pkts)
}

// --- Application-side I/O (net.Conn) ---

func (c *Conn) Read(b []byte) (int, error) {
	c.recvMu.Lock()
	defer c.recvMu.Unlock()

	for c.recvBuf == nil || c.recvBuf.Readable() == 0 {
		if c.closed.Load() {
			return 0, io.EOF
		}
		select {
		case <-c.finRecvd:
			return 0, io.EOF
		default:
		}

		if dl, ok := c.readDeadline.Load().(time.Time); ok && !dl.IsZero() {
			if time.Now().After(dl) {
				return 0, &net.OpError{Op: "read", Err: errors.New("i/o timeout")}
			}
			timer := time.AfterFunc(time.Until(dl), func() { c.recvCond.Broadcast() })
			c.recvCond.Wait()
			timer.Stop()
		} else {
			c.recvCond.Wait()
		}
	}

	n := c.recvBuf.Read(b)
	return n, nil
}

func (c *Conn) Write(b []byte) (int, error) {
	if c.closed.Load() {
		return 0, errors.New("connection closed")
	}

	c.mu.Lock()
	if c.state != StateEstablished && c.state != StateCloseWait {
		c.mu.Unlock()
		return 0, errors.New("connection not established")
	}

	written := 0
	for written < len(b) {
		n := c.sendBuf.Write(b[written:])
		if n == 0 {
			// Buffer full, wait for ACKs to drain it
			c.sendCond.Wait()
			if c.closed.Load() {
				c.mu.Unlock()
				return written, errors.New("connection closed")
			}
			continue
		}
		written += n
	}

	c.flushSendQueue()
	pkts := c.drainOutgoing()
	c.mu.Unlock()

	c.flushPackets(pkts)
	return written, nil
}

func (c *Conn) Close() error {
	if c.closed.Load() {
		return nil
	}

	c.mu.Lock()
	var pkts [][]byte
	switch c.state {
	case StateEstablished:
		c.flushSendQueue()
		c.state = StateFinWait1
		c.queueFIN()
		c.startRTO()
		pkts = c.drainOutgoing()
	case StateCloseWait:
		c.state = StateLastAck
		c.queueFIN()
		c.startRTO()
		pkts = c.drainOutgoing()
	case StateSynSent, StateSynReceived:
		c.state = StateClosed
		c.closed.Store(true)
		c.stopRTO()
		c.stopKeepalive()
		c.stopPersist()
	default:
		c.closed.Store(true)
		c.state = StateClosed
		c.stopRTO()
		c.stopKeepalive()
		c.stopPersist()
	}
	c.mu.Unlock()

	c.flushPackets(pkts)
	c.recvCond.Broadcast()
	c.sendCond.Broadcast()
	return nil
}

func (c *Conn) queueFIN() {
	seg := Segment{
		SrcPort: c.localPort,
		DstPort: c.remotePort,
		Seq:     c.sendBuf.NXT(),
		Ack:     c.recvBuf.Nxt(),
		Flags:   FlagFIN | FlagACK,
		Window:  c.rcvWindow(),
	}
	c.queueSeg(seg)
	c.sendBuf.AdvanceSent(1) // FIN consumes 1 seq
}

// Abort immediately tears down the connection.
func (c *Conn) Abort() [][]byte {
	c.mu.Lock()
	if c.state == StateClosed {
		c.mu.Unlock()
		return nil
	}
	wasEstablished := c.state != StateClosed && c.state != StateSynSent
	c.state = StateClosed
	c.closed.Store(true)
	c.stopRTO()
	c.stopKeepalive()
	c.stopPersist()

	var pkts [][]byte
	if wasEstablished && c.sendBuf != nil && c.recvBuf != nil {
		seg := Segment{
			SrcPort: c.localPort,
			DstPort: c.remotePort,
			Seq:     c.sendBuf.NXT(),
			Flags:   FlagRST,
		}
		c.queueSeg(seg)
		pkts = c.drainOutgoing()
	}
	c.mu.Unlock()

	c.recvCond.Broadcast()
	c.sendCond.Broadcast()
	c.safeCloseEstablished()
	c.safeCloseFinRecvd()

	return pkts
}

// --- net.Conn interface ---

func (c *Conn) LocalAddr() net.Addr   { return c.localAddr }
func (c *Conn) RemoteAddr() net.Addr  { return c.remoteAddr }
func (c *Conn) Writer() SegmentWriter { return c.writer }

// SetupForHandshake puts the connection into SYN-SENT state with the given ISN,
// allowing HandleSegment to process a SYN-ACK. This is used for manual handshake
// in tests where Connect() can't be used (synchronous delivery).
func (c *Conn) SetupForHandshake(iss uint32) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sendBuf = NewSendBuf(c.recvBufSize(), iss)
	c.recvBuf = NewRecvBuf(0, c.recvBufCap)
	c.state = StateSynSent
	c.sendBuf.AdvanceSent(1) // SYN consumes 1 seq
}

func (c *Conn) SetDeadline(t time.Time) error {
	c.readDeadline.Store(t)
	c.writeDeadline.Store(t)
	c.recvCond.Broadcast()
	return nil
}

func (c *Conn) SetReadDeadline(t time.Time) error {
	c.readDeadline.Store(t)
	c.recvCond.Broadcast()
	return nil
}

func (c *Conn) SetWriteDeadline(t time.Time) error {
	c.writeDeadline.Store(t)
	return nil
}

// --- Lifecycle helpers ---

func (c *Conn) safeCloseEstablished() {
	c.establishedOnce.Do(func() { close(c.established) })
}

func (c *Conn) safeCloseFinRecvd() {
	c.finRecvdOnce.Do(func() {
		close(c.finRecvd)
		c.recvCond.Broadcast()
	})
}

func min(vals ...int) int {
	m := vals[0]
	for _, v := range vals[1:] {
		if v < m {
			m = v
		}
	}
	return m
}
