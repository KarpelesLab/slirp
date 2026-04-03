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
	EnableWindowScaling bool
	WindowScale         uint8 // 0-14
	EnableTimestamps    bool

	// RFC 2018
	EnableSACK bool

	// RFC 1122 keepalive
	Keepalive         bool
	KeepaliveIdle     time.Duration
	KeepaliveInterval time.Duration
	KeepaliveCount    int

	SendBufSize int
	RecvBufSize int
}

func (cfg *ConnConfig) mss() int {
	if cfg.MSS > 0 {
		return cfg.MSS
	}
	return DefaultMSS
}

func (cfg *ConnConfig) sendBufSize() int {
	if cfg.SendBufSize > 0 {
		return cfg.SendBufSize
	}
	return DefaultSendBuf
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
	recvMu  sync.Mutex
	recvBuf *RecvBuf
	recvCond *sync.Cond

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
	c := &Conn{
		localPort:  cfg.LocalPort,
		remotePort: cfg.RemotePort,
		localAddr:  cfg.LocalAddr,
		remoteAddr: cfg.RemoteAddr,
		writer:     cfg.Writer,
		state:      StateClosed,
		mss:        cfg.mss(),
		sndWnd:     DefaultWindowSize,
		cc:         NewNewReno(uint32(cfg.mss())),
		rto:        NewRTOCalculator(),
		lastRecv:   time.Now(),
		established: make(chan struct{}),
		finRecvd:    make(chan struct{}),

		// Options config (negotiated during handshake)
		rcvWndShift: cfg.WindowScale,
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

func (c *Conn) makeSegment(flags uint8, payload []byte) Segment {
	seg := Segment{
		SrcPort: c.localPort,
		DstPort: c.remotePort,
		Seq:     c.sendBuf.NXT(),
		Flags:   flags,
		Window:  c.rcvWindow(),
	}
	if flags&FlagACK != 0 {
		seg.Ack = c.recvBuf.Nxt()
	}
	if len(payload) > 0 {
		seg.Payload = payload
	}
	return seg
}

func (c *Conn) rcvWindow() uint16 {
	// TODO: implement window scaling (shift rcvWndShift)
	return DefaultWindowSize
}

func (c *Conn) buildSYNOptions() []Option {
	opts := []Option{MSSOption(uint16(c.mss))}
	if c.rcvWndShift > 0 {
		opts = append(opts, WScaleOption(c.rcvWndShift))
	}
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
	c.recvBuf = NewRecvBuf(0) // RCV.NXT set when SYN-ACK arrives

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
	c.recvBuf = NewRecvBuf(syn.Seq + 1) // SYN consumed 1 seq

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

	c.startRTO()

	return c.drainOutgoing()
}

func (c *Conn) negotiateOptions(remoteOpts []Option) {
	// Window scaling
	if c.rcvWndShift > 0 {
		if ws := GetWScale(remoteOpts); ws >= 0 {
			c.sndWndShift = uint8(ws)
			c.wscaleOK = true
		}
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

// --- Network-side I/O ---

// HandleSegment processes an incoming TCP segment.
// Returns packets to send in response. The caller MUST send these.
func (c *Conn) HandleSegment(seg Segment) [][]byte {
	c.mu.Lock()

	c.lastRecv = time.Now()
	c.keepaliveSent = 0

	// RST: tear down immediately
	if seg.HasFlag(FlagRST) {
		c.state = StateClosed
		c.closed.Store(true)
		c.stopRTO()
		c.stopKeepalive()
		c.mu.Unlock()
		c.recvCond.Broadcast()
		c.sendCond.Broadcast()
		c.safeCloseEstablished()
		c.safeCloseFinRecvd()
		return nil
	}

	var pkts [][]byte

	switch c.state {
	case StateSynSent:
		pkts = c.handleSynSent(seg)
	case StateSynReceived:
		pkts = c.handleSynReceived(seg)
	case StateEstablished:
		pkts = c.handleEstablished(seg)
	case StateFinWait1:
		pkts = c.handleFinWait1(seg)
	case StateFinWait2:
		pkts = c.handleFinWait2(seg)
	case StateCloseWait:
		pkts = c.handleCloseWait(seg)
	case StateClosing:
		pkts = c.handleClosing(seg)
	case StateLastAck:
		pkts = c.handleLastAck(seg)
	case StateTimeWait:
		// In TIME-WAIT, respond to any segment with ACK
		c.queueACK()
		pkts = c.drainOutgoing()
	}

	c.mu.Unlock()
	return pkts
}

// --- State handlers ---

func (c *Conn) handleSynSent(seg Segment) [][]byte {
	// Expect SYN-ACK
	if !seg.HasFlag(FlagSYN) || !seg.HasFlag(FlagACK) {
		return c.drainOutgoing()
	}
	if seg.Ack != c.sendBuf.NXT() {
		return c.drainOutgoing()
	}

	// ACK our SYN
	c.sendBuf.Acknowledge(seg.Ack)
	c.retries = 0
	c.stopRTO()

	// Parse options from SYN-ACK
	if mss := GetMSS(seg.Options); mss > 0 && int(mss) < c.mss {
		c.mss = int(mss)
	}
	c.negotiateOptions(seg.Options)

	// Set receive state
	c.recvBuf = NewRecvBuf(seg.Seq + 1) // SYN consumes 1 seq
	c.sndWnd = uint32(seg.Window) << c.sndWndShift
	c.cc = NewNewReno(uint32(c.mss)) // reinit with negotiated MSS

	// RTT sample
	c.rto.AckReceived(seg.Ack)

	c.state = StateEstablished

	// Send ACK
	c.queueACK()

	// Flush any queued app data
	c.flushSendQueue()

	// Start keepalive if configured
	if c.keepalive {
		c.startKeepalive()
	}

	pkts := c.drainOutgoing()

	// Signal establishment (outside lock via deferred close)
	c.safeCloseEstablished()

	return pkts
}

func (c *Conn) handleSynReceived(seg Segment) [][]byte {
	if !seg.HasFlag(FlagACK) {
		return c.drainOutgoing()
	}
	if seg.Ack != c.sendBuf.NXT() {
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
		finSeq := seg.Seq + seg.DataLen()
		if finSeq == c.recvBuf.Nxt() {
			// FIN is in-order — advance nxt by 1 (FIN consumes a sequence number)
			c.recvBuf.nxt++
		}
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
		c.recvCond.Broadcast()
		c.sendCond.Broadcast()
	}
	return c.drainOutgoing()
}

// --- Data processing ---

func (c *Conn) processData(seg Segment) {
	n := c.recvBuf.Insert(seg.Seq, seg.Payload)
	if n > 0 {
		c.recvMu.Lock()
		c.recvMu.Unlock()
		c.recvCond.Broadcast()
	}
	// Out-of-order: still send ACK (dup ACK helps sender)
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
		c.mu.Unlock()
		c.recvCond.Broadcast()
		c.sendCond.Broadcast()
	})
}

// --- Keepalive ---

func (c *Conn) startKeepalive() {
	c.stopKeepalive()
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
	default:
		c.closed.Store(true)
		c.state = StateClosed
		c.stopRTO()
		c.stopKeepalive()
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

func (c *Conn) LocalAddr() net.Addr  { return c.localAddr }
func (c *Conn) RemoteAddr() net.Addr { return c.remoteAddr }

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
