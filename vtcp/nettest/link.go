// Package nettest provides a simulated network link with configurable
// impairments (loss, delay, reorder, duplication) for testing the vtcp
// TCP implementation under adversarial conditions.
package nettest

import (
	"container/heap"
	"math/rand/v2"
	"sync"
	"time"

	"github.com/KarpelesLab/slirp/vtcp"
)

// LinkConfig configures network impairments for one direction.
type LinkConfig struct {
	Loss      float64       // packet loss probability [0,1]
	Reorder   float64       // reorder probability [0,1] (delayed by 1-3 packets)
	Delay     time.Duration // base one-way delay
	Jitter    time.Duration // random jitter (uniform) added to delay
	Duplicate float64       // duplicate probability [0,1]
}

// deliveryItem is a packet scheduled for future delivery.
type deliveryItem struct {
	data    []byte
	delivAt time.Time
	index   int // heap index
}

// deliveryQueue is a min-heap ordered by delivery time.
type deliveryQueue []*deliveryItem

func (q deliveryQueue) Len() int           { return len(q) }
func (q deliveryQueue) Less(i, j int) bool { return q[i].delivAt.Before(q[j].delivAt) }
func (q deliveryQueue) Swap(i, j int)      { q[i], q[j] = q[j], q[i]; q[i].index = i; q[j].index = j }
func (q *deliveryQueue) Push(x any) {
	item := x.(*deliveryItem)
	item.index = len(*q)
	*q = append(*q, item)
}
func (q *deliveryQueue) Pop() any {
	old := *q
	n := len(old)
	item := old[n-1]
	old[n-1] = nil
	item.index = -1
	*q = old[:n-1]
	return item
}

// halfLink represents one direction of a link (A→B).
type halfLink struct {
	cfg     LinkConfig
	stats   Stats
	deliver func([]byte) // called to deliver a packet to the receiver

	mu    sync.Mutex
	queue deliveryQueue
	timer *time.Timer
	done  chan struct{}
}

func newHalfLink(cfg LinkConfig, deliver func([]byte)) *halfLink {
	return &halfLink{
		cfg:     cfg,
		deliver: deliver,
		done:    make(chan struct{}),
	}
}

// send processes an outgoing packet, applying impairments.
func (h *halfLink) send(seg []byte) {
	h.stats.Sent.Add(1)

	// Loss
	if h.cfg.Loss > 0 && rand.Float64() < h.cfg.Loss {
		h.stats.Dropped.Add(1)
		return
	}

	// Calculate delivery time
	delay := h.cfg.Delay
	if h.cfg.Jitter > 0 {
		delay += time.Duration(rand.Int64N(int64(h.cfg.Jitter)))
	}

	// Reorder: add extra random delay
	if h.cfg.Reorder > 0 && rand.Float64() < h.cfg.Reorder {
		extra := time.Duration(rand.Int64N(int64(50*time.Millisecond))) + 10*time.Millisecond
		delay += extra
		h.stats.Reordered.Add(1)
	}

	// Make a copy
	cp := make([]byte, len(seg))
	copy(cp, seg)

	if delay == 0 {
		// Deliver immediately
		h.deliverPacket(cp)
	} else {
		// Schedule for later
		h.schedule(cp, time.Now().Add(delay))
	}

	// Duplicate
	if h.cfg.Duplicate > 0 && rand.Float64() < h.cfg.Duplicate {
		h.stats.Duplicated.Add(1)
		dup := make([]byte, len(seg))
		copy(dup, seg)
		dupDelay := delay + time.Duration(rand.Int64N(int64(5*time.Millisecond)))
		if dupDelay == 0 {
			h.deliverPacket(dup)
		} else {
			h.schedule(dup, time.Now().Add(dupDelay))
		}
	}
}

func (h *halfLink) deliverPacket(data []byte) {
	h.stats.Delivered.Add(1)
	h.stats.Bytes.Add(int64(len(data)))
	h.mu.Lock()
	fn := h.deliver
	h.mu.Unlock()
	if fn != nil {
		fn(data)
	}
}

func (h *halfLink) schedule(data []byte, at time.Time) {
	h.mu.Lock()
	defer h.mu.Unlock()

	item := &deliveryItem{data: data, delivAt: at}
	heap.Push(&h.queue, item)

	// Reset timer to earliest delivery
	if h.timer == nil {
		h.timer = time.AfterFunc(time.Until(at), h.flush)
	} else if h.queue[0] == item {
		h.timer.Reset(time.Until(at))
	}
}

func (h *halfLink) flush() {
	h.mu.Lock()
	now := time.Now()
	var toDeliver [][]byte
	for h.queue.Len() > 0 && !h.queue[0].delivAt.After(now) {
		item := heap.Pop(&h.queue).(*deliveryItem)
		toDeliver = append(toDeliver, item.data)
	}
	// Reschedule timer for next item
	if h.queue.Len() > 0 {
		if h.timer != nil {
			h.timer.Reset(time.Until(h.queue[0].delivAt))
		} else {
			h.timer = time.AfterFunc(time.Until(h.queue[0].delivAt), h.flush)
		}
	} else {
		h.timer = nil
	}
	h.mu.Unlock()

	for _, data := range toDeliver {
		h.deliverPacket(data)
	}
}

func (h *halfLink) close() {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.timer != nil {
		h.timer.Stop()
		h.timer = nil
	}
}

// Link is a simulated bidirectional network link with configurable impairments.
type Link struct {
	AtoB *halfLink // client → server
	BtoA *halfLink // server → client
}

// NewLink creates a new link. The deliver functions are set later by Pair.
func NewLink(cfgAtoB, cfgBtoA LinkConfig) *Link {
	return &Link{
		AtoB: newHalfLink(cfgAtoB, nil),
		BtoA: newHalfLink(cfgBtoA, nil),
	}
}

// Close stops all pending deliveries.
func (l *Link) Close() {
	l.AtoB.close()
	l.BtoA.close()
}

// Stats returns the per-direction statistics.
func (l *Link) Stats() (aToB, bToA *Stats) {
	return &l.AtoB.stats, &l.BtoA.stats
}

// Pair creates two vtcp.Conn endpoints connected through a Link with
// the given impairment configuration (applied symmetrically to both directions).
type Pair struct {
	client *vtcp.Conn
	server *vtcp.Conn
	link   *Link
}

// NewPair creates a connected client-server pair with the given impairments.
// The handshake is performed automatically.
func NewPair(cfg LinkConfig) (*Pair, error) {
	return NewPairAsymmetric(cfg, cfg)
}

// NewPairAsymmetric creates a pair with different impairments per direction.
func NewPairAsymmetric(clientToServer, serverToClient LinkConfig) (*Pair, error) {
	link := NewLink(clientToServer, serverToClient)

	var client, server *vtcp.Conn
	var serverMu sync.Mutex

	// Client's writer → goes through link A→B → server.HandleSegment
	clientWriter := func(seg []byte) error {
		link.AtoB.send(seg)
		return nil
	}

	// Server's writer → goes through link B→A → client.HandleSegment
	serverWriter := func(seg []byte) error {
		link.BtoA.send(seg)
		return nil
	}

	client = vtcp.NewConn(vtcp.ConnConfig{
		LocalPort:  50000,
		RemotePort: 9000,
		Writer:     clientWriter,
		MSS:        1460,
	})

	server = vtcp.NewConn(vtcp.ConnConfig{
		LocalPort:  9000,
		RemotePort: 50000,
		Writer:     serverWriter,
		MSS:        1460,
	})

	// Wire up delivery callbacks
	link.AtoB.deliver = func(data []byte) {
		seg, err := vtcp.ParseSegment(data)
		if err != nil {
			return
		}
		serverMu.Lock()
		s := server
		serverMu.Unlock()
		pkts := s.HandleSegment(seg)
		for _, pkt := range pkts {
			_ = serverWriter(pkt)
		}
	}

	link.BtoA.deliver = func(data []byte) {
		seg, err := vtcp.ParseSegment(data)
		if err != nil {
			return
		}
		pkts := client.HandleSegment(seg)
		for _, pkt := range pkts {
			_ = clientWriter(pkt)
		}
	}

	p := &Pair{client: client, server: server, link: link}
	return p, nil
}

// Client returns the client-side connection.
func (p *Pair) Client() *vtcp.Conn { return p.client }

// Server returns the server-side connection.
func (p *Pair) Server() *vtcp.Conn { return p.server }

// Link returns the underlying link for stats access.
func (p *Pair) Link() *Link { return p.link }

// Close shuts down the link and both connections.
func (p *Pair) Close() {
	p.link.Close()
	p.client.Abort()
	p.server.Abort()
}
