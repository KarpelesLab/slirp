package nettest

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"testing"
	"time"

	"github.com/KarpelesLab/slirp/vtcp"
)

// connectPair performs the 3-way handshake on a Pair.
// For zero-delay configs, uses synchronous handshake.
// For delayed configs, uses goroutine-based handshake.
func connectPair(t *testing.T, p *Pair) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Server accepts in a goroutine
	serverReady := make(chan struct{})
	go func() {
		// We need the client to send SYN first, then server processes it
		// via the link delivery. For non-delayed links, the SYN is delivered
		// synchronously inside Connect. For delayed links, we need to wait.
		close(serverReady)
	}()
	<-serverReady

	// For the handshake to work through the Link, we need the server
	// to be in LISTEN/CLOSED state and process the SYN via HandleSegment.
	// The Pair's delivery callbacks handle this automatically.

	// However, Connect blocks until established. With delay, the SYN
	// is queued and delivered later. We need server to AcceptSYN.
	// Let's use a different approach: manual handshake.

	// Actually, the Link's deliver callback calls server.HandleSegment
	// which works for data but NOT for the initial SYN (server is in CLOSED state).
	// We need AcceptSYN for the first SYN. Let's intercept.

	// Approach: override the AtoB deliver for the first SYN to call AcceptSYN,
	// then switch to HandleSegment for subsequent packets.

	synHandled := false
	origDeliver := p.link.AtoB.deliver
	p.link.AtoB.deliver = func(data []byte) {
		if synHandled {
			origDeliver(data)
			return
		}
		seg, err := vtcp.ParseSegment(data)
		if err != nil {
			return
		}
		if seg.HasFlag(vtcp.FlagSYN) && !seg.HasFlag(vtcp.FlagACK) {
			synHandled = true
			pkts := p.server.AcceptSYN(seg)
			p.link.AtoB.deliver = origDeliver
			for _, pkt := range pkts {
				_ = p.server.Writer()(pkt)
			}
			return
		}
		origDeliver(data)
	}

	err := p.client.Connect(ctx)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
}

// transferData sends data from src to dst and verifies integrity.
// Returns throughput in bytes/sec and elapsed time.
func transferData(t *testing.T, src, dst *vtcp.Conn, size int) (throughput float64, elapsed time.Duration) {
	t.Helper()

	// Generate deterministic data
	data := make([]byte, size)
	for i := range data {
		data[i] = byte(i % 251) // prime to avoid alignment patterns
	}
	srcHash := sha256.Sum256(data)

	errCh := make(chan error, 2)

	// Writer goroutine
	start := time.Now()
	go func() {
		written := 0
		for written < len(data) {
			chunk := data[written:]
			if len(chunk) > 32768 {
				chunk = chunk[:32768]
			}
			n, err := src.Write(chunk)
			if err != nil {
				errCh <- fmt.Errorf("Write at %d: %v", written, err)
				return
			}
			written += n
		}
		errCh <- nil
	}()

	// Reader goroutine
	received := make([]byte, 0, size)
	go func() {
		buf := make([]byte, 65536)
		for len(received) < size {
			dst.SetReadDeadline(time.Now().Add(30 * time.Second))
			n, err := dst.Read(buf)
			if err != nil {
				if err == io.EOF && len(received) == size {
					break
				}
				errCh <- fmt.Errorf("Read at %d/%d: %v", len(received), size, err)
				return
			}
			received = append(received, buf[:n]...)
		}
		errCh <- nil
	}()

	// Wait for both
	for range 2 {
		if err := <-errCh; err != nil {
			t.Fatal(err)
		}
	}
	elapsed = time.Since(start)

	// Verify integrity
	dstHash := sha256.Sum256(received)
	if srcHash != dstHash {
		t.Errorf("data integrity check failed: sent %d bytes, received %d bytes", size, len(received))
		// Find first mismatch
		for i := range min(len(data), len(received)) {
			if data[i] != received[i] {
				t.Errorf("first mismatch at byte %d: sent 0x%02x, got 0x%02x", i, data[i], received[i])
				break
			}
		}
	}

	if elapsed > 0 {
		throughput = float64(size) / elapsed.Seconds()
	}
	return throughput, elapsed
}

func TestStressClean(t *testing.T) {
	p, err := NewPair(LinkConfig{})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()

	connectPair(t, p)

	size := 256 * 1024 // 256 KB
	tp, elapsed := transferData(t, p.Client(), p.Server(), size)
	t.Logf("Clean: %d KB in %v (%.1f MB/s)", size/1024, elapsed, tp/1e6)
}

func TestStressWithDelay(t *testing.T) {
	tests := []struct {
		delay time.Duration
		size  int
	}{
		{5 * time.Millisecond, 4 * 1024 * 1024},
		{25 * time.Millisecond, 4 * 1024 * 1024},
		{50 * time.Millisecond, 4 * 1024 * 1024},
	}
	for _, tt := range tests {
		t.Run(tt.delay.String(), func(t *testing.T) {
			p, err := NewPair(LinkConfig{Delay: tt.delay})
			if err != nil {
				t.Fatal(err)
			}
			defer p.Close()

			connectPair(t, p)

			tp, elapsed := transferData(t, p.Client(), p.Server(), tt.size)

			aToB, bToA := p.Link().Stats()
			t.Logf("Delay %v: %d KB in %v (%.1f MB/s) | c→s: %d sent %d delivered | s→c: %d sent %d delivered",
				tt.delay, tt.size/1024, elapsed, tp/1e6,
				aToB.Sent.Load(), aToB.Delivered.Load(),
				bToA.Sent.Load(), bToA.Delivered.Load())
		})
	}
}

func TestStressWithLoss(t *testing.T) {
	for _, loss := range []float64{0.01, 0.05} {
		t.Run(fmt.Sprintf("%.0f%%", loss*100), func(t *testing.T) {
			p, err := NewPair(LinkConfig{Loss: loss, Delay: 5 * time.Millisecond})
			if err != nil {
				t.Fatal(err)
			}
			defer p.Close()

			connectPair(t, p)

			size := 128 * 1024
			tp, elapsed := transferData(t, p.Client(), p.Server(), size)

			aToB, bToA := p.Link().Stats()
			t.Logf("Loss %.0f%%: %d KB in %v (%.1f MB/s) | c→s: %d sent %d dropped | s→c: %d sent %d dropped",
				loss*100, size/1024, elapsed, tp/1e6,
				aToB.Sent.Load(), aToB.Dropped.Load(),
				bToA.Sent.Load(), bToA.Dropped.Load())
		})
	}
}

func TestStressWithReorder(t *testing.T) {
	p, err := NewPair(LinkConfig{Reorder: 0.10, Delay: 5 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()

	connectPair(t, p)

	size := 64 * 1024
	tp, elapsed := transferData(t, p.Client(), p.Server(), size)

	aToB, bToA := p.Link().Stats()
	t.Logf("Reorder 10%%: %d KB in %v (%.1f MB/s) | c→s: %d reordered | s→c: %d reordered",
		size/1024, elapsed, tp/1e6,
		aToB.Reordered.Load(), bToA.Reordered.Load())
}

func TestStressCombined(t *testing.T) {
	p, err := NewPair(LinkConfig{
		Loss:    0.02,
		Reorder: 0.05,
		Delay:   10 * time.Millisecond,
		Jitter:  5 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()

	connectPair(t, p)

	size := 32 * 1024
	tp, elapsed := transferData(t, p.Client(), p.Server(), size)

	aToB, bToA := p.Link().Stats()
	t.Logf("Combined: %d KB in %v (%.1f MB/s) | c→s: sent=%d drop=%d reord=%d | s→c: sent=%d drop=%d reord=%d",
		size/1024, elapsed, tp/1e6,
		aToB.Sent.Load(), aToB.Dropped.Load(), aToB.Reordered.Load(),
		bToA.Sent.Load(), bToA.Dropped.Load(), bToA.Reordered.Load())
}

func TestStressBidirectional(t *testing.T) {
	p, err := NewPair(LinkConfig{Delay: 5 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()

	connectPair(t, p)

	// Wait for server to reach ESTABLISHED
	for i := 0; i < 100; i++ {
		if p.Server().State() == vtcp.StateEstablished {
			break
		}
		time.Sleep(time.Millisecond)
	}

	size := 32 * 1024

	// Client → Server (sequential for simplicity with delay)
	tp, elapsed := transferData(t, p.Client(), p.Server(), size)
	t.Logf("C→S: %d KB in %v (%.1f MB/s)", size/1024, elapsed, tp/1e6)

	// Server → Client
	tp, elapsed = transferData(t, p.Server(), p.Client(), size)
	t.Logf("S→C: %d KB in %v (%.1f MB/s)", size/1024, elapsed, tp/1e6)
}

// BenchmarkThroughputClean measures baseline throughput.
func BenchmarkThroughputClean(b *testing.B) {
	p, err := NewPair(LinkConfig{})
	if err != nil {
		b.Fatal(err)
	}
	defer p.Close()

	// Manual connect for benchmarks
	ctx := context.Background()
	synHandled := false
	origDeliver := p.link.AtoB.deliver
	p.link.AtoB.deliver = func(data []byte) {
		if synHandled {
			origDeliver(data)
			return
		}
		seg, err := vtcp.ParseSegment(data)
		if err != nil {
			return
		}
		if seg.HasFlag(vtcp.FlagSYN) && !seg.HasFlag(vtcp.FlagACK) {
			synHandled = true
			pkts := p.server.AcceptSYN(seg)
			p.link.AtoB.deliver = origDeliver
			for _, pkt := range pkts {
				_ = p.server.Writer()(pkt)
			}
			return
		}
		origDeliver(data)
	}
	if err := p.client.Connect(ctx); err != nil {
		b.Fatal(err)
	}

	data := make([]byte, 1460)
	for i := range data {
		data[i] = byte(i)
	}

	b.ResetTimer()
	b.SetBytes(int64(len(data)))

	for range b.N {
		_, err := p.client.Write(data)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
