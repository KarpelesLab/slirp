package nettest

import (
	"crypto/rand"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/KarpelesLab/slirp/vtcp"
)

// directPair creates two vtcp.Conn connected synchronously (no Link, no delay).
// Uses unique ports per connection. Returns connected (ESTABLISHED) pair.
func directPair(clientPort, serverPort uint16, bufSize int) (client, server *vtcp.Conn, err error) {
	// Phase 1: create conns with writers that deliver to each other.
	// We use a two-phase approach: first create both, then wire writers.
	var clientRef, serverRef atomic.Pointer[vtcp.Conn]

	client = vtcp.NewConn(vtcp.ConnConfig{
		LocalPort:   clientPort,
		RemotePort:  serverPort,
		MSS:         1460,
		SendBufSize: bufSize,
		RecvBufSize: bufSize,
		Writer: func(seg []byte) error {
			s := serverRef.Load()
			if s == nil {
				return nil
			}
			parsed, err := vtcp.ParseSegment(seg)
			if err != nil {
				return nil
			}
			pkts := s.HandleSegment(parsed)
			for _, pkt := range pkts {
				p, _ := vtcp.ParseSegment(pkt)
				c := clientRef.Load()
				if c != nil {
					rpkts := c.HandleSegment(p)
					for _, rpkt := range rpkts {
						rp, _ := vtcp.ParseSegment(rpkt)
						s.HandleSegment(rp)
					}
				}
			}
			return nil
		},
	})

	server = vtcp.NewConn(vtcp.ConnConfig{
		LocalPort:   serverPort,
		RemotePort:  clientPort,
		MSS:         1460,
		SendBufSize: bufSize,
		RecvBufSize: bufSize,
		Writer: func(seg []byte) error {
			c := clientRef.Load()
			if c == nil {
				return nil
			}
			parsed, err := vtcp.ParseSegment(seg)
			if err != nil {
				return nil
			}
			pkts := c.HandleSegment(parsed)
			for _, pkt := range pkts {
				p, _ := vtcp.ParseSegment(pkt)
				s := serverRef.Load()
				if s != nil {
					rpkts := s.HandleSegment(p)
					for _, rpkt := range rpkts {
						rp, _ := vtcp.ParseSegment(rpkt)
						c.HandleSegment(rp)
					}
				}
			}
			return nil
		},
	})

	clientRef.Store(client)
	serverRef.Store(server)

	// Phase 2: handshake. Build SYN, server AcceptSYN, feed responses.
	iss := vtcp.RandUint32Exported()
	syn := vtcp.Segment{
		SrcPort: clientPort,
		DstPort: serverPort,
		Seq:     iss,
		Flags:   vtcp.FlagSYN,
		Window:  65535,
		Options: []vtcp.Option{vtcp.MSSOption(1460), vtcp.WScaleOption(4)},
	}

	synAckPkts := server.AcceptSYN(syn)
	if len(synAckPkts) == 0 {
		return nil, nil, fmt.Errorf("AcceptSYN returned no packets")
	}

	// Manually set up client state to match
	synAck, err := vtcp.ParseSegment(synAckPkts[0])
	if err != nil {
		return nil, nil, err
	}

	// Feed SYN-ACK to client via HandleSegment.
	// Client is in CLOSED state, so we need to put it in SYN-SENT first.
	client.SetupForHandshake(iss)
	ackPkts := client.HandleSegment(synAck)

	// Feed ACK to server
	for _, pkt := range ackPkts {
		p, _ := vtcp.ParseSegment(pkt)
		server.HandleSegment(p)
	}

	if client.State() != vtcp.StateEstablished {
		return nil, nil, fmt.Errorf("client state = %v, want ESTABLISHED", client.State())
	}
	if server.State() != vtcp.StateEstablished {
		return nil, nil, fmt.Errorf("server state = %v, want ESTABLISHED", server.State())
	}

	return client, server, nil
}

// massTest runs N concurrent TCP connections, each transferring dataSize random bytes.
func massTest(t *testing.T, numConns int, dataSize int, timeout time.Duration) {
	t.Helper()

	var (
		totalBytes     atomic.Int64
		completedConns atomic.Int64
		failedConns    atomic.Int64
	)

	start := time.Now()
	var wg sync.WaitGroup

	sem := make(chan struct{}, 1000) // limit concurrent goroutines

	for i := range numConns {
		wg.Add(1)
		sem <- struct{}{}

		go func(idx int) {
			defer wg.Done()
			defer func() { <-sem }()

			cPort := uint16(10000 + (idx % 55000))
			sPort := uint16(60000 + (idx % 5535))
			bufSize := 64 * 1024
			if dataSize <= 1024 {
				bufSize = 16 * 1024
			}

			client, server, err := directPair(cPort, sPort, bufSize)
			if err != nil {
				failedConns.Add(1)
				return
			}

			// Generate random data
			data := make([]byte, dataSize)
			rand.Read(data)

			errCh := make(chan error, 2)

			// Writer
			go func() {
				_, err := client.Write(data)
				errCh <- err
			}()

			// Reader
			go func() {
				received := 0
				buf := make([]byte, 8192)
				server.SetReadDeadline(time.Now().Add(timeout))
				for received < dataSize {
					n, err := server.Read(buf)
					if err != nil {
						if err == io.EOF && received >= dataSize {
							break
						}
						errCh <- fmt.Errorf("read at %d/%d: %w", received, dataSize, err)
						return
					}
					received += n
				}
				errCh <- nil
			}()

			for range 2 {
				if err := <-errCh; err != nil {
					failedConns.Add(1)
					client.Abort()
					server.Abort()
					return
				}
			}

			totalBytes.Add(int64(dataSize))
			completedConns.Add(1)
			client.Close()
			server.Close()
		}(i)
	}

	wg.Wait()
	elapsed := time.Since(start)

	completed := completedConns.Load()
	failed := failedConns.Load()
	bytes := totalBytes.Load()
	throughput := float64(bytes) / elapsed.Seconds()

	t.Logf("%d connections: %d completed, %d failed in %v",
		numConns, completed, failed, elapsed.Round(time.Millisecond))
	t.Logf("  Total: %.1f MB transferred (%.1f MB/s)",
		float64(bytes)/1e6, throughput/1e6)
	t.Logf("  Per-conn: %d bytes, %.0f conns/s",
		dataSize, float64(completed)/elapsed.Seconds())

	if failed > 0 {
		t.Errorf("%d/%d connections failed", failed, numConns)
	}
}

func TestMass1K(t *testing.T) {
	massTest(t, 1_000, 4096, 30*time.Second)
}

func TestMass10K(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping in short mode")
	}
	massTest(t, 10_000, 4096, 60*time.Second)
}

func TestMass100K(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping in short mode")
	}
	massTest(t, 100_000, 1024, 120*time.Second)
}
