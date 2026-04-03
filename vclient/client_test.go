package vclient_test

import (
	"net"
	"testing"
	"time"

	"github.com/KarpelesLab/slirp"
	"github.com/KarpelesLab/slirp/vclient"
)

func TestPipeTCPEcho(t *testing.T) {
	stack := slirp.New()
	defer stack.Close()

	clientMAC := [6]byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}
	gwMAC := [6]byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x02}

	// Create a virtual listener on the stack
	ln, err := stack.Listen("tcp", "10.0.0.1:9000")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	// Echo server
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 4096)
				for {
					n, err := c.Read(buf)
					if err != nil {
						return
					}
					c.Write(buf[:n])
				}
			}(conn)
		}
	}()

	// Create client via Pipe
	client := vclient.Pipe(stack, 0, clientMAC, gwMAC)
	defer client.Close()
	client.SetIP(
		net.IPv4(10, 0, 0, 2),
		net.IPv4Mask(255, 255, 255, 0),
		net.IPv4(10, 0, 0, 1),
	)

	// Dial the echo server
	conn, err := client.Dial("tcp", "10.0.0.1:9000")
	if err != nil {
		t.Fatal("Dial failed:", err)
	}
	defer conn.Close()

	// Send data
	testData := []byte("Hello, virtual network!")
	n, err := conn.Write(testData)
	if err != nil {
		t.Fatal("Write failed:", err)
	}
	if n != len(testData) {
		t.Fatalf("Write: expected %d bytes, got %d", len(testData), n)
	}

	// Read echo response
	buf := make([]byte, 100)
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err = conn.Read(buf)
	if err != nil {
		t.Fatal("Read failed:", err)
	}

	if string(buf[:n]) != string(testData) {
		t.Fatalf("Echo mismatch: got %q, want %q", string(buf[:n]), string(testData))
	}
}

func TestPipeTCPLargeTransfer(t *testing.T) {
	stack := slirp.New()
	defer stack.Close()

	clientMAC := [6]byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x03}
	gwMAC := [6]byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x04}

	ln, err := stack.Listen("tcp", "10.0.0.1:9001")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	// Server that echoes everything back in chunks
	serverDone := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			serverDone <- err
			return
		}
		defer conn.Close()
		buf := make([]byte, 4096)
		for {
			n, err := conn.Read(buf)
			if err != nil {
				serverDone <- err
				return
			}
			if _, err := conn.Write(buf[:n]); err != nil {
				serverDone <- err
				return
			}
		}
	}()

	client := vclient.Pipe(stack, 0, clientMAC, gwMAC)
	defer client.Close()
	client.SetIP(
		net.IPv4(10, 0, 0, 2),
		net.IPv4Mask(255, 255, 255, 0),
		net.IPv4(10, 0, 0, 1),
	)

	conn, err := client.Dial("tcp", "10.0.0.1:9001")
	if err != nil {
		t.Fatal("Dial failed:", err)
	}

	// Send 8KB of data
	data := make([]byte, 8192)
	for i := range data {
		data[i] = byte(i % 256)
	}

	n, err := conn.Write(data)
	if err != nil {
		t.Fatal("Write failed:", err)
	}
	if n != len(data) {
		t.Fatalf("Write: expected %d, got %d", len(data), n)
	}

	// Read it all back
	// Use a generous per-read deadline to handle race detector overhead.
	received := make([]byte, 0, len(data))
	buf := make([]byte, 4096)
	for len(received) < len(data) {
		conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		n, err := conn.Read(buf)
		if err != nil {
			t.Fatalf("Read failed after %d bytes: %v", len(received), err)
		}
		received = append(received, buf[:n]...)
	}

	for i := range data {
		if received[i] != data[i] {
			t.Fatalf("Data mismatch at byte %d: got %d, want %d", i, received[i], data[i])
		}
	}

	conn.Close()
}

func TestPipeUDP(t *testing.T) {
	stack := slirp.New()
	defer stack.Close()

	clientMAC := [6]byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x05}
	gwMAC := [6]byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x06}

	client := vclient.Pipe(stack, 0, clientMAC, gwMAC)
	defer client.Close()
	client.SetIP(
		net.IPv4(10, 0, 0, 2),
		net.IPv4Mask(255, 255, 255, 0),
		net.IPv4(10, 0, 0, 1),
	)

	// UDP Dial creates a connection object (even though UDP is connectionless)
	conn, err := client.Dial("udp", "10.0.0.2:12345")
	if err != nil {
		t.Fatal("UDP Dial failed:", err)
	}
	defer conn.Close()

	// Just verify we can create and close a UDP connection
	if conn.LocalAddr() == nil {
		t.Error("LocalAddr should not be nil")
	}
	if conn.RemoteAddr() == nil {
		t.Error("RemoteAddr should not be nil")
	}
}

func TestClientSetIP(t *testing.T) {
	client := vclient.New([6]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06}, nil)
	defer client.Close()

	client.SetIP(
		net.IPv4(192, 168, 1, 100),
		net.IPv4Mask(255, 255, 255, 0),
		net.IPv4(192, 168, 1, 1),
	)

	ip := client.IP()
	if !ip.Equal(net.IPv4(192, 168, 1, 100)) {
		t.Errorf("IP = %v, want 192.168.1.100", ip)
	}
}
