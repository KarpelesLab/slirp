// Package vclient implements a virtual network client with a user-space TCP/IP
// stack. It operates at the IP packet level and can be connected to a slirp
// Stack for testing, or used on any IP-based network.
//
// The client supports DNS, TCP (with retransmission), and UDP, and exposes
// standard Go interfaces such as Dial, net.Conn, and net.Resolver.
package vclient

import (
	"errors"
	"net"
	"sync"
	"sync/atomic"

	"github.com/KarpelesLab/slirp"
)

// connKey identifies a connection by local port + remote endpoint.
type connKey struct {
	localPort  uint16
	remoteIP   [4]byte
	remotePort uint16
}

// Client is a virtual network client operating at the IP packet level.
type Client struct {
	mu   sync.RWMutex
	ip   [4]byte
	mask [4]byte
	gw   [4]byte
	dns  [][4]byte

	w slirp.Writer // how to send IP packets out

	// TCP connections
	tcpMu    sync.Mutex
	tcpConns map[connKey]*TCPConn

	// TCP listeners
	listenerMu sync.Mutex
	listeners  map[uint16]*Listener // keyed by local port

	// UDP connections
	udpMu    sync.Mutex
	udpConns map[connKey]*UDPConn

	// Ephemeral port allocation
	portMu   sync.Mutex
	nextPort uint16

	done   chan struct{}
	closed atomic.Bool
}

// New creates a new virtual network client with the given packet writer.
// The writer is called whenever the client needs to send an IP packet.
func New(w slirp.Writer) *Client {
	return &Client{
		w:         w,
		tcpConns:  make(map[connKey]*TCPConn),
		listeners: make(map[uint16]*Listener),
		udpConns:  make(map[connKey]*UDPConn),
		nextPort:  49152,
		done:      make(chan struct{}),
	}
}

// SetWriter sets or replaces the packet writer.
func (c *Client) SetWriter(w slirp.Writer) {
	c.mu.Lock()
	c.w = w
	c.mu.Unlock()
}

// SetIP configures a static IP address, subnet mask, and default gateway.
func (c *Client) SetIP(ip net.IP, mask net.IPMask, gw net.IP) {
	c.mu.Lock()
	defer c.mu.Unlock()
	copy(c.ip[:], ip.To4())
	copy(c.mask[:], mask)
	copy(c.gw[:], gw.To4())
}

// SetDNS configures the DNS server addresses.
func (c *Client) SetDNS(servers []net.IP) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.dns = nil
	for _, s := range servers {
		var ip [4]byte
		copy(ip[:], s.To4())
		c.dns = append(c.dns, ip)
	}
}

// IP returns the client's current IP address.
func (c *Client) IP() net.IP {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return net.IP(c.ip[:]).To4()
}

// HandlePacket processes an incoming IP packet. This is the entry point
// for packets received from the network (or from a slirp Stack's Writer).
func (c *Client) HandlePacket(packet []byte) error {
	if len(packet) < 20 {
		return nil
	}
	version := packet[0] >> 4
	switch version {
	case 4:
		return c.handleIPv4(packet)
	}
	return nil
}

func (c *Client) handleIPv4(ip []byte) error {
	if len(ip) < 20 {
		return nil
	}
	ihl := int(ip[0]&0x0F) * 4
	if len(ip) < ihl {
		return nil
	}
	proto := ip[9]

	switch proto {
	case 6: // TCP
		if len(ip) < ihl+20 {
			return nil
		}
		return c.handleTCP(ip, ihl)
	case 17: // UDP
		if len(ip) < ihl+8 {
			return nil
		}
		return c.handleUDP(ip, ihl)
	}
	return nil
}

// allocPort returns the next ephemeral port, skipping ports already in use.
func (c *Client) allocPort() uint16 {
	const minPort = 49152
	const maxPort = 65535
	const portRange = maxPort - minPort + 1

	for i := 0; i < portRange; i++ {
		c.portMu.Lock()
		p := c.nextPort
		c.nextPort++
		if c.nextPort == 0 || c.nextPort < minPort {
			c.nextPort = minPort
		}
		c.portMu.Unlock()

		// Check if port is in use in TCP connections
		inUse := false
		c.tcpMu.Lock()
		for k := range c.tcpConns {
			if k.localPort == p {
				inUse = true
				break
			}
		}
		c.tcpMu.Unlock()

		if !inUse {
			c.udpMu.Lock()
			for k := range c.udpConns {
				if k.localPort == p {
					inUse = true
					break
				}
			}
			c.udpMu.Unlock()
		}

		if !inUse {
			return p
		}
	}

	// All ports exhausted; return the next candidate anyway as a fallback.
	c.portMu.Lock()
	p := c.nextPort
	c.nextPort++
	if c.nextPort == 0 || c.nextPort < minPort {
		c.nextPort = minPort
	}
	c.portMu.Unlock()
	return p
}

// sendPacket sends a raw IP packet via the writer.
func (c *Client) sendPacket(ipPacket []byte) error {
	c.mu.RLock()
	w := c.w
	c.mu.RUnlock()
	if w == nil {
		return errors.New("no writer configured")
	}
	return w(ipPacket)
}

// Close shuts down the client and all active connections.
func (c *Client) Close() error {
	if !c.closed.CompareAndSwap(false, true) {
		return nil
	}
	close(c.done)

	// Close all listeners
	c.listenerMu.Lock()
	for port, l := range c.listeners {
		l.closeOnce.Do(func() { close(l.closeCh) })
		delete(c.listeners, port)
	}
	c.listenerMu.Unlock()

	// Close all TCP connections
	c.tcpMu.Lock()
	for k, conn := range c.tcpConns {
		conn.abort()
		delete(c.tcpConns, k)
	}
	c.tcpMu.Unlock()

	// Close all UDP connections
	c.udpMu.Lock()
	for k, conn := range c.udpConns {
		conn.closed.Store(true)
		conn.recvMu.Lock()
		conn.closedForRead = true
		conn.recvCond.Broadcast()
		conn.recvMu.Unlock()
		delete(c.udpConns, k)
	}
	c.udpMu.Unlock()

	return nil
}
