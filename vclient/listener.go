package vclient

import (
	"errors"
	"net"
	"strconv"
	"sync"
)

// Listener is a virtual TCP listener that accepts connections from the
// virtual network. It implements net.Listener.
type Listener struct {
	c         *Client
	addr      *net.TCPAddr
	port      uint16
	acceptCh  chan net.Conn
	closeCh   chan struct{}
	closeOnce sync.Once
}

// Listen announces on the virtual network address and returns a net.Listener.
// The network must be "tcp" or "tcp4". The address is "host:port" where host
// is the client's virtual IP (or empty/"0.0.0.0" for any).
func (c *Client) Listen(network, address string) (net.Listener, error) {
	switch network {
	case "tcp", "tcp4":
	default:
		return nil, errors.New("unsupported network: " + network)
	}

	host, portStr, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 0 || port > 65535 {
		return nil, errors.New("invalid port")
	}

	// Resolve the listen IP
	var listenIP [4]byte
	if host == "" || host == "0.0.0.0" {
		// wildcard — use client's IP for the address
		c.mu.RLock()
		listenIP = c.ip
		c.mu.RUnlock()
	} else {
		ip := net.ParseIP(host)
		if ip == nil {
			return nil, errors.New("invalid listen address: " + host)
		}
		ip4 := ip.To4()
		if ip4 == nil {
			return nil, errors.New("IPv6 not supported")
		}
		copy(listenIP[:], ip4)
	}

	c.listenerMu.Lock()
	defer c.listenerMu.Unlock()

	if _, exists := c.listeners[uint16(port)]; exists {
		return nil, errors.New("address already in use")
	}

	l := &Listener{
		c:        c,
		addr:     &net.TCPAddr{IP: net.IP(listenIP[:]).To4(), Port: port},
		port:     uint16(port),
		acceptCh: make(chan net.Conn, 16),
		closeCh:  make(chan struct{}),
	}

	c.listeners[uint16(port)] = l
	return l, nil
}

// Accept waits for and returns the next connection to the listener.
func (l *Listener) Accept() (net.Conn, error) {
	select {
	case conn := <-l.acceptCh:
		return conn, nil
	case <-l.closeCh:
		return nil, errors.New("listener closed")
	}
}

// Close closes the listener.
func (l *Listener) Close() error {
	l.closeOnce.Do(func() {
		close(l.closeCh)
		l.c.listenerMu.Lock()
		delete(l.c.listeners, l.port)
		l.c.listenerMu.Unlock()
	})
	return nil
}

// Addr returns the listener's network address.
func (l *Listener) Addr() net.Addr {
	return l.addr
}
