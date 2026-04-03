package vclient

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strconv"

	"github.com/KarpelesLab/slirp/vtcp"
)

// Dial connects to the address on the named network.
// Supported networks are "tcp", "tcp4", "udp", "udp4".
func (c *Client) Dial(network, address string) (net.Conn, error) {
	return c.DialContext(context.Background(), network, address)
}

// DialContext connects to the address on the named network using the provided context.
func (c *Client) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, portStr, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, err
	}
	if port < 0 || port > 65535 {
		return nil, errors.New("invalid port")
	}

	// Resolve hostname
	var remoteIP [4]byte
	ip := net.ParseIP(host)
	if ip == nil {
		// DNS resolution
		addrs, err := c.LookupHost(ctx, host)
		if err != nil {
			return nil, err
		}
		if len(addrs) == 0 {
			return nil, errors.New("no addresses found for " + host)
		}
		ip = net.ParseIP(addrs[0])
		if ip == nil {
			return nil, errors.New("invalid IP from DNS: " + addrs[0])
		}
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return nil, errors.New("IPv6 not supported yet")
	}
	copy(remoteIP[:], ip4)

	c.mu.RLock()
	localIP := c.ip
	c.mu.RUnlock()

	switch network {
	case "tcp", "tcp4":
		return c.dialTCP(ctx, localIP, remoteIP, uint16(port))
	case "udp", "udp4":
		return c.dialUDP(localIP, remoteIP, uint16(port))
	default:
		return nil, errors.New("unsupported network: " + network)
	}
}

func (c *Client) dialTCP(ctx context.Context, localIP, remoteIP [4]byte, remotePort uint16) (net.Conn, error) {
	localPort := c.allocPort()

	localAddr := &net.TCPAddr{IP: net.IP(localIP[:]).To4(), Port: int(localPort)}
	remoteAddr := &net.TCPAddr{IP: net.IP(remoteIP[:]).To4(), Port: int(remotePort)}

	vc := vtcp.NewConn(vtcp.ConnConfig{
		LocalPort:  localPort,
		RemotePort: remotePort,
		LocalAddr:  localAddr,
		RemoteAddr: remoteAddr,
		Writer: func(tcpSeg []byte) error {
			return c.sendPacket(buildIPv4Packet(localIP, remoteIP, tcpSeg))
		},
		MSS:       1460,
		Keepalive: true,
	})

	k := connKey{localPort: localPort, remoteIP: remoteIP, remotePort: remotePort}
	conn := &TCPConn{vc: vc, c: c, k: k}

	c.tcpMu.Lock()
	c.tcpConns[k] = conn
	c.tcpMu.Unlock()

	// Initiate handshake
	if err := vc.Connect(ctx); err != nil {
		c.tcpMu.Lock()
		delete(c.tcpConns, k)
		c.tcpMu.Unlock()
		return nil, err
	}

	return conn, nil
}

func (c *Client) dialUDP(localIP, remoteIP [4]byte, remotePort uint16) (net.Conn, error) {
	localPort := c.allocPort()
	conn := newUDPConn(c, localIP, localPort, remoteIP, remotePort)

	k := connKey{localPort: localPort, remoteIP: remoteIP, remotePort: remotePort}
	c.udpMu.Lock()
	c.udpConns[k] = conn
	c.udpMu.Unlock()

	return conn, nil
}

// HTTPClient returns an *http.Client configured to route all traffic through
// this virtual network client, including DNS resolution via DialContext which
// internally calls LookupHost.
func (c *Client) HTTPClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			DialContext: c.DialContext,
		},
	}
}
