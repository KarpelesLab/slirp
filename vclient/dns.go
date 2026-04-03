package vclient

import (
	"context"
	"encoding/binary"
	"errors"
	"math/rand/v2"
	"net"
	"strings"
	"time"
)

// LookupHost resolves a hostname to IP addresses using the configured DNS servers.
func (c *Client) LookupHost(ctx context.Context, host string) ([]string, error) {
	// If it's already an IP, return directly
	if ip := net.ParseIP(host); ip != nil {
		return []string{ip.String()}, nil
	}

	c.mu.RLock()
	if len(c.dns) == 0 {
		c.mu.RUnlock()
		return nil, errors.New("no DNS servers configured")
	}
	dnsServer := c.dns[0]
	localIP := c.ip
	c.mu.RUnlock()

	// Allocate ephemeral port and create UDP conn for DNS
	port := c.allocPort()
	conn := newUDPConn(c, localIP, port, dnsServer, 53)
	c.udpMu.Lock()
	c.udpConns[connKey{localPort: port, remoteIP: dnsServer, remotePort: 53}] = conn
	c.udpMu.Unlock()
	defer conn.Close()

	// Build DNS query
	id := uint16(rand.Uint32())
	query := buildDNSQuery(id, host, 1) // A record

	// Send query
	if _, err := conn.Write(query); err != nil {
		return nil, err
	}

	// Read responses in a goroutine so we can respect context/timeout
	type dnsResult struct {
		addrs []string
		err   error
	}
	resultCh := make(chan dnsResult, 1)
	go func() {
		buf := make([]byte, 512)
		for {
			n, err := conn.Read(buf)
			if err != nil {
				resultCh <- dnsResult{err: err}
				return
			}
			ips, err := parseDNSResponse(buf[:n], id)
			if err != nil {
				continue // wrong ID or parse error, keep waiting
			}
			if len(ips) == 0 {
				resultCh <- dnsResult{err: errors.New("no addresses found for " + host)}
				return
			}
			result := make([]string, len(ips))
			for i, ip := range ips {
				result[i] = ip.String()
			}
			resultCh <- dnsResult{addrs: result}
			return
		}
	}()

	timeout := time.NewTimer(5 * time.Second)
	defer timeout.Stop()

	select {
	case res := <-resultCh:
		return res.addrs, res.err
	case <-ctx.Done():
		conn.Close() // unblock the Read goroutine
		return nil, ctx.Err()
	case <-timeout.C:
		conn.Close() // unblock the Read goroutine
		return nil, errors.New("DNS resolution timeout")
	}
}

// Resolver returns a *net.Resolver that uses this client's DNS resolution.
func (c *Client) Resolver() *net.Resolver {
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			// Connect to our configured DNS server via UDP
			c.mu.RLock()
			if len(c.dns) == 0 {
				c.mu.RUnlock()
				return nil, errors.New("no DNS servers configured")
			}
			dnsServer := c.dns[0]
			localIP := c.ip
			c.mu.RUnlock()

			port := c.allocPort()
			conn := newUDPConn(c, localIP, port, dnsServer, 53)
			c.udpMu.Lock()
			c.udpConns[connKey{localPort: port, remoteIP: dnsServer, remotePort: 53}] = conn
			c.udpMu.Unlock()
			return conn, nil
		},
	}
}

// buildDNSQuery builds a DNS query packet for the given name and type.
func buildDNSQuery(id uint16, name string, qtype uint16) []byte {
	// Header: 12 bytes
	hdr := make([]byte, 12)
	binary.BigEndian.PutUint16(hdr[0:2], id)
	hdr[2] = 0x01 // RD (Recursion Desired)
	hdr[3] = 0x00
	binary.BigEndian.PutUint16(hdr[4:6], 1) // QDCOUNT = 1

	// Question section
	qname := encodeDNSName(name)
	question := make([]byte, len(qname)+4)
	copy(question, qname)
	binary.BigEndian.PutUint16(question[len(qname):], qtype) // QTYPE
	binary.BigEndian.PutUint16(question[len(qname)+2:], 1)   // QCLASS = IN

	pkt := make([]byte, len(hdr)+len(question))
	copy(pkt, hdr)
	copy(pkt[len(hdr):], question)
	return pkt
}

// encodeDNSName encodes a domain name in DNS wire format.
func encodeDNSName(name string) []byte {
	name = strings.TrimSuffix(name, ".")
	parts := strings.Split(name, ".")
	var buf []byte
	for _, part := range parts {
		buf = append(buf, byte(len(part)))
		buf = append(buf, []byte(part)...)
	}
	buf = append(buf, 0) // root label
	return buf
}

// parseDNSResponse parses a DNS response and extracts A record IPs.
func parseDNSResponse(data []byte, expectedID uint16) ([]net.IP, error) {
	if len(data) < 12 {
		return nil, errors.New("response too short")
	}

	id := binary.BigEndian.Uint16(data[0:2])
	if id != expectedID {
		return nil, errors.New("ID mismatch")
	}

	flags := binary.BigEndian.Uint16(data[2:4])
	if flags&0x8000 == 0 {
		return nil, errors.New("not a response")
	}
	rcode := flags & 0x0F
	if rcode != 0 {
		return nil, errors.New("DNS error")
	}

	qdcount := binary.BigEndian.Uint16(data[4:6])
	ancount := binary.BigEndian.Uint16(data[6:8])

	offset := 12
	// Skip questions
	for i := 0; i < int(qdcount); i++ {
		offset = skipDNSName(data, offset)
		if offset < 0 || offset+4 > len(data) {
			return nil, errors.New("malformed question")
		}
		offset += 4 // QTYPE + QCLASS
	}

	// Parse answers
	var ips []net.IP
	for i := 0; i < int(ancount); i++ {
		offset = skipDNSName(data, offset)
		if offset < 0 || offset+10 > len(data) {
			break
		}
		rtype := binary.BigEndian.Uint16(data[offset : offset+2])
		// rclass := binary.BigEndian.Uint16(data[offset+2 : offset+4])
		// ttl := binary.BigEndian.Uint32(data[offset+4 : offset+8])
		rdlength := binary.BigEndian.Uint16(data[offset+8 : offset+10])
		offset += 10

		if offset+int(rdlength) > len(data) {
			break
		}

		if rtype == 1 && rdlength == 4 { // A record
			ip := net.IPv4(data[offset], data[offset+1], data[offset+2], data[offset+3])
			ips = append(ips, ip)
		}
		offset += int(rdlength)
	}

	return ips, nil
}

// skipDNSName skips a DNS name in wire format, handling compression pointers.
func skipDNSName(data []byte, offset int) int {
	if offset >= len(data) {
		return -1
	}
	for {
		if offset >= len(data) {
			return -1
		}
		l := int(data[offset])
		if l == 0 {
			return offset + 1
		}
		if l&0xC0 == 0xC0 {
			// Compression pointer
			return offset + 2
		}
		offset += 1 + l
	}
}
