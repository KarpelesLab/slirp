package vclient_test

import (
	"net"
	"testing"

	"github.com/KarpelesLab/slirp"
	"github.com/KarpelesLab/slirp/vclient"
)

// TestLookupHostIP tests that LookupHost returns an IP address directly without DNS.
func TestLookupHostIP(t *testing.T) {
	stack := slirp.New()
	defer stack.Close()

	client := vclient.Pipe(stack, 0, [6]byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x10}, [6]byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x20})
	defer client.Close()
	client.SetIP(net.IPv4(10, 0, 0, 2), net.IPv4Mask(255, 255, 255, 0), net.IPv4(10, 0, 0, 1))

	addrs, err := client.LookupHost(t.Context(), "1.2.3.4")
	if err != nil {
		t.Fatalf("LookupHost for IP: %v", err)
	}
	if len(addrs) != 1 || addrs[0] != "1.2.3.4" {
		t.Errorf("LookupHost = %v, want [1.2.3.4]", addrs)
	}
}

// TestLookupHostNoDNS tests that LookupHost returns an error when no DNS servers are configured.
func TestLookupHostNoDNS(t *testing.T) {
	stack := slirp.New()
	defer stack.Close()

	client := vclient.Pipe(stack, 0, [6]byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x10}, [6]byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x20})
	defer client.Close()
	client.SetIP(net.IPv4(10, 0, 0, 2), net.IPv4Mask(255, 255, 255, 0), net.IPv4(10, 0, 0, 1))

	_, err := client.LookupHost(t.Context(), "example.com")
	if err == nil {
		t.Error("expected error with no DNS servers")
	}
}

// TestDHCPResult tests the DHCPResult accessor.
func TestDHCPResult(t *testing.T) {
	client := vclient.New([6]byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x30}, func([]byte) error { return nil })
	defer client.Close()

	result := client.DHCPResult()
	if result == nil {
		t.Fatal("DHCPResult() returned nil")
	}
	if result.IP == nil {
		t.Error("DHCPResult().IP should not be nil")
	}
}
