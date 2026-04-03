package vclient

import (
	"github.com/KarpelesLab/slirp"
)

// Pipe creates a Client wired to a slirp Stack. IP packets sent by the client
// are fed directly to the stack's HandlePacket. Responses from the stack are
// delivered to the client's HandlePacket.
//
// Use SetIP/SetDNS after Pipe to configure the client's network.
func Pipe(stack *slirp.Stack, namespace uintptr) *Client {
	c := New(nil) // writer set below

	c.SetWriter(func(packet []byte) error {
		return stack.HandlePacket(namespace, packet, c.HandlePacket)
	})

	return c
}
