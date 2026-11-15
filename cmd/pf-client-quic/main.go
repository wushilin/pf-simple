// pf-client-quic is pf-client over QUIC (tunnel protocol 3): the same
// commands and flags, with the hub reached over its QUIC listener instead
// of WebSockets. It works with pf-client on the other side of a tunnel.
// Where UDP is blocked it cannot connect; use pf-client there.
package main

import (
	"os"

	"github.com/wushilin/pf-simple/internal/clientcli"
	"github.com/wushilin/pf-simple/pfrelayquic"
)

func main() {
	// quic-go says on stderr when the system's UDP buffers are smaller than
	// it would like. As an ssh ProxyCommand that lands in the user's
	// terminal on every connection, and it changes nothing: say nothing.
	if os.Getenv("QUIC_GO_DISABLE_RECEIVE_BUFFER_WARNING") == "" {
		_ = os.Setenv("QUIC_GO_DISABLE_RECEIVE_BUFFER_WARNING", "true")
	}
	clientcli.Main(clientcli.Program{
		Name: "pf-client-quic", Version: version, NewClient: pfrelayquic.NewClient,
		ProtoMin: pfrelayquic.Proto, ProtoMax: pfrelayquic.Proto,
	})
}
