// pf-client is the client of pf-simple's ad-hoc tunnels over WebSocket: one
// side serves a local target, the other connects to it through a local
// port, and they meet at a pf-simple server by a shared word. See
// internal/clientcli.
package main

import (
	"github.com/wushilin/pf-simple/internal/clientcli"
	"github.com/wushilin/pf-simple/pfrelay"
)

func main() {
	clientcli.Main(clientcli.Program{
		Name: "pf-client", Version: version, NewClient: pfrelay.NewClient,
		ProtoMin: pfrelay.ProtoMin, ProtoMax: pfrelay.ProtoMax,
	})
}
