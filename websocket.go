package main

import (
	"net/http"

	"github.com/wushilin/pf-simple/internal/tunnel"
)

// The WebSocket implementation lives in internal/tunnel, shared with
// pf-client. These names keep the console code short.

type wsConn = tunnel.Conn

const (
	wsOpText  = tunnel.OpText
	wsOpClose = tunnel.OpClose
	wsOpPing  = tunnel.OpPing
)

var headerHasToken = tunnel.HeaderHasToken

func upgradeWebSocket(w http.ResponseWriter, r *http.Request) (*wsConn, error) {
	return tunnel.Upgrade(w, r, nil)
}
