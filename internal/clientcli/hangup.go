package clientcli

import (
	"context"
	"os"
	"os/signal"
	"syscall"
	"time"
)

// hangupGrace is how long a stdio run outlives a SIGHUP. ssh sends its
// ProxyCommand SIGHUP as it exits, right after closing the pipes to it, so
// the connection is then usually finishing: both sides half-closing. Dying
// at once would cut it instead, and a cut connection is counted as failed
// and costs the serving side the leg the server could otherwise reuse.
var hangupGrace = 2 * time.Second

// onHangup returns a context that ends grace after the first SIGHUP, or
// when parent ends. Until then a SIGHUP does not stop the program.
func onHangup(parent context.Context, grace time.Duration) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(parent)
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	go func() {
		defer signal.Stop(hup)
		select {
		case <-hup:
		case <-ctx.Done():
			return
		}
		t := time.NewTimer(grace)
		defer t.Stop()
		select {
		case <-t.C:
			cancel()
		case <-ctx.Done():
		}
	}()
	return ctx, cancel
}
