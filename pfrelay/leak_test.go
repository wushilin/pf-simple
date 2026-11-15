package pfrelay

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/wushilin/pf-simple/internal/tunnel"
)

// Connection leaks in the Go SDK, found in review: each test failed, or
// leaked, before its fix.

// Client.Close releases the client's pooled HTTP connections: the server
// sees each of them closed by the client.
func TestLeakHTTPPool(t *testing.T) {
	var open atomic.Int64
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(tunnel.HeaderProto, "2")
		w.WriteHeader(204)
	}))
	srv.Config.ConnState = func(_ net.Conn, st http.ConnState) {
		switch st {
		case http.StateNew:
			open.Add(1)
		case http.StateClosed, http.StateHijacked:
			open.Add(-1)
		}
	}
	srv.StartTLS()
	defer srv.Close()
	cfg := srv.Client().Transport.(*http.Transport).TLSClientConfig
	for i := 0; i < 20; i++ {
		c, err := NewClient(srv.URL, "k3f9-x2mq-7hpa", cfg)
		if err != nil {
			t.Fatal(err)
		}
		if err := c.Check(context.Background()); err != nil {
			t.Fatal(err)
		}
		c.Close()
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && open.Load() != 0 {
		time.Sleep(20 * time.Millisecond)
	}
	if n := open.Load(); n != 0 {
		t.Errorf("20 clients checked and closed: the server still has %d connections from them", n)
	}
}

// Conn.Close behind a Write that the peer is not reading returns, and so
// does a Fail after it.
func TestLeakCloseBehindWrite(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(tunnel.HeaderProto, "2")
		w.Header().Set(tunnel.HeaderConn, "c1")
		if _, err := tunnel.Upgrade(w, r, nil); err != nil {
			return
		}
		// never reads, never closes
	}))
	defer srv.Close()
	c, _ := NewClient(srv.URL, "k3f9-x2mq-7hpa", srv.Client().Transport.(*http.Transport).TLSClientConfig)
	conn, err := c.Dial(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var wrote atomic.Int64
	go func() {
		buf := make([]byte, 64<<10)
		for {
			n, err := conn.Write(buf)
			wrote.Add(int64(n))
			if err != nil {
				t.Logf("Write ended: %v", err)
				return
			}
		}
	}()
	for last := int64(-1); last != wrote.Load(); time.Sleep(300 * time.Millisecond) {
		last = wrote.Load()
	}
	t.Logf("Write is blocked after %d bytes", wrote.Load())
	closed := make(chan struct{})
	go func() { conn.Close(); close(closed) }()
	select {
	case <-closed:
	case <-time.After(8 * time.Second):
		t.Fatalf("Close still blocked after 8s; Active=%d", c.Stats().Active)
	}
	failed := make(chan struct{})
	go func() { conn.Fail("x"); close(failed) }()
	select {
	case <-failed:
	case <-time.After(5 * time.Second):
		t.Fatal("Fail blocked behind Close")
	}
	if st := c.Stats(); st.Active != 0 {
		t.Errorf("stats after Close = %+v", st)
	}
}

// Listener.Close while an accept handshake is in flight: the connection
// that arrives after it is ended, never left queued.
func TestLeakListenerCloseRace(t *testing.T) {
	const trials = 20
	leaked := 0
	for i := 0; i < trials; i++ {
		ctl := make(chan *tunnel.Conn, 1)
		acc := make(chan *tunnel.Conn, 1)
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set(tunnel.HeaderProto, "2")
			switch strings.TrimPrefix(r.URL.Path, tunnel.Path) {
			case "/serve":
				ws, err := tunnel.Upgrade(w, r, nil)
				if err == nil {
					ctl <- ws
				}
			case "/accept":
				time.Sleep(150 * time.Millisecond) // a slow answer: the handshake is in flight
				ws, err := tunnel.Upgrade(w, r, nil)
				if err == nil {
					acc <- ws
				}
			}
		}))
		c, _ := NewClient(srv.URL, "k3f9-x2mq-7hpa", srv.Client().Transport.(*http.Transport).TLSClientConfig)
		c.ServeToken, c.Name = strings.Repeat("s", tunnel.MinSecret), "Script"
		l, err := c.Listen(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		cw := <-ctl
		msg, _ := json.Marshal(tunnel.ControlMessage{Open: "conn-1"})
		_ = cw.WriteFrame(tunnel.OpText, msg)
		time.Sleep(60 * time.Millisecond)
		l.Close()
		ws := <-acc
		// The hub's end of the leg: does the client ever end it?
		s := tunnel.NewStream(ws)
		got := make(chan error, 1)
		go func() { _, e := s.Read(make([]byte, 16)); got <- e }()
		var rerr error
		select {
		case rerr = <-got:
		case <-time.After(1500 * time.Millisecond):
		}
		time.Sleep(200 * time.Millisecond)
		active := c.Stats().Active
		if active != 0 || rerr == nil {
			leaked++
		}
		s.Close()
		srv.CloseClientConnections()
		srv.Close()
	}
	if leaked != 0 {
		t.Errorf("%d of %d unaccepted connections outlived Listener.Close", leaked, trials)
	}
}
