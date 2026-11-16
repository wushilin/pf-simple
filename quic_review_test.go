package main

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/wushilin/pf-simple/internal/tunnel"
)

// Regression tests for a review of the Go QUIC SDK.

// A connecting client whose application stops reading several connections
// still gets answers on its QUIC connection: a stalled stream holds up only
// itself (§13.3). With the hub's pre-authentication window (256 KiB) as the
// client's connection window, four stalled streams stopped everything.
func TestQUICStalledStreamsDoNotStarveTheConnection(t *testing.T) {
	f := newRelayFixture(t, "")
	f.withQUIC(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// A target that sends 4 MiB to each connection and never reads.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_, _ = c.Write(make([]byte, 4<<20))
				<-ctx.Done()
			}()
		}
	}()
	server := f.client(t, testWord, testServeToken)
	go func() { _ = server.Serve(ctx, ln.Addr().String()) }()
	dialer := f.quicClient(t, testWord, "")
	waitFor(t, "the word to be served", func() bool { return dialer.Check(ctx) == nil })

	for i := 0; i < 8; i++ { // twice what used to freeze it
		conn, err := dialer.Dial(ctx)
		if err != nil {
			t.Fatalf("dial %d: %v", i, err)
		}
		defer conn.Close()
	}
	time.Sleep(time.Second) // let the windows fill
	cctx, ccancel := context.WithTimeout(ctx, 5*time.Second)
	defer ccancel()
	if err := dialer.Check(cctx); err != nil {
		t.Fatalf("check with stalled connections open: %v", err)
	}
}

// Write, then Close without waiting for the far end: over QUIC as over
// WebSocket, what was written arrives. A reset used to discard it.
func TestQUICWriteThenCloseDelivers(t *testing.T) {
	f := newRelayFixture(t, "")
	f.withQUIC(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	got := make(chan int, 64)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				n, _ := io.Copy(io.Discard, c)
				got <- int(n)
			}()
		}
	}()
	server := f.client(t, testWord, testServeToken)
	go func() { _ = server.Serve(ctx, ln.Addr().String()) }()
	dialer := f.quicClient(t, testWord, "")
	waitFor(t, "the word to be served", func() bool { return dialer.Check(ctx) == nil })

	const size, rounds = 100 << 10, 10
	for i := 0; i < rounds; i++ {
		conn, err := dialer.Dial(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := conn.Write(make([]byte, size)); err != nil {
			t.Fatal(err)
		}
		conn.Close()
	}
	for i := 0; i < rounds; i++ {
		select {
		case n := <-got:
			if n != size {
				t.Errorf("the target got %d bytes of %d", n, size)
			}
		case <-time.After(15 * time.Second):
			t.Fatalf("only %d of %d connections reached the target", i, rounds)
		}
	}
}

// A connection the hub answered 429 for (scope "connection") gets no more
// requests, and is closed (none) once it holds nothing, not left open on
// its keepalive (§13.8).
func TestQUICRetiredConnectionIsClosed(t *testing.T) {
	f := newRelayFixture(t, "")
	q := f.withQUIC(t)
	ctx := context.Background()
	conns := func() int {
		q.mu.Lock()
		defer q.mu.Unlock()
		return len(q.conns)
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	server := f.client(t, testWord, testServeToken) // over WebSocket: not counted
	server.ClientToken = "open-sesame"
	go func() { _ = server.Serve(ctx, echoTarget(t)) }()
	guesser := f.quicClient(t, testWord, "")
	guesser.ClientToken = "open-sesame"
	waitFor(t, "the word to be served", func() bool { return guesser.Check(ctx) == nil })
	// Discovery is done: wrong guesses now go over the QUIC connection.
	guesser.ClientToken = "wrong-guess"
	var se *tunnel.StatusError
	for i := 0; i < 10; i++ {
		err := guesser.Check(ctx)
		if errors.As(err, &se) && se.Code == http.StatusTooManyRequests {
			break
		}
		se = nil
	}
	if se == nil {
		t.Fatal("no 429 after 10 refused checks")
	}
	waitFor(t, "the retired connection to be closed", func() bool { return conns() == 0 })
}
