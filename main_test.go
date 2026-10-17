package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"io"
	"net"
	"testing"
	"time"
)

// startForwarder forwards a fresh local port to target and returns its address.
func startForwarder(t *testing.T, target string, idleTimeout time.Duration) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() { cancel(); ln.Close() })
	go acceptConnections(ctx, ln, newListenerStats(0, ln.Addr().String(), target), idleTimeout)
	return ln.Addr().String()
}

// startServer runs handle for each accepted connection and returns its address.
func startServer(t *testing.T, handle func(*net.TCPConn)) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				handle(c.(*net.TCPConn))
			}()
		}
	}()
	return ln.Addr().String()
}

func dial(t *testing.T, addr string) *net.TCPConn {
	t.Helper()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	_ = c.SetDeadline(time.Now().Add(20 * time.Second))
	return c.(*net.TCPConn)
}

func TestBidirectionalIntegrity(t *testing.T) {
	const size = 32 << 20
	payload := make([]byte, size)
	if _, err := rand.Read(payload); err != nil {
		t.Fatal(err)
	}
	want := sha256.Sum256(payload)

	// The server hashes what it receives and streams the payload back at the
	// same time, so both directions carry data concurrently.
	gotUp := make(chan [32]byte, 1)
	target := startServer(t, func(c *net.TCPConn) {
		writerDone := make(chan struct{})
		go func() {
			defer close(writerDone)
			_, _ = c.Write(payload)
			_ = c.CloseWrite()
		}()
		h := sha256.New()
		_, _ = io.Copy(h, c)
		// startServer closes c when this handler returns. Finish sending
		// before returning, even when the upload completes first.
		<-writerDone
		var sum [32]byte
		copy(sum[:], h.Sum(nil))
		gotUp <- sum
	})
	c := dial(t, startForwarder(t, target, halfCloseIdleTimeout))

	go func() {
		_, _ = c.Write(payload)
		_ = c.CloseWrite()
	}()
	h := sha256.New()
	if n, err := io.Copy(h, c); err != nil || n != size {
		t.Fatalf("downstream copy: n=%d err=%v", n, err)
	}
	if !bytes.Equal(h.Sum(nil), want[:]) {
		t.Fatal("downstream data corrupted")
	}
	if got := <-gotUp; got != want {
		t.Fatal("upstream data corrupted")
	}
}

func TestHalfCloseReply(t *testing.T) {
	target := startServer(t, func(c *net.TCPConn) {
		n, _ := io.Copy(io.Discard, c) // read until the client's FIN
		time.Sleep(200 * time.Millisecond)
		_, _ = c.Write([]byte{byte(n >> 8), byte(n)})
	})
	c := dial(t, startForwarder(t, target, halfCloseIdleTimeout))
	_, _ = c.Write(make([]byte, 1000))
	_ = c.CloseWrite()
	reply, err := io.ReadAll(c)
	if err != nil || !bytes.Equal(reply, []byte{1000 >> 8, 1000 & 0xff}) {
		t.Fatalf("reply=%v err=%v", reply, err)
	}
}

// A slow trickle after a half-close must keep the connection alive even though
// each gap is shorter than the idle timeout but the total spans many of them.
func TestTrickleAfterHalfCloseStaysOpen(t *testing.T) {
	const ticks = 10
	target := startServer(t, func(c *net.TCPConn) {
		_, _ = io.Copy(io.Discard, c)
		for i := 0; i < ticks; i++ {
			time.Sleep(100 * time.Millisecond)
			_, _ = c.Write([]byte{'t'})
		}
	})
	c := dial(t, startForwarder(t, target, 300*time.Millisecond))
	_ = c.CloseWrite()
	got, _ := io.ReadAll(c)
	if len(got) != ticks {
		t.Fatalf("received %d of %d ticks", len(got), ticks)
	}
}

func TestIdleAfterHalfCloseIsClosed(t *testing.T) {
	target := startServer(t, func(c *net.TCPConn) {
		_, _ = io.Copy(io.Discard, c)
		time.Sleep(3 * time.Second)
	})
	c := dial(t, startForwarder(t, target, 300*time.Millisecond))
	_ = c.CloseWrite()
	start := time.Now()
	_, _ = io.ReadAll(c)
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("connection stayed open %v after going idle", elapsed)
	}
}
