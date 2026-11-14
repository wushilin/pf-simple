package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/wushilin/pf-simple/pfrelay"
)

// The SDK's own API, Listen and Dial, against a real hub.

func listenSDK(t *testing.T, f *relayFixture, ctx context.Context) *pfrelay.Listener {
	t.Helper()
	server := f.client(t, testWord, testServeToken)
	l, err := server.Listen(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	return l
}

// echo serves each accepted connection by sending back what it reads, and
// half-closes when its peer does.
func echo(l *pfrelay.Listener) {
	for {
		conn, err := l.AcceptConn()
		if err != nil {
			return
		}
		go func() {
			defer conn.Close()
			_, _ = io.Copy(conn, conn)
			_ = conn.CloseWrite()
		}()
	}
}

func TestSDKListenDial(t *testing.T) {
	f := newRelayFixture(t, "")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	l := listenSDK(t, f, ctx)
	if !l.Up() {
		t.Fatal("Listen returned before registering")
	}
	go echo(l)

	connector := f.client(t, testWord, "")
	payload := make([]byte, 3<<20)
	_, _ = rand.Read(payload)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			conn, err := connector.Dial(ctx)
			if err != nil {
				t.Error(err)
				return
			}
			defer conn.Close()
			go func() {
				_, _ = conn.Write(payload)
				_ = conn.CloseWrite()
			}()
			got, err := io.ReadAll(conn)
			if err != nil || !bytes.Equal(got, payload) {
				t.Errorf("echoed %d bytes, %v; want %d", len(got), err, len(payload))
			}
		}()
	}
	wg.Wait()

	st := connector.Stats()
	if st.Opened != 8 || st.Failed != 0 || st.Sent != 8*int64(len(payload)) || st.Received != st.Sent {
		t.Errorf("connector stats = %+v", st)
	}
	if n := len(connector.Conns()); n != 0 {
		t.Errorf("%d connections still listed after all were closed", n)
	}
}

func TestSDKConnsAndDeadlines(t *testing.T) {
	f := newRelayFixture(t, "")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	l := listenSDK(t, f, ctx)

	connector := f.client(t, testWord, "")
	conn, err := connector.Dial(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	accepted, err := l.AcceptConn()
	if err != nil {
		t.Fatal(err)
	}
	defer accepted.Close()
	if accepted.ID() != conn.ID() || len(conn.ID().String()) != 16 {
		t.Errorf("ids: connect %q, serve %q", conn.ID(), accepted.ID())
	}

	if _, err := conn.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 5)
	if _, err := io.ReadFull(accepted, buf); err != nil || string(buf) != "hello" {
		t.Fatalf("read %q, %v", buf, err)
	}
	list := connector.Conns()
	if len(list) != 1 || list[0].ID != conn.ID() || list[0].Side != pfrelay.SideConnect || list[0].Sent != 5 {
		t.Errorf("Conns() = %+v", list)
	}

	// A read deadline that passes leaves the connection usable.
	_ = accepted.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	if _, err := accepted.Read(buf); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("read past the deadline = %v", err)
	}
	var ne net.Error
	if _, err := accepted.Read(buf); !errors.As(err, &ne) || !ne.Timeout() {
		t.Fatalf("a passed deadline is not a timeout: %v", err)
	}
	// Moving the deadline wakes a reader that waits on the old one.
	_ = accepted.SetReadDeadline(time.Time{})
	got := make(chan error, 1)
	go func() {
		_, err := accepted.Read(buf)
		got <- err
	}()
	time.Sleep(50 * time.Millisecond)
	_ = accepted.SetReadDeadline(time.Now().Add(20 * time.Millisecond))
	select {
	case err := <-got:
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("read = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a shortened deadline did not wake the reader")
	}
	_ = accepted.SetReadDeadline(time.Time{})
	if _, err := conn.Write([]byte("again")); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(accepted, buf); err != nil || string(buf) != "again" {
		t.Fatalf("after the deadline: %q, %v", buf, err)
	}
}

// Fail's reason reaches the far end as a *RemoteError.
func TestSDKFailReason(t *testing.T) {
	f := newRelayFixture(t, "")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	f.hub.idle = 300 * time.Millisecond // the hub ends a half-closed, idle connection, and says why
	l := listenSDK(t, f, ctx)
	connector := f.client(t, testWord, "")
	conn, err := connector.Dial(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	accepted, err := l.AcceptConn()
	if err != nil {
		t.Fatal(err)
	}
	accepted.Fail("the database is down")
	// The hub passes the failure on as a half-close, then the reason.
	if _, err := conn.Read(make([]byte, 1)); err != io.EOF {
		var remote *pfrelay.RemoteError
		if !errors.As(err, &remote) {
			t.Fatalf("read = %v", err)
		}
	}
	var remote *pfrelay.RemoteError
	waitFor(t, "the reason", func() bool { return errors.As(conn.Err(), &remote) })
	if remote.Reason != "the database is down" {
		t.Fatalf("Err() = %v", remote)
	}
	if st := connector.Stats(); st.Failed != 0 { // not until it is closed
		t.Errorf("stats before Close = %+v", st)
	}
	conn.Close()
	if st := connector.Stats(); st.Failed != 1 || st.Active != 0 {
		t.Errorf("stats after Close = %+v", st)
	}
}

// Listen reports a refusal that waiting cannot cure, and Dial a wrong word.
func TestSDKRefusals(t *testing.T) {
	f := newRelayFixture(t, "")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	bad := f.client(t, testWord, "wrong-serve-token-0123456789abcdefgh")
	if _, err := bad.Listen(ctx); !errors.Is(err, pfrelay.ErrAccessDenied) {
		t.Errorf("Listen with a wrong serve token = %v", err)
	}
	if _, err := f.client(t, otherWord, "").Dial(ctx); !errors.Is(err, pfrelay.ErrAccessDenied) {
		t.Errorf("Dial with nobody serving = %v", err)
	}
	// A listener that is closed refuses what has not been accepted.
	l := listenSDK(t, f, ctx)
	l.Close()
	if _, err := l.Accept(); !errors.Is(err, net.ErrClosed) {
		t.Errorf("Accept after Close = %v", err)
	}
}
