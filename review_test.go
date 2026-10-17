package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestListenerSaveFailurePreservesState(t *testing.T) {
	for _, action := range []string{"add", "start", "stop", "edit", "delete"} {
		t.Run(action, func(t *testing.T) {
			target := startServer(t, func(c *net.TCPConn) { _, _ = io.Copy(c, c) })
			var forwards []forwarding
			for i := 0; i < 3; i++ {
				fw, _, err := buildForwarding(listenerSpec{
					Name: fmt.Sprintf("listener %d", i), Listen: fmt.Sprintf("127.0.0.1:%d", freePort(t)), Target: target,
				})
				if err != nil {
					t.Fatal(err)
				}
				fw.fromFile, fw.disabled = true, action != "stop"
				forwards = append(forwards, fw)
			}
			mgr := newManager(forwards, &managePolicy{}, halfCloseIdleTimeout)
			mgr.configPath = filepath.Join(t.TempDir(), "pf.toml")
			if err := mgr.saveLocked(); err != nil {
				t.Fatal(err)
			}
			path := mgr.configPath
			before := readFile(t, path)
			if err := mgr.startAll(context.Background()); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				mgr.mu.Lock()
				defer mgr.mu.Unlock()
				for _, ml := range mgr.list {
					mgr.stopLocked(ml, true)
				}
			})
			ml := mgr.list[1]
			stats, enabled, running := ml.stats, ml.enabled, ml.running
			ml.lastErr = "previous error"
			var client *net.TCPConn
			if running {
				client = dial(t, ml.stats.listen)
				if _, err := client.Write([]byte("a")); err != nil {
					t.Fatal(err)
				}
				if _, err := io.ReadFull(client, make([]byte, 1)); err != nil {
					t.Fatal(err)
				}
			}
			// Renaming over a directory fails even when tests run as root.
			mgr.configPath = filepath.Dir(path)
			var err error
			switch action {
			case "add":
				_, err = mgr.add(listenerSpec{Listen: fmt.Sprintf("127.0.0.1:%d", freePort(t)), Target: target})
			case "start":
				err = mgr.start(ml.stats.id)
			case "stop":
				err = mgr.stop(ml.stats.id)
			case "edit":
				spec := ml.stats.spec
				spec.Name = "changed"
				err = mgr.edit(ml.stats.id, spec)
			case "delete":
				err = mgr.remove(ml.stats.id)
			}
			if err == nil {
				t.Fatal("expected save failure")
			}
			if len(mgr.list) != 3 || mgr.list[1] != ml || ml.stats != stats || ml.enabled != enabled || ml.running != running || ml.lastErr != "previous error" {
				t.Fatalf("failed %s changed listener state: %+v", action, ml)
			}
			if readFile(t, path) != before {
				t.Fatal("failed save changed the config")
			}
			if client != nil {
				if _, err := client.Write([]byte("b")); err != nil {
					t.Fatal(err)
				}
				buf := make([]byte, 1)
				if _, err := io.ReadFull(client, buf); err != nil || string(buf) != "b" {
					t.Fatalf("failed stop interrupted an existing pipe: %q %v", buf, err)
				}
			} else {
				if conn, err := net.DialTimeout("tcp", ml.stats.listen, time.Second); err == nil {
					conn.Close()
					t.Fatal("failed operation left a listener running")
				}
			}
			entries, err := filepath.Glob(filepath.Join(filepath.Dir(path), ".pf-simple-*.toml"))
			if err != nil || len(entries) != 0 {
				t.Fatalf("temporary configs left behind: %v %v", entries, err)
			}
		})
	}
}

func TestRateLimitedReplySurvivesHalfCloseIdleTimeout(t *testing.T) {
	payload := bytes.Repeat([]byte("x"), 768)
	target := startServer(t, func(c *net.TCPConn) {
		_, _ = io.Copy(io.Discard, c)
		_, _ = c.Write(payload)
	})
	addr := startLimitedForwarderWithIdle(t, target, 200*time.Millisecond, func(l *listenerStats) {
		l.perConnRate = 256 // each full chunk waits one second after the burst
	})
	client := dial(t, addr)
	if err := client.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(client)
	if err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("slow reply truncated: got %d of %d bytes, err=%v", len(got), len(payload), err)
	}
}

func TestTotalLimitBoundsBurstAcrossNewConnections(t *testing.T) {
	const connections = 8
	received := make(chan struct{}, connections)
	target := startServer(t, func(c *net.TCPConn) {
		if _, err := io.ReadFull(c, make([]byte, 256)); err == nil {
			received <- struct{}{}
		}
	})
	addr := startLimitedForwarder(t, target, func(l *listenerStats) {
		l.totalRate = 1024
		l.totalUp, l.totalDown = newLimiter(l.totalRate), newLimiter(l.totalRate)
	})
	start := time.Now()
	for i := 0; i < connections; i++ {
		c := dial(t, addr)
		if _, err := c.Write(make([]byte, 256)); err != nil {
			t.Fatal(err)
		}
		_ = c.CloseWrite()
	}
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	for i := 0; i < connections; i++ {
		select {
		case <-received:
		case <-deadline.C:
			t.Fatal("rate-limited connections did not finish")
		}
	}
	if elapsed := time.Since(start); elapsed < 1500*time.Millisecond {
		t.Fatalf("new connections bypassed shared limit: 2048 bytes arrived in %v", elapsed)
	}
}

func TestBufferedCopyWaitsBeforeDeliveryAndCancels(t *testing.T) {
	src, producer := net.Pipe()
	dst, consumer := net.Pipe()
	defer src.Close()
	defer producer.Close()
	defer dst.Close()
	defer consumer.Close()
	cancel := make(chan struct{})
	lim := newLimiter(1)
	lim.tokens = 0 // no initial burst: even the first byte must wait
	f := &flow{total: lim, cancel: cancel}
	done := make(chan error, 1)
	go func() { done <- copyBuffered(dst, src, f) }()
	if _, err := producer.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	_ = consumer.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	if n, err := consumer.Read(make([]byte, 1)); n != 0 || !os.IsTimeout(err) {
		t.Fatalf("copy delivered bytes before reserving capacity: n=%d err=%v", n, err)
	}
	close(cancel)
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled copy: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("cancel did not interrupt rate-limit wait")
	}
	if f.written.Load() != 0 || f.throttling.Load() {
		t.Fatal("canceled wait forwarded bytes or remained marked as throttling")
	}
}
