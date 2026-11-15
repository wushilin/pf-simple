//go:build unix

package main

import (
	"context"
	"syscall"
	"testing"
	"time"
)

func TestHangupGivesGrace(t *testing.T) {
	ctx, cancel := onHangup(context.Background(), 300*time.Millisecond)
	defer cancel()
	time.Sleep(20 * time.Millisecond) // signal.Notify is in place before onHangup returns; be safe anyway
	start := time.Now()
	if err := syscall.Kill(syscall.Getpid(), syscall.SIGHUP); err != nil {
		t.Fatal(err)
	}
	select {
	case <-ctx.Done():
		t.Fatalf("ended %v after SIGHUP, before the grace", time.Since(start))
	case <-time.After(150 * time.Millisecond):
	}
	select {
	case <-ctx.Done():
		if d := time.Since(start); d < 300*time.Millisecond {
			t.Fatalf("ended after %v, want the 300ms grace", d)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("still running 2s after SIGHUP")
	}
}

func TestHangupEndsWithParent(t *testing.T) {
	parent, stop := context.WithCancel(context.Background())
	ctx, cancel := onHangup(parent, time.Hour)
	defer cancel()
	stop()
	select {
	case <-ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("did not end with its parent")
	}
}
