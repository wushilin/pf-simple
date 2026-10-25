//go:build linux

package main

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"
	"net"
	"os"
	"syscall"
	"testing"
	"time"
)

// pacedStream sends total bytes from a sender to a receiver through
// copyStream, written as write-sized segments in bursts every millisecond so
// the stream arrives at rate bytes/s (0: as fast as it goes). It returns the
// process CPU time it took and checks every byte arrived in order.
func pacedStream(t testing.TB, total, write int, rate float64, linger bool) time.Duration {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	sink, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer sink.Close()

	sum := make(chan [32]byte, 1)
	go func() {
		c, err := sink.Accept()
		if err != nil {
			sum <- [32]byte{}
			return
		}
		defer c.Close()
		h := sha256.New()
		_, _ = io.Copy(h, c)
		var s [32]byte
		copy(s[:], h.Sum(nil))
		sum <- s
	}()
	copied := make(chan error, 1)
	go func() {
		in, err := ln.Accept()
		if err != nil {
			copied <- err
			return
		}
		defer in.Close()
		out, err := net.Dial("tcp", sink.Addr().String())
		if err != nil {
			copied <- err
			return
		}
		f := &flow{linger: linger}
		err = copyStream(out, in, f)
		out.(*net.TCPConn).CloseWrite()
		out.Close()
		copied <- err
	}()

	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	c.(*net.TCPConn).SetNoDelay(true) // one segment per write
	payload := bytes.Repeat([]byte("0123456789abcdef"), (write+15)/16)[:write]
	want := sha256.New()
	before := cpuTime()
	start := time.Now()
	perTick := total
	if rate > 0 {
		perTick = max(write, int(rate/1000))
	}
	for sent := 0; sent < total; {
		for n := 0; n < perTick && sent < total; n += write {
			if _, err := c.Write(payload); err != nil {
				t.Fatal(err)
			}
			want.Write(payload)
			sent += write
		}
		if rate > 0 {
			next := start.Add(time.Duration(float64(sent) / rate * float64(time.Second)))
			time.Sleep(time.Until(next))
		}
	}
	c.Close()
	if err := <-copied; err != nil {
		t.Fatal(err)
	}
	got := <-sum
	if !bytes.Equal(got[:], want.Sum(nil)) {
		t.Fatal("the stream arrived corrupted")
	}
	return cpuTime() - before
}

func cpuTime() time.Duration {
	var ru syscall.Rusage
	_ = syscall.Getrusage(syscall.RUSAGE_SELF, &ru)
	return time.Duration(ru.Utime.Nano() + ru.Stime.Nano())
}

// A paced stream of small segments arrives intact, lingering or not.
func TestSpliceCoalesceIntact(t *testing.T) {
	for _, rate := range []float64{0, 50e6, 1e6} {
		pacedStream(t, 8<<20, 1448, rate, true)
		pacedStream(t, 8<<20, 1448, rate, false)
	}
}

// TestSpliceCoalesceCPU compares CPU time with lingering off and on. It is
// a measurement, not a check: set PF_COALESCE_BENCH=1 to run it.
func TestSpliceCoalesceCPU(t *testing.T) {
	if os.Getenv("PF_COALESCE_BENCH") == "" {
		t.Skip("set PF_COALESCE_BENCH=1 to measure")
	}
	const total = 400 << 20
	for _, rate := range []float64{20e6, 50e6, 100e6, 200e6, 400e6, 0} {
		var cpu [2]time.Duration
		for i, on := range []bool{false, true} {
			cpu[i] = pacedStream(t, total, 1448, rate, on)
		}
		label := "unpaced"
		if rate > 0 {
			label = fmt.Sprintf("%.0f MB/s", rate/1e6)
		}
		t.Logf("%-9s off %7.0fms  on %7.0fms  (%+.0f%%)", label,
			float64(cpu[0].Milliseconds()), float64(cpu[1].Milliseconds()),
			100*(float64(cpu[1])/float64(cpu[0])-1))
	}
}
