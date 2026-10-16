package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"
)

const halfCloseIdleTimeout = 30 * time.Second
const dialTimeout = 5 * time.Second

// copyChunkSize is the most data moved per read/splice call in either direction.
const copyChunkSize = 64 << 10

type forwarding struct {
	listen   string
	target   string
	listener net.Listener
	stats    *listenerStats
}

func parseForward(value string) (forwarding, error) {
	if strings.Count(value, "@") != 1 {
		return forwarding{}, fmt.Errorf("%q must have the form listen@target, like 8080@10.0.0.6 or 0.0.0.0:8080@10.0.0.6:80", value)
	}
	listen, target, _ := strings.Cut(value, "@")
	return newForwarding(listen, target)
}

func main() {
	cfg, err := parseArgs(os.Args[1:], os.Stderr, os.Getenv("PF_PASSWORD"))
	if err != nil {
		exitForArgsError(err)
	}
	for i := range cfg.forwards {
		cfg.forwards[i].stats.id = i
	}
	var console *consoleServer
	if cfg.console != nil {
		console = newConsoleServer(cfg.console.addr, cfg.console.password, cfg.forwards)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, cfg.forwards, console); err != nil && !errors.Is(err, context.Canceled) {
		log.Fatal(err)
	}
}

func run(ctx context.Context, forwards []forwarding, console *consoleServer) error {
	closeAll := func(n int) {
		for j := 0; j < n; j++ {
			_ = forwards[j].listener.Close()
		}
	}
	for i := range forwards {
		ln, err := net.Listen("tcp", forwards[i].listen)
		if err != nil {
			closeAll(i)
			return fmt.Errorf("listen on %s: %w", forwards[i].listen, err)
		}
		forwards[i].listener = ln
		log.Printf("forwarding %s -> %s%s", forwards[i].stats.labelFor(ln.Addr().String()), forwards[i].target, forwards[i].stats.limitsNote())
	}

	var wg sync.WaitGroup
	if console != nil {
		ln, err := net.Listen("tcp", console.addr)
		if err != nil {
			closeAll(len(forwards))
			return fmt.Errorf("console listen on %s: %w", console.addr, err)
		}
		if console.password == "" {
			log.Printf("console on http://%s (no password)", ln.Addr())
		} else {
			log.Printf("console on http://%s (password required)", ln.Addr())
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			console.serve(ctx, ln)
		}()
	}
	for i := range forwards {
		f := forwards[i]
		wg.Add(1)
		go func() {
			defer wg.Done()
			acceptConnections(ctx, f.listener, f.stats, halfCloseIdleTimeout)
		}()
	}
	<-ctx.Done()
	closeAll(len(forwards))
	wg.Wait()
	return ctx.Err()
}

func acceptConnections(ctx context.Context, ln net.Listener, l *listenerStats, idleTimeout time.Duration) {
	for {
		client, err := ln.Accept()
		if err != nil {
			if ctx.Err() == nil {
				log.Printf("accept on %s: %v", ln.Addr(), err)
			}
			return
		}
		if !l.admit() {
			l.rejected.Add(1)
			changes.notify()
			reject(client)
			continue
		}
		go handleConnection(client, l, idleTimeout)
	}
}

// reject refuses a connection over max_connections with an immediate RST.
func reject(c net.Conn) {
	if tcp, ok := c.(*net.TCPConn); ok {
		_ = tcp.SetLinger(0)
	}
	_ = c.Close()
}

func handleConnection(client net.Conn, l *listenerStats, idleTimeout time.Duration) {
	defer l.release()
	l.accepted.Add(1)
	changes.notify()
	upstream, err := net.DialTimeout("tcp", l.target, dialTimeout)
	if err != nil {
		l.failed.Add(1)
		changes.notify()
		log.Printf("connect to %s: %v", l.target, err)
		_ = client.Close()
		return
	}
	defer client.Close()
	defer upstream.Close()
	p := pipes.add(l, client, upstream)
	defer pipes.remove(p)
	defer p.end()

	// Each copy direction ends independently. CloseWrite propagates its EOF
	// without preventing the opposite direction from returning a final response.
	done := make(chan struct{}, 2)
	activity := make(chan struct{}, 1)
	signalActivity := func() {
		select {
		case activity <- struct{}{}:
		default:
		}
	}
	p.up.activity = signalActivity
	p.down.activity = signalActivity
	copyDirection := func(dst, src net.Conn, f *flow) {
		_ = copyStream(dst, src, f)
		f.finish()
		if p.interrupted.Load() {
			done <- struct{}{}
			return // the pipe is being reset; a FIN would race the RST
		}
		if cw, ok := dst.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
		done <- struct{}{}
	}
	go copyDirection(upstream, client, &p.up)
	go copyDirection(client, upstream, &p.down)

	completed := 0
	var timer *time.Timer
	var timeout <-chan time.Time
	for completed < 2 {
		select {
		case <-done:
			completed++
			if completed == 1 {
				timer = time.NewTimer(idleTimeout)
				timeout = timer.C
			}
		case <-activity:
			if timer != nil {
				if !timer.Stop() {
					select {
					case <-timer.C:
					default:
					}
				}
				timer.Reset(idleTimeout)
			}
		case <-timeout:
			return // deferred Close interrupts the remaining blocked copy.
		}
	}
	if timer != nil {
		timer.Stop()
	}
}

// copyBuffered moves src to dst through a user-space buffer, counting bytes
// and reporting activity after every write that makes progress.
func copyBuffered(dst, src net.Conn, f *flow) error {
	buf := make([]byte, f.chunk())
	for {
		n, err := src.Read(buf)
		if n > 0 {
			f.gotRead(int64(n))
			w, werr := dst.Write(buf[:n])
			f.wrote(int64(w))
			if werr != nil {
				return werr
			}
			f.throttle(int64(w))
		}
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
	}
}
