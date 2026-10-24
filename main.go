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
	stats    *listenerStats
	fromFile bool // from a config file rather than the command line
	disabled bool // saved as enabled = false
}

func parseForward(value string) (forwarding, error) {
	if strings.Count(value, "@") != 1 {
		return forwarding{}, fmt.Errorf("%q must have the form listen@target, like 8080@10.0.0.6 or 0.0.0.0:8080@10.0.0.6:80", value)
	}
	listen, target, _ := strings.Cut(value, "@")
	return newForwarding(listen, target)
}

func main() {
	if len(os.Args) == 2 && (os.Args[1] == "--version" || os.Args[1] == "-version") {
		fmt.Println("pf-simple " + version)
		return
	}
	log.Printf("pf-simple %s", version)
	cfg, err := parseArgs(os.Args[1:], os.Stderr, os.Getenv("PF_PASSWORD"))
	if err != nil {
		exitForArgsError(err)
	}
	var policy *managePolicy
	if cfg.console != nil {
		policy = cfg.console.manage
	}
	mgr := newManager(cfg.forwards, policy, halfCloseIdleTimeout)
	mgr.configPath, mgr.consoleRaw = cfg.configPath, cfg.consoleRaw
	var console *consoleServer
	if cfg.console != nil {
		console = newConsoleServer(cfg.console.addr, cfg.console.password, mgr)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, mgr, console); err != nil && !errors.Is(err, context.Canceled) {
		log.Fatal(err)
	}
}

func run(ctx context.Context, mgr *manager, console *consoleServer) error {
	if err := mgr.startAll(ctx); err != nil {
		return err
	}
	var wg sync.WaitGroup
	if console != nil {
		ln, err := net.Listen("tcp", console.addr)
		if err != nil {
			mgr.shutdown()
			return fmt.Errorf("console listen on %s: %w", console.addr, err)
		}
		mode := "password required"
		if console.password == "" {
			mode = "no password"
		}
		if console.mgr.policy != nil {
			mode += ", listener management on"
		}
		log.Printf("console on http://%s%s/ (%s)", ln.Addr(), consolePrefix, mode)
		wg.Add(1)
		go func() {
			defer wg.Done()
			console.serve(ctx, ln)
		}()
	}
	<-ctx.Done()
	mgr.shutdown()
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
		id, start := connIDs.Add(1), time.Now()
		if !l.admit() {
			l.rejected.Add(1)
			changes.notify()
			flows.refused(id, l, start, client, flowRefused, fmt.Sprintf("max_connections (%d) reached", l.maxConns))
			reject(client)
			continue
		}
		l.conns.Add(1)
		go func() {
			defer l.conns.Done()
			handleConnection(ctx, id, start, client, l, idleTimeout)
		}()
	}
}

// reject refuses a connection over max_connections with an immediate RST.
func reject(c net.Conn) {
	if tcp, ok := c.(*net.TCPConn); ok {
		_ = tcp.SetLinger(0)
	}
	_ = c.Close()
}

// handleConnection forwards one client. ctx is the listener's: stopping the
// listener cancels a dial that is still in progress.
func handleConnection(ctx context.Context, id uint64, start time.Time, client net.Conn, l *listenerStats, idleTimeout time.Duration) {
	defer l.release()
	l.accepted.Add(1)
	changes.notify()
	dialCtx, cancel := context.WithTimeout(ctx, dialTimeout)
	upstream, err := (&net.Dialer{}).DialContext(dialCtx, "tcp", l.target)
	cancel()
	if err != nil {
		if ctx.Err() == nil {
			l.failed.Add(1)
			changes.notify()
			log.Printf("connect to %s: %v", l.target, err)
			flows.refused(id, l, start, client, flowFailed, err.Error())
		} else {
			flows.refused(id, l, start, client, flowRefused, "listener stopped")
		}
		reject(client)
		return
	}
	defer client.Close()
	defer upstream.Close()
	p := pipes.add(id, start, l, client, upstream)
	if p == nil { // the listener is stopping
		flows.refused(id, l, start, client, flowRefused, "listener stopped")
		reject(client)
		reject(upstream)
		return
	}
	idle := false
	// Runs before the deferred Closes, so the flow log sees the pipe's final
	// counts and both addresses.
	defer func() {
		pipes.remove(p)
		flows.ended(p, idle)
	}()
	defer p.end()
	flows.opened(p)

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
			if p.up.throttling.Load() || p.down.throttling.Load() {
				timer.Reset(idleTimeout)
				continue
			}
			// Activity and the timer may become ready together. Honor a
			// completed throttle wait before treating the connection as idle.
			select {
			case <-activity:
				timer.Reset(idleTimeout)
				continue
			default:
			}
			idle = true
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
			if !f.throttle(int64(n)) {
				return context.Canceled
			}
			w, werr := dst.Write(buf[:n])
			f.wrote(int64(w))
			if werr != nil {
				return werr
			}
			if w != n {
				return io.ErrShortWrite
			}
		}
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
	}
}
