package main

import (
	"context"
	"errors"
	"flag"
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

type forwardsFlag []string

func (f *forwardsFlag) String() string { return strings.Join(*f, ",") }

func (f *forwardsFlag) Set(value string) error {
	*f = append(*f, value)
	return nil
}

type forwarding struct {
	listen   string
	target   string
	listener net.Listener
}

func parseForward(value string) (forwarding, error) {
	if strings.Count(value, "@") != 1 {
		return forwarding{}, fmt.Errorf("%q must have the form listen-address@target-address", value)
	}
	parts := strings.SplitN(value, "@", 2)
	if _, _, err := net.SplitHostPort(parts[0]); err != nil {
		return forwarding{}, fmt.Errorf("invalid listen address %q: %w", parts[0], err)
	}
	if _, _, err := net.SplitHostPort(parts[1]); err != nil {
		return forwarding{}, fmt.Errorf("invalid target address %q: %w", parts[1], err)
	}
	return forwarding{listen: parts[0], target: parts[1]}, nil
}

func main() {
	var values forwardsFlag
	flag.Var(&values, "forward", "TCP mapping listen-address@target-address (repeatable)")
	flag.Parse()
	if len(values) == 0 {
		fmt.Fprintln(os.Stderr, "at least one --forward is required")
		flag.Usage()
		os.Exit(2)
	}
	if flag.NArg() != 0 {
		log.Fatalf("unexpected arguments: %s", strings.Join(flag.Args(), " "))
	}

	forwards := make([]forwarding, 0, len(values))
	for _, value := range values {
		f, err := parseForward(value)
		if err != nil {
			log.Fatal(err)
		}
		forwards = append(forwards, f)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, forwards); err != nil && !errors.Is(err, context.Canceled) {
		log.Fatal(err)
	}
}

func run(ctx context.Context, forwards []forwarding) error {
	for i := range forwards {
		ln, err := net.Listen("tcp", forwards[i].listen)
		if err != nil {
			for j := 0; j < i; j++ {
				_ = forwards[j].listener.Close()
			}
			return fmt.Errorf("listen on %s: %w", forwards[i].listen, err)
		}
		forwards[i].listener = ln
		log.Printf("forwarding %s -> %s", ln.Addr(), forwards[i].target)
	}

	var wg sync.WaitGroup
	for i := range forwards {
		f := forwards[i]
		wg.Add(1)
		go func() {
			defer wg.Done()
			acceptConnections(ctx, f.listener, f.target)
		}()
	}
	<-ctx.Done()
	for i := range forwards {
		_ = forwards[i].listener.Close()
	}
	wg.Wait()
	return ctx.Err()
}

func acceptConnections(ctx context.Context, ln net.Listener, target string) {
	for {
		client, err := ln.Accept()
		if err != nil {
			if ctx.Err() == nil {
				log.Printf("accept on %s: %v", ln.Addr(), err)
			}
			return
		}
		go handleConnection(client, target)
	}
}

func handleConnection(client net.Conn, target string) {
	upstream, err := net.DialTimeout("tcp", target, dialTimeout)
	if err != nil {
		log.Printf("connect to %s: %v", target, err)
		_ = client.Close()
		return
	}
	defer client.Close()
	defer upstream.Close()

	// Each copy direction ends independently. CloseWrite propagates its EOF
	// without preventing the opposite direction from returning a final response.
	done := make(chan struct{}, 2)
	activity := make(chan struct{}, 1)
	copyDirection := func(dst, src net.Conn) {
		_, _ = io.Copy(&activityWriter{conn: dst, activity: activity}, src)
		if cw, ok := dst.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
		done <- struct{}{}
	}
	go copyDirection(upstream, client)
	go copyDirection(client, upstream)

	completed := 0
	var timer *time.Timer
	var timeout <-chan time.Time
	for completed < 2 {
		select {
		case <-done:
			completed++
			if completed == 1 {
				timer = time.NewTimer(halfCloseIdleTimeout)
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
				timer.Reset(halfCloseIdleTimeout)
			}
		case <-timeout:
			return // deferred Close interrupts the remaining blocked copy.
		}
	}
	if timer != nil {
		timer.Stop()
	}
}

type activityWriter struct {
	conn     net.Conn
	activity chan<- struct{}
}

func (w *activityWriter) Write(p []byte) (int, error) {
	n, err := w.conn.Write(p)
	if n > 0 {
		select {
		case w.activity <- struct{}{}:
		default:
		}
	}
	return n, err
}
