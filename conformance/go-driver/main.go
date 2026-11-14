// Command go-driver is the Go SDK's conformance driver: the small program
// the conformance suite runs to put an SDK through its cases. Every SDK
// has one; see conformance/README.md for what it must do.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/wushilin/pf-simple/pfrelay"
)

func main() {
	if len(os.Args) < 2 {
		fail(2, "usage: go-driver serve|connect|check|version [flags]")
	}
	cmd := os.Args[1]
	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	server := fs.String("server", "", "hub URL")
	ca := fs.String("ca", "", "PEM file of the hub's certificate")
	word := fs.String("word", "", "the tunnel's word")
	serveToken := fs.String("serve-token", "", "serve token")
	clientToken := fs.String("client-token", "", "client token")
	name := fs.String("name", "conformance", "tunnel name")
	target := fs.String("target", "", "serve: host:port to forward to")
	listen := fs.String("listen", "", "connect: host:port to listen on")
	_ = fs.Parse(os.Args[2:])

	tlsConfig := &tls.Config{}
	if *ca != "" {
		pem, err := os.ReadFile(*ca)
		if err != nil {
			fail(1, err.Error())
		}
		pool := x509.NewCertPool()
		pool.AppendCertsFromPEM(pem)
		tlsConfig.RootCAs = pool
	}
	if *word == "" {
		*word = "aaaa-bbbb-cccc" // version needs none, but a client is made with one
	}
	c, err := pfrelay.NewClient(*server, *word, tlsConfig)
	if err != nil {
		fail(2, err.Error())
	}
	c.ServeToken, c.ClientToken, c.Name, c.Target = *serveToken, *clientToken, *name, *target
	c.Agent = "pfrelay-go conformance"

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	switch cmd {
	case "version":
		info, err := c.Probe(ctx)
		check(err)
		out, _ := json.Marshal(info)
		fmt.Println(string(out))
	case "check":
		check(c.Check(ctx))
	case "serve":
		l, err := c.Listen(ctx)
		check(err)
		fmt.Println("ready")
		go func() { <-ctx.Done(); l.Close() }()
		for {
			conn, err := l.AcceptConn()
			if err != nil {
				return
			}
			go serveOne(conn, *target)
		}
	case "connect":
		ln, err := net.Listen("tcp", *listen)
		check(err)
		fmt.Println("listening " + ln.Addr().String())
		go func() { <-ctx.Done(); ln.Close() }()
		for {
			local, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				conn, err := c.Dial(ctx)
				if err != nil {
					fmt.Fprintln(os.Stderr, "dial:", err)
					local.Close()
					return
				}
				pipe(local.(*net.TCPConn), conn)
			}()
		}
	default:
		fail(2, "unknown command "+cmd)
	}
}

func serveOne(conn *pfrelay.Conn, target string) {
	t, err := net.DialTimeout("tcp", target, 5*time.Second)
	if err != nil {
		conn.Fail("the serving side could not reach its target")
		return
	}
	pipe(t.(*net.TCPConn), conn)
}

// pipe copies both ways, passing on half-closes, until both directions are
// done or one fails.
func pipe(local *net.TCPConn, conn *pfrelay.Conn) {
	done := make(chan error, 2)
	go func() {
		_, err := io.Copy(conn, local)
		if err == nil {
			err = conn.CloseWrite()
		}
		done <- err
	}()
	go func() {
		_, err := io.Copy(local, conn)
		if err == nil {
			err = local.CloseWrite()
		}
		done <- err
	}()
	for i := 0; i < 2; i++ {
		if err := <-done; err != nil {
			conn.Fail(err.Error())
			local.Close()
			<-done
			return
		}
	}
	conn.Close()
	local.Close()
}

// check exits with the code the conformance suite expects for err.
func check(err error) {
	var pe *pfrelay.ProtoError
	switch {
	case err == nil:
		return
	case errors.As(err, &pe):
		fail(3, err.Error())
	case errors.Is(err, pfrelay.ErrAccessDenied):
		fail(4, err.Error())
	}
	fail(1, err.Error())
}

func fail(code int, msg string) {
	fmt.Fprintln(os.Stderr, msg)
	os.Exit(code)
}
