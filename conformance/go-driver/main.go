// Command go-driver is the Go SDK's conformance driver: the small program
// the conformance suite runs to put an SDK through its cases. Every SDK
// has one; see conformance/README.md for what it must do.
package main

import (
	"bufio"
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
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/wushilin/pf-simple/pfrelay"
	"github.com/wushilin/pf-simple/pfrelayquic"
)

// Mode is how a driver uses the SDK.
type Mode string

const (
	ModeListen  Mode = "listen"  // the SDK's listen/accept and dial API, with the driver's own copy loop
	ModeForward Mode = "forward" // the SDK's forwarders: Serve(target) and Connect(listener)
)

// Command is what the suite asks the driver to do.
type Command string

const (
	CmdServe     Command = "serve"
	CmdConnect   Command = "connect"
	CmdCheck     Command = "check"
	CmdVersion   Command = "version"
	CmdProtocols Command = "protocols" // prints the protocol range the driver speaks
)

// Query is a question the suite asks on stdin while serve or connect runs.
type Query string

const (
	QueryStats Query = "stats"
	QueryConns Query = "conns"
	QueryDrop  Query = "drop" // "drop <id>": drop that connection
)

// Event is a line the driver prints when the SDK reports one of its
// events.
type Event string

const (
	EventReady   Event = "ready"     // the first registration (serve)
	EventOpened  Event = "opened"    // "opened <id> <side>"
	EventClosed  Event = "closed"    // "closed <id> <sent> <received> ok|failed"
	EventRefused Event = "refused"   // "refused <id>"
	EventUp      Event = "tunnel up" // Watch: reachable (connect)
	EventDown    Event = "tunnel down"
)

// Outcome is how a closed connection ended, in EventClosed.
type Outcome string

const (
	OutcomeOK     Outcome = "ok"
	OutcomeFailed Outcome = "failed"
)

// StatsAnswer is the answer to QueryStats.
type StatsAnswer struct {
	Opened   uint64 `json:"opened"`
	Active   uint64 `json:"active"`
	Failed   uint64 `json:"failed"`
	Sent     int64  `json:"sent"`
	Received int64  `json:"received"`
}

// ConnAnswer is one entry of the answer to QueryConns.
type ConnAnswer struct {
	ID       string       `json:"id"`
	Side     pfrelay.Side `json:"side"`
	Sent     int64        `json:"sent"`
	Received int64        `json:"received"`
}

// transport is "quic" in the QUIC build of this driver (go build -ldflags
// "-X main.transport=quic"): it then drives pfrelayquic, which speaks
// protocol 3 only.
var transport = ""

func main() {
	quic := transport == "quic"
	if len(os.Args) < 2 {
		fail(2, "usage: go-driver serve|connect|check|version [flags]")
	}
	cmd := Command(os.Args[1])
	fs := flag.NewFlagSet(string(cmd), flag.ExitOnError)
	server := fs.String("server", "", "hub URL")
	ca := fs.String("ca", "", "PEM file of the hub's certificate")
	word := fs.String("word", "", "the tunnel's word")
	serveToken := fs.String("serve-token", "", "serve token")
	clientToken := fs.String("client-token", "", "client token")
	name := fs.String("name", "conformance", "tunnel name")
	target := fs.String("target", "", "serve: host:port to forward to")
	listen := fs.String("listen", "", "connect: host:port to listen on")
	modeFlag := fs.String("mode", string(ModeListen), "listen: the SDK's listen/accept and dial API; forward: its forwarders")
	noAccept := fs.Bool("no-accept", false, "serve: register, but never accept a connection")
	protoMax := fs.Int("proto-max", pfrelay.ProtoMax, "the newest tunnel protocol to offer; 0: announce none, like a client from before 0.14")
	_ = fs.Parse(os.Args[2:])
	if cmd == CmdProtocols {
		if quic {
			say(pfrelay.ProtoRange(pfrelayquic.Proto, pfrelayquic.Proto))
		} else {
			say(pfrelay.ProtoRange(pfrelay.ProtoMin, pfrelay.ProtoMax))
		}
		return
	}
	if *protoMax < 0 || *protoMax > pfrelay.ProtoMax {
		fail(2, "--proto-max must be from 0 to "+pfrelay.ProtoRange(0, pfrelay.ProtoMax))
	}
	mode := Mode(*modeFlag)
	if mode != ModeListen && mode != ModeForward {
		fail(2, "unknown mode "+*modeFlag)
	}

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
	newClient, agent := pfrelay.NewClient, "pfrelay-go conformance"
	if quic {
		newClient, agent = pfrelayquic.NewClient, "pfrelayquic-go conformance"
	}
	c, err := newClient(*server, *word, tlsConfig)
	if err != nil {
		fail(2, err.Error())
	}
	c.ServeToken, c.ClientToken, c.Name, c.Target = *serveToken, *clientToken, *name, *target
	c.Agent = agent
	c.MaxProto = *protoMax
	if *protoMax == 0 {
		c.MaxProto = -1 // announce no protocol at all
	}
	var ready sync.Once
	c.Events = pfrelay.Events{
		OnServing: func(up bool) {
			if up {
				ready.Do(func() { say(string(EventReady)) })
			}
		},
		OnTunnel: func(up bool, _ error) {
			if up {
				say(string(EventUp))
			} else {
				say(string(EventDown))
			}
		},
		OnOpen: func(ci pfrelay.ConnInfo) {
			say(fmt.Sprintf("%s %s %s", EventOpened, ci.ID, ci.Side))
		},
		OnClose: func(ci pfrelay.ConnInfo, err error) {
			outcome := OutcomeOK
			if err != nil {
				outcome = OutcomeFailed
			}
			say(fmt.Sprintf("%s %s %d %d %s", EventClosed, ci.ID, ci.Sent, ci.Received, outcome))
		},
		OnRefuse: func(id pfrelay.ConnID, _ string) {
			say(fmt.Sprintf("%s %s", EventRefused, id))
		},
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if cmd == CmdServe || cmd == CmdConnect {
		go queries(c)
	}
	switch {
	case cmd == CmdVersion:
		info, err := c.Probe(ctx)
		check(err)
		out, _ := json.Marshal(info)
		say(string(out))
	case cmd == CmdCheck:
		check(c.Check(ctx))
	case cmd == CmdServe && mode == ModeForward:
		check(c.Serve(ctx, *target))
	case cmd == CmdServe:
		l, err := c.Listen(ctx) // its registration says EventReady
		check(err)
		go func() { <-ctx.Done(); l.Close() }()
		if *noAccept {
			<-ctx.Done()
			return
		}
		for {
			conn, err := l.AcceptConn()
			if err != nil {
				return
			}
			go serveOne(conn, *target)
		}
	case cmd == CmdConnect:
		ln, err := net.Listen("tcp", *listen)
		check(err)
		say("listening " + ln.Addr().String())
		go c.Watch(ctx)
		if mode == ModeForward {
			check(c.Connect(ctx, ln))
			return
		}
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
		fail(2, "unknown command "+string(cmd))
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

var out sync.Mutex

// say prints one line of output; lines never interleave.
func say(line string) {
	out.Lock()
	defer out.Unlock()
	fmt.Println(line)
}

// queries answers the suite's questions on stdin: "stats" and "conns".
func queries(c *pfrelay.Client) {
	sc := bufio.NewScanner(os.Stdin)
	for sc.Scan() {
		word, arg, _ := strings.Cut(strings.TrimSpace(sc.Text()), " ")
		q := Query(word)
		var answer any
		switch q {
		case QueryDrop:
			answer = dropByName(c, arg)
		case QueryStats:
			st := c.Stats()
			answer = StatsAnswer{Opened: st.Opened, Active: st.Active, Failed: st.Failed, Sent: st.Sent, Received: st.Received}
		case QueryConns:
			list := []ConnAnswer{}
			for _, ci := range c.Conns() {
				list = append(list, ConnAnswer{ID: ci.ID.String(), Side: ci.Side, Sent: ci.Sent, Received: ci.Received})
			}
			answer = list
		default:
			continue
		}
		b, _ := json.Marshal(answer)
		say(string(q) + " " + string(b))
	}
}

// dropByName drops the open connection whose id prints as name.
func dropByName(c *pfrelay.Client, name string) bool {
	for _, ci := range c.Conns() {
		if ci.ID.String() == name {
			return c.Drop(ci.ID, "dropped by the conformance suite")
		}
	}
	return false
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
