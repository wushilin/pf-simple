// pf-client is the client of pf-simple's ad-hoc tunnels: one side serves a
// local target, the other connects to it through a local port, and they meet
// at a pf-simple server by a shared token.
package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/BurntSushi/toml"

	"github.com/wushilin/pf-simple/internal/tunnel"
)

const usage = `pf-client: reach a TCP port on another machine through a pf-simple server.

  pf-client serve   <server> [word] <target> --name <name>   offer a target
  pf-client connect <server> <word> <listen>                 reach it on a local port
  pf-client serve|connect -c <file>                          the same, from a config file
  pf-client word                                             print a random word

Run "serve" on the machine that can reach the target and "connect" where you
want to use it, with the same word:

  pf-client serve https://relay.example.com/ 22 --name "Office SSH"
  pf-client connect https://relay.example.com/ k3f9-x2mq-7hpa 2222
  ssh -p 2222 user@127.0.0.1

<server>  the pf-simple server, https only:  https://relay.example.com/
<word>    the tunnel's secret, the same on both sides: three groups of four
          letters or digits, like k3f9-x2mq-7hpa; case does not matter.
          "serve" without a word makes a random one and prints it; it
          leaves out 0, o, 1, i and l, which are easy to confuse. Anyone
          who guesses the word can connect, so prefer a random one. The
          first serve token to register a word owns it until the server's
          admin clears it.
<target>  host:port, or a port alone for 127.0.0.1;
          "stdio" or "-" offers this program's own stdin/stdout instead, to
          one connection, and then exits: a pipe between two machines
            tar c dir | pf-client serve <server> stdio --name copy
            pf-client connect <server> <word> stdio | tar x
<listen>  host:port, or a port alone to listen on 127.0.0.1 only;
          "stdio" or "-" carries one connection over stdin/stdout and
          then exits, silent unless it fails, for ssh:
            ssh -o ProxyCommand="pf-client connect <server> <word> stdio" user@host

Flags:
  -c, --config <file>    read everything from a TOML file instead of the
                         command line; keys: server, word, target (serve),
                         listen (connect), name, serve_token, client_token,
                         ca, insecure
  -n, --name <name>      what the tunnel is called in the server's console,
                         e.g. "Office SSH"; "serve" needs it
  -s, --serve-token <t>  your serve token, from the server's admin: permission
                         to register there, for "serve"; defaults to
                         $PF_SERVE_TOKEN. Without one the registration is
                         anonymous, which works only on a server that allows
                         serving without a token
  -t, --client-token <t> a second secret on top of the word, 8 to 128
                         characters; defaults to $PF_CLIENT_TOKEN. Given to
                         "serve", whoever connects must give the same one to
                         "connect"; a wrong or missing one is "access denied"
  --ca <file>            trust the server's certificate if this CA issued it:
                         a PEM file, such as certs/ca.crt of a pf-simple that
                         serves https itself. No question is asked then
  -k, --insecure         do not verify the server's certificate
  --version              print the version

Without -k, a certificate that does not verify is shown with its fingerprint
and you are asked whether to trust it for this run.

With stdio a command carries one connection and exits. Otherwise both
commands run until interrupted and recover on their own, so they can be
started once and left. "serve" registers again whenever it loses the
server, pausing 1s, 2s, 4s ... up to 30s between attempts, and starting over
from 1s once it has been up for a minute. "connect" keeps listening whether
or not the tunnel is up, and says in its log when that changes. Only a
mistake stops them: a malformed argument, or the server refusing the very
first "serve" (wrong serve token, or a word that belongs to someone else).
Nothing is resumed: a connection whose link breaks is closed, and whatever
was using it connects again.
`

func main() {
	log.SetFlags(log.Ltime)
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "pf-client:", err)
		os.Exit(1)
	}
}

// options is one invocation, from the command line or a config file.
type options struct {
	command     string // "serve", "connect" or "word"
	server      string
	word        string
	generated   bool   // the word was made up here, so it must be shown
	endpoint    string // serve: the target; connect: the listen address; "-" for stdio
	name        string
	serveToken  string
	clientToken string
	ca          string // PEM file of a CA to trust for the server
	insecure    bool
}

// fileConfig is a pf-client config file: the same parameters as the command
// line, for "pf-client serve -c file" or "pf-client connect -c file". One
// file may hold both target and listen and serve either command.
type fileConfig struct {
	Server      string `toml:"server"`
	Word        string `toml:"word"`
	Target      string `toml:"target"`
	Listen      string `toml:"listen"`
	Name        string `toml:"name"`
	ServeToken  string `toml:"serve_token"`
	ClientToken string `toml:"client_token"`
	CA          string `toml:"ca"`
	Insecure    bool   `toml:"insecure"`
}

var errUsage = errors.New("usage: pf-client serve <server> [word] <target> --name <name>, pf-client connect <server> <word> <listen>, or either with -c <file>; run 'pf-client -h' for more")

// parse turns the arguments into checked options, reading the config file
// if one is named. It returns nil options when it already printed what was
// asked for (-h, --version).
func parse(args []string, envToken, envClientToken string, out io.Writer) (*options, error) {
	o := &options{serveToken: envToken, clientToken: envClientToken}
	configPath := ""
	var pos, flags []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		// Flags that take a value: "--flag value" or "--flag=value".
		value := func(target *string) error {
			if _, v, ok := strings.Cut(a, "="); ok && strings.HasPrefix(a, "--") {
				*target = v
				return nil
			}
			if i+1 >= len(args) {
				return fmt.Errorf("%s needs a value", a)
			}
			i++
			*target = args[i]
			return nil
		}
		name, _, _ := strings.Cut(a, "=")
		var err error
		switch name {
		case "-c", "--config":
			err = value(&configPath)
		case "-s", "--serve-token":
			flags = append(flags, name)
			err = value(&o.serveToken)
		case "-t", "--client-token":
			flags = append(flags, name)
			err = value(&o.clientToken)
		case "--ca":
			flags = append(flags, name)
			err = value(&o.ca)
		case "-n", "--name":
			flags = append(flags, name)
			err = value(&o.name)
		case "-k", "--insecure":
			flags = append(flags, name)
			o.insecure = true
		case "-h", "--help", "help":
			fmt.Fprint(out, usage)
			return nil, nil
		case "--version", "-version":
			fmt.Fprintln(out, "pf-client "+version)
			return nil, nil
		default:
			if strings.HasPrefix(a, "-") && a != "-" {
				return nil, fmt.Errorf("unknown flag %s; run 'pf-client -h' for usage", a)
			}
			pos = append(pos, a)
		}
		if err != nil {
			return nil, err
		}
	}
	if len(pos) == 0 {
		return nil, errUsage
	}
	o.command = pos[0]
	switch {
	case o.command == "word" && len(pos) == 1 && configPath == "":
		return o, nil
	case o.command != "serve" && o.command != "connect":
		return nil, errUsage
	case configPath != "":
		// As with pf-simple -c, the file is the whole configuration.
		if len(pos) > 1 || len(flags) > 0 {
			return nil, fmt.Errorf("-c cannot be combined with other arguments (got %s); put everything in the config file", strings.Join(append(pos[1:], flags...), ", "))
		}
		if err := o.load(configPath); err != nil {
			return nil, err
		}
	case o.command == "serve" && len(pos) == 3:
		o.server, o.endpoint = pos[1], pos[2]
	case len(pos) == 4:
		o.server, o.word, o.endpoint = pos[1], pos[2], pos[3]
	default:
		return nil, errUsage
	}

	o.name = strings.TrimSpace(o.name)
	var err error
	if o.command == "serve" {
		if o.name == "" {
			return nil, errors.New("serve needs a name for the tunnel, shown in the server's console: --name \"Office SSH\", or name = \"...\" in the config file")
		}
		// No serve token: an anonymous registration, if the server allows it.
		if o.serveToken != "" {
			if err := tunnel.CheckSecret("serve token", o.serveToken); err != nil {
				return nil, err
			}
		}
		if o.word == "" { // made up here, and printed once it is being served
			if o.word, err = tunnel.NewWord(); err != nil {
				return nil, err
			}
			o.generated = true
		}
		if isStdio(o.endpoint) {
			o.endpoint = "-"
		} else if o.endpoint, err = hostPort(o.endpoint, "target"); err != nil {
			return nil, err
		}
	} else if isStdio(o.endpoint) {
		o.endpoint = "-"
	} else {
		if o.endpoint, err = hostPort(o.endpoint, "listen address"); err != nil {
			return nil, err
		}
	}
	if o.ca != "" && o.insecure {
		return nil, errors.New("--ca and -k contradict each other: trust the CA, or skip the check")
	}
	if o.clientToken != "" {
		if err := tunnel.CheckClientToken(o.clientToken); err != nil {
			return nil, err
		}
	}
	// NewClient checks the server URL and the word, before any network use.
	if _, err := tunnel.NewClient(o.server, o.word, nil); err != nil {
		return nil, err
	}
	return o, nil
}

// load fills the options from a config file. Unknown keys are errors, so a
// typo is reported instead of ignored.
func (o *options) load(path string) error {
	var fc fileConfig
	md, err := toml.DecodeFile(path, &fc)
	if err != nil {
		return fmt.Errorf("config %s: %w", path, err)
	}
	if undecoded := md.Undecoded(); len(undecoded) > 0 {
		keys := make([]string, len(undecoded))
		for i, k := range undecoded {
			keys[i] = k.String()
		}
		return fmt.Errorf("config %s: unknown keys: %s", path, strings.Join(keys, ", "))
	}
	o.server, o.word, o.name, o.insecure = fc.Server, fc.Word, fc.Name, fc.Insecure
	if fc.ServeToken != "" {
		o.serveToken = fc.ServeToken
	}
	if fc.ClientToken != "" {
		o.clientToken = fc.ClientToken
	}
	if o.ca = fc.CA; o.ca != "" && !filepath.IsAbs(o.ca) {
		o.ca = filepath.Join(filepath.Dir(path), o.ca) // relative to the config file
	}
	if fc.ServeToken != "" || fc.ClientToken != "" {
		if info, err := os.Stat(path); err == nil && info.Mode().Perm()&0o004 != 0 {
			fmt.Fprintf(os.Stderr, "warning: %s holds a token and is readable by every user; consider chmod 600\n", path)
		}
	}
	o.endpoint = fc.Listen
	what := "listen"
	if o.command == "serve" {
		o.endpoint, what = fc.Target, "target"
	}
	for key, value := range map[string]string{"server": o.server, what: o.endpoint} {
		if value == "" {
			return fmt.Errorf("config %s: %s is missing; '%s' needs it", path, key, o.command)
		}
	}
	if o.command == "connect" && o.word == "" {
		return fmt.Errorf("config %s: word is missing; 'connect' needs it", path)
	}
	return nil
}

func run(args []string) error {
	o, err := parse(args, os.Getenv("PF_SERVE_TOKEN"), os.Getenv("PF_CLIENT_TOKEN"), os.Stdout)
	if err != nil || o == nil {
		return err
	}
	if o.command == "word" {
		word, err := tunnel.NewWord()
		if err == nil {
			fmt.Println(word)
		}
		return err
	}
	stdio := o.endpoint == "-"

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	tlsConfig, err := trust(ctx, o.server, o.ca, o.insecure, !stdio)
	if err != nil {
		return err
	}
	client, err := tunnel.NewClient(o.server, o.word, tlsConfig)
	if err != nil {
		return err
	}
	client.Name, client.ClientToken = o.name, o.clientToken
	if o.command == "serve" {
		client.ServeToken = o.serveToken
	}

	if o.command == "serve" {
		if o.generated {
			listen := "<listen>"
			if stdio {
				listen = "stdio"
			}
			if o.clientToken != "" {
				listen += " --client-token <the client token>"
			}
			log.Printf("word: %s   (connect with: pf-client connect %s %s %s)", o.word, o.server, o.word, listen)
		}
		if o.serveToken == "" {
			log.Printf("no serve token: registering anonymously, which the server must allow")
		}
		if stdio {
			// Stdin can be read once: one connection, and its end is ours.
			err := client.ServeOne(ctx, tunnel.Stdio{In: os.Stdin, Out: os.Stdout})
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		err := client.Serve(ctx, o.endpoint)
		if err != nil && o.serveToken == "" && err.Error() == "access denied" {
			return errors.New("access denied: this server does not allow serving without a serve token; give --serve-token, set $PF_SERVE_TOKEN, or put serve_token in the config file")
		}
		return err
	}
	if stdio {
		// One connection for one caller, such as ssh: fail at once. Stderr
		// is the caller's terminal, so say nothing unless it goes wrong.
		client.Logf = func(string, ...any) {}
		if err := client.Check(ctx); err != nil {
			return err
		}
		err := client.ConnectOne(ctx, tunnel.Stdio{In: os.Stdin, Out: os.Stdout})
		if ctx.Err() != nil { // stopped by the caller: not a failure
			return nil
		}
		return err
	}
	// Listen whether or not the tunnel is up yet, and keep listening when
	// it goes away: each connection is carried if it can be at that moment.
	ln, err := net.Listen("tcp", o.endpoint)
	if err != nil {
		return err
	}
	log.Printf("listening on %s", ln.Addr())
	go client.Watch(ctx)
	return client.Connect(ctx, ln)
}

// trust decides how the server's certificate is checked: normally, not at
// all (-k), or pinned to one the user accepted by fingerprint.
func trust(ctx context.Context, server, ca string, insecure, mayAsk bool) (*tls.Config, error) {
	if insecure {
		return &tls.Config{InsecureSkipVerify: true}, nil
	}
	if ca != "" {
		// Only this CA: the certificate must chain to it and name the
		// host in the server URL.
		pem, err := os.ReadFile(ca)
		if err != nil {
			return nil, fmt.Errorf("--ca: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("--ca: %s holds no PEM certificate", ca)
		}
		return &tls.Config{RootCAs: pool}, nil
	}
	cert, verifyErr, err := tunnel.ProbeCert(ctx, server)
	if err != nil {
		return nil, fmt.Errorf("cannot reach %s: %w", server, err)
	}
	if verifyErr == nil {
		return nil, nil
	}
	info, _ := os.Stdin.Stat()
	if !mayAsk || info == nil || info.Mode()&os.ModeCharDevice == 0 {
		return nil, fmt.Errorf("the server's certificate is not trusted (%v); give its CA with --ca, or use -k to skip the check", verifyErr)
	}
	fmt.Fprintf(os.Stderr, "The server's certificate is not trusted: %v\n  subject:     %s\n  issuer:      %s\n  valid until: %s\n  SHA-256:     %s\nDo you trust this certificate for this run? [y/N] ",
		verifyErr, cert.Subject, cert.Issuer, cert.NotAfter.Format("2006-01-02"), tunnel.Fingerprint(cert))
	answer, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	switch strings.ToLower(strings.TrimSpace(answer)) {
	case "y", "yes":
		return tunnel.PinnedTLS(cert), nil
	}
	return nil, errors.New("certificate not trusted")
}

// isStdio reports whether an endpoint names stdin/stdout.
func isStdio(s string) bool { return s == "-" || strings.EqualFold(s, "stdio") }

func isPort(s string) bool {
	n, err := strconv.Atoi(s)
	return err == nil && n >= 1 && n <= 65535 && strconv.Itoa(n) == s
}

func hostPort(s, what string) (string, error) {
	if isPort(s) {
		return net.JoinHostPort("127.0.0.1", s), nil
	}
	host, port, err := net.SplitHostPort(s)
	if err != nil || !isPort(port) || (host == "" && what == "target") {
		return "", fmt.Errorf("invalid %s %q: use host:port, or a port alone for 127.0.0.1", what, s)
	}
	return net.JoinHostPort(host, port), nil
}
