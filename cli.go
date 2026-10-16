package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
)

const usageText = `pf-simple: a small TCP port forwarder.

Quick start (forwards can be plain arguments or --forward/-f):

  pf-simple 8080@10.0.0.6                 :8080 -> 10.0.0.6:8080
  pf-simple 8080@10.0.0.6:80 9030@db:9030 two listeners
  pf-simple -f 127.0.0.1:4100@10.0.0.7:3306 --console 18222@secret

Defaults: a listen port alone binds every interface, a target without a
port reuses the listen port, and a console port alone binds 127.0.0.1.

Config file (names, max_connections, speed limits, and a console that can
add, edit and delete listeners):

  pf-simple -c /etc/pf-simple.toml

--config/-c cannot be combined with any other flag or argument.

Flags:
`

type forwardsFlag []string

func (f *forwardsFlag) String() string { return strings.Join(*f, ",") }

func (f *forwardsFlag) Set(value string) error {
	*f = append(*f, value)
	return nil
}

// parseArgs turns a command line (without the program name) into settings.
// It returns flag.ErrHelp after printing usage for -h.
func parseArgs(args []string, stderr io.Writer, envPassword string) (settings, error) {
	fs := flag.NewFlagSet("pf-simple", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var forwards forwardsFlag
	var consoleValue, configPath, configShort string
	fs.Var(&forwards, "forward", "mapping `listen@target` (repeatable)")
	fs.Var(&forwards, "f", "short for --forward `listen@target`")
	fs.StringVar(&consoleValue, "console", "", "web console `listen[@password]`; password defaults to $PF_PASSWORD")
	fs.StringVar(&configPath, "config", "", "TOML config `file`; excludes every other flag")
	fs.StringVar(&configShort, "c", "", "short for --config `file`")
	fs.Usage = func() {
		fmt.Fprint(fs.Output(), usageText)
		fs.PrintDefaults()
	}
	// Go's flag package stops at the first plain argument; keep going so
	// forwards and flags can be mixed in any order. "--" ends flag parsing.
	var positional []string
	for {
		if err := fs.Parse(args); err != nil {
			return settings{}, err
		}
		rest := fs.Args()
		if len(rest) == 0 {
			break
		}
		if len(args) > len(rest) && args[len(args)-len(rest)-1] == "--" {
			positional = append(positional, rest...)
			break
		}
		positional = append(positional, rest[0])
		args = rest[1:]
	}

	var set []string
	fs.Visit(func(f *flag.Flag) { set = append(set, f.Name) })
	if configPath != "" && configShort != "" {
		return settings{}, errors.New("give the config file once, with either --config or -c")
	}
	if configShort != "" {
		configPath = configShort
	}
	if configPath != "" {
		var others []string
		for _, name := range set {
			if name != "config" && name != "c" {
				others = append(others, flagName(name))
			}
		}
		if len(positional) > 0 {
			others = append(others, fmt.Sprintf("argument %q", positional[0]))
		}
		if len(others) > 0 {
			return settings{}, fmt.Errorf("%w (got %s)", errConfigExclusive, strings.Join(others, ", "))
		}
		return loadConfig(configPath, envPassword)
	}

	forwards = append(forwards, positional...)
	if len(forwards) == 0 {
		if consoleValue != "" {
			return settings{}, errors.New("a console alone cannot add listeners on the command line; give at least one listen@target, or use -c config.toml")
		}
		return settings{}, errors.New("nothing to run: give at least one listen@target, or -c config.toml")
	}
	var s settings
	seen := make(map[string]bool)
	for _, value := range forwards {
		f, err := parseForward(value)
		if err != nil {
			return settings{}, err
		}
		if seen[f.listen] {
			return settings{}, fmt.Errorf("listen address %s is used twice", f.listen)
		}
		seen[f.listen] = true
		s.forwards = append(s.forwards, f)
	}
	if consoleValue != "" {
		addr, password, err := parseConsole(consoleValue, envPassword)
		if err != nil {
			return settings{}, err
		}
		s.console = &consoleSettings{addr: addr, password: password}
	}
	return s, nil
}

func flagName(name string) string {
	if len(name) == 1 {
		return "-" + name
	}
	return "--" + name
}

// exitForArgsError reports a command-line error and exits.
func exitForArgsError(err error) {
	if errors.Is(err, flag.ErrHelp) {
		os.Exit(0)
	}
	fmt.Fprintln(os.Stderr, "pf-simple:", err)
	fmt.Fprintln(os.Stderr, "Run 'pf-simple -h' for usage.")
	os.Exit(2)
}
