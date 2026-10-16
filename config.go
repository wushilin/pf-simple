package main

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/BurntSushi/toml"
)

// settings is what pf-simple runs with, whether it came from flags or from a
// --config file.
type settings struct {
	forwards []forwarding
	console  *consoleSettings // nil when the console is off
}

type consoleSettings struct {
	addr     string
	password string
}

// fileConfig mirrors the TOML file. See pf-simple.example.toml.
type fileConfig struct {
	Console *struct {
		Listen   string `toml:"listen"`
		Password string `toml:"password"`
	} `toml:"console"`
	Forward []struct {
		Name           string `toml:"name"` // shown in the console and logs
		Listen         string `toml:"listen"`
		Target         string `toml:"target"`
		MaxConnections int64  `toml:"max_connections"`          // 0 = unlimited
		TotalSpeed     string `toml:"total_speed"`              // shared by all pipes, per direction
		PerConnSpeed   string `toml:"per_connection_max_speed"` // each pipe, per direction
	} `toml:"forward"`
}

// newForwarding applies the address shorthand: a bare listen port binds to
// every interface, and a target without a port reuses the listen port.
func newForwarding(listen, target string) (forwarding, error) {
	listen, err := normalizeListen(listen, "")
	if err != nil {
		return forwarding{}, err
	}
	_, port, _ := net.SplitHostPort(listen)
	target, err = normalizeTarget(target, port)
	if err != nil {
		return forwarding{}, err
	}
	return forwarding{listen: listen, target: target, stats: newListenerStats(0, listen, target)}, nil
}

// loadConfig reads a TOML config file. Unknown keys are errors so that a typo
// fails loudly instead of being ignored. An empty console password falls back
// to envPassword, as with --console.
func loadConfig(path, envPassword string) (settings, error) {
	var fc fileConfig
	md, err := toml.DecodeFile(path, &fc)
	if err != nil {
		return settings{}, fmt.Errorf("config %s: %w", path, err)
	}
	if undecoded := md.Undecoded(); len(undecoded) > 0 {
		keys := make([]string, len(undecoded))
		for i, k := range undecoded {
			keys[i] = k.String()
		}
		return settings{}, fmt.Errorf("config %s: unknown keys: %s", path, strings.Join(keys, ", "))
	}

	var s settings
	seen := make(map[string]bool)
	for i, f := range fc.Forward {
		if f.Listen == "" || f.Target == "" {
			return settings{}, fmt.Errorf("config %s: forward #%d needs both listen and target", path, i+1)
		}
		fw, err := newForwarding(f.Listen, f.Target)
		if err != nil {
			return settings{}, fmt.Errorf("config %s: forward #%d: %w", path, i+1, err)
		}
		if seen[fw.listen] {
			return settings{}, fmt.Errorf("config %s: forward #%d: listen address %s is used twice", path, i+1, fw.listen)
		}
		seen[fw.listen] = true
		if f.MaxConnections < 0 {
			return settings{}, fmt.Errorf("config %s: forward #%d: max_connections must be 0 (unlimited) or more", path, i+1)
		}
		fw.stats.name = strings.TrimSpace(f.Name)
		fw.stats.maxConns = f.MaxConnections
		for _, lim := range []struct {
			key   string
			value string
			dst   *float64
		}{{"total_speed", f.TotalSpeed, &fw.stats.totalRate}, {"per_connection_max_speed", f.PerConnSpeed, &fw.stats.perConnRate}} {
			if lim.value == "" {
				continue
			}
			rate, err := parseRate(lim.value)
			if err != nil {
				return settings{}, fmt.Errorf("config %s: forward #%d %s: %w", path, i+1, lim.key, err)
			}
			*lim.dst = rate
		}
		fw.stats.totalUp = newLimiter(fw.stats.totalRate)
		fw.stats.totalDown = newLimiter(fw.stats.totalRate)
		s.forwards = append(s.forwards, fw)
	}
	if len(s.forwards) == 0 {
		return settings{}, fmt.Errorf("config %s: at least one [[forward]] is required", path)
	}

	if c := fc.Console; c != nil {
		if c.Listen == "" {
			return settings{}, fmt.Errorf("config %s: [console] needs listen", path)
		}
		addr, err := normalizeListen(c.Listen, "127.0.0.1")
		if err != nil {
			return settings{}, fmt.Errorf("config %s: [console]: %w", path, err)
		}
		password := c.Password
		if password == "" {
			password = envPassword
		}
		s.console = &consoleSettings{addr: addr, password: password}
		if c.Password != "" {
			if info, err := os.Stat(path); err == nil && info.Mode().Perm()&0o004 != 0 {
				fmt.Fprintf(os.Stderr, "warning: %s holds the console password and is readable by every user; consider chmod 600\n", path)
			}
		}
	}
	return s, nil
}

// errConfigExclusive is returned when --config is combined with other flags.
var errConfigExclusive = errors.New("--config/-c cannot be combined with other flags or forwards; put everything in the config file")
