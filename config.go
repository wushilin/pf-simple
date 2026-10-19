package main

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"

	"github.com/BurntSushi/toml"
)

// settings is what pf-simple runs with, whether it came from flags or from a
// --config file.
type settings struct {
	forwards []forwarding
	console  *consoleSettings // nil when the console is off
	// configPath and consoleRaw let the console rewrite the config file.
	// consoleRaw is [console] exactly as written.
	configPath string
	consoleRaw *consoleTable
	// httpRedirect adds the HTTP-to-HTTPS redirect listener on port 80. redirectRaw is
	// enable_http_to_https_redirect exactly as written (nil when omitted).
	httpRedirect bool
	redirectRaw  *bool
}

type consoleSettings struct {
	addr     string
	password string
	manage   *managePolicy // set in config mode: the console may change listeners
}

// consoleTable is the [console] table. The tags keep a rewritten file free of
// keys the user never set.
type consoleTable struct {
	Listen   string `toml:"listen"`
	Password string `toml:"password,omitempty"`
	// Optional fences for listeners added or edited in the console. An
	// omitted one means no restriction.
	AllowTargetHosts []string `toml:"allow_target_hosts,omitempty"`
	AllowTargetPorts string   `toml:"allow_target_ports,omitempty"`
	AllowBindHosts   []string `toml:"allow_bind_hosts,omitempty"`
	AllowBindPorts   string   `toml:"allow_bind_ports,omitempty"`
}

// listenerSpec is one listener as written in a config file, in the console's
// state file, or sent by the console's "Add listener" form. Every source goes
// through buildForwarding, so they share one set of rules.
type listenerSpec struct {
	Name           string `toml:"name,omitempty" json:"name"`
	Listen         string `toml:"listen" json:"listen"`
	Target         string `toml:"target" json:"target"`
	MaxConnections int64  `toml:"max_connections,omitzero" json:"maxConnections"`
	TotalSpeed     string `toml:"total_speed,omitempty" json:"totalSpeed"`
	PerConnSpeed   string `toml:"per_connection_max_speed,omitempty" json:"perConnSpeed"`
	// Enabled is false for a listener stopped in the console; absent means
	// enabled. The form never sends it.
	Enabled *bool `toml:"enabled,omitempty" json:"-"`
}

// fileConfig mirrors the TOML file. See pf-simple.example.toml.
type fileConfig struct {
	// EnableHTTPToHTTPSRedirect defaults to true when omitted.
	EnableHTTPToHTTPSRedirect *bool          `toml:"enable_http_to_https_redirect,omitempty"`
	Console                   *consoleTable  `toml:"console,omitempty"`
	Forward                   []listenerSpec `toml:"forward"`
}

const maxNameLen = 64

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

// buildForwarding validates a listenerSpec and returns a ready forwarding.
// The returned spec is normalized (trimmed name, canonical addresses).
func buildForwarding(spec listenerSpec) (forwarding, listenerSpec, error) {
	spec.Name = strings.TrimSpace(spec.Name)
	spec.TotalSpeed = strings.TrimSpace(spec.TotalSpeed)
	spec.PerConnSpeed = strings.TrimSpace(spec.PerConnSpeed)
	if strings.TrimSpace(spec.Listen) == "" || strings.TrimSpace(spec.Target) == "" {
		return forwarding{}, spec, errors.New("both listen and target are required")
	}
	if len(spec.Name) > maxNameLen {
		return forwarding{}, spec, fmt.Errorf("name is longer than %d characters", maxNameLen)
	}
	fw, err := newForwarding(spec.Listen, spec.Target)
	if err != nil {
		return forwarding{}, spec, err
	}
	spec.Listen, spec.Target = fw.listen, fw.target
	if spec.MaxConnections < 0 {
		return forwarding{}, spec, errors.New("max_connections must be 0 (unlimited) or more")
	}
	fw.stats.name = spec.Name
	fw.stats.maxConns = spec.MaxConnections
	for _, lim := range []struct {
		key   string
		value string
		dst   *float64
	}{{"total_speed", spec.TotalSpeed, &fw.stats.totalRate}, {"per_connection_max_speed", spec.PerConnSpeed, &fw.stats.perConnRate}} {
		if lim.value == "" {
			continue
		}
		rate, err := parseRate(lim.value)
		if err != nil {
			return forwarding{}, spec, fmt.Errorf("%s: %w", lim.key, err)
		}
		*lim.dst = rate
	}
	fw.stats.totalUp = newLimiter(fw.stats.totalRate)
	fw.stats.totalDown = newLimiter(fw.stats.totalRate)
	fw.stats.spec = spec
	return fw, spec, nil
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
	for i, spec := range fc.Forward {
		fw, _, err := buildForwarding(spec)
		if err != nil {
			return settings{}, fmt.Errorf("config %s: forward #%d: %w", path, i+1, err)
		}
		if seen[fw.listen] {
			return settings{}, fmt.Errorf("config %s: forward #%d: listen address %s is used twice", path, i+1, fw.listen)
		}
		seen[fw.listen] = true
		fw.fromFile = true
		fw.disabled = spec.Enabled != nil && !*spec.Enabled
		s.forwards = append(s.forwards, fw)
	}
	s.configPath = path
	s.consoleRaw = fc.Console
	s.redirectRaw = fc.EnableHTTPToHTTPSRedirect
	s.httpRedirect = fc.EnableHTTPToHTTPSRedirect == nil || *fc.EnableHTTPToHTTPSRedirect

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
		// In config mode the console manages listeners and writes them back
		// here, so the file's directory must be writable.
		policy, err := newManagePolicy(c)
		if err != nil {
			return settings{}, fmt.Errorf("config %s: [console]: %w", path, err)
		}
		if err := checkWritableDir(path); err != nil {
			return settings{}, fmt.Errorf("config %s: %w", path, err)
		}
		s.console.manage = policy
	}
	if len(s.forwards) == 0 && s.console == nil {
		return settings{}, fmt.Errorf("config %s: nothing to run: add a [[forward]] or a [console]", path)
	}
	return s, nil
}

// checkWritableDir makes sure the console can later replace path atomically,
// which needs a new file in the same directory.
func checkWritableDir(path string) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, ".pf-simple-write-test-*")
	if err != nil {
		return fmt.Errorf("pf-simple rewrites this file when listeners change, but cannot create files in %s (%v); keep the file in a directory the service can write, such as a systemd StateDirectory (LoadCredential copies are read-only)", dir, err)
	}
	name := f.Name()
	f.Close()
	return os.Remove(name)
}

// errConfigExclusive is returned when --config is combined with other flags.
var errConfigExclusive = errors.New("--config/-c cannot be combined with other flags or forwards; put everything in the config file")
