package main

import (
	"errors"
	"flag"
	"io"
	"strings"
	"testing"
)

const tinyConfig = "[[forward]]\nlisten = \"127.0.0.1:2\"\ntarget = \"127.0.0.1:3\"\n"

func TestConfigFlagExcludesEverythingElse(t *testing.T) {
	path := writeConfig(t, tinyConfig)
	cases := map[string][]string{
		"--forward":            {"-c", path, "--forward", "8080@10.0.0.6"},
		"-f":                   {"--config", path, "-f", "8080@10.0.0.6"},
		"--console":            {"-c", path, "--console", "18222"},
		`argument "8080@x"`:    {"-c", path, "8080@x"},
		"--console, --forward": {"--forward", "1@x", "--console", "2", "-c", path},
	}
	for want, args := range cases {
		_, err := parseArgs(args, io.Discard, "")
		if !errors.Is(err, errConfigExclusive) || !strings.Contains(err.Error(), want) {
			t.Errorf("%v: want exclusive error naming %s, got %v", args, want, err)
		}
	}
	if _, err := parseArgs([]string{"-c", path, "--config", path}, io.Discard, ""); err == nil {
		t.Error("-c and --config together should fail")
	}
	for _, args := range [][]string{{"-c", path}, {"--config", path}, {"-config=" + path}} {
		s, err := parseArgs(args, io.Discard, "")
		if err != nil || len(s.forwards) != 1 {
			t.Errorf("%v: %+v %v", args, s, err)
		}
	}
}

func TestQuickStartDefaults(t *testing.T) {
	s, err := parseArgs([]string{
		"8080@10.0.0.6",                // bare port, target reuses it
		"-f", "127.0.0.1:4100@db:3306", // short flag, full addresses
		"--forward", "9030@[2001:db8::6]", // IPv6 target without a port
		"--console", "18222@pw",
		"--", "-1@weird", // after "--" everything is a forward, even with a dash
	}, io.Discard, "")
	if err == nil || !strings.Contains(err.Error(), "-1") {
		t.Fatalf("a forward after -- should be parsed as a forward (and fail on its port): %v", err)
	}
	s, err = parseArgs([]string{
		"8080@10.0.0.6",
		"-f", "127.0.0.1:4100@db:3306",
		"--forward", "9030@[2001:db8::6]",
		"--console", "18222@pw",
	}, io.Discard, "")
	if err != nil {
		t.Fatal(err)
	}
	got := make([]string, len(s.forwards))
	for i, f := range s.forwards {
		got[i] = f.listen + "@" + f.target
	}
	expect := map[string]bool{
		":8080@10.0.0.6:8080":      true,
		"127.0.0.1:4100@db:3306":   true,
		":9030@[2001:db8::6]:9030": true,
	}
	for _, g := range got {
		if !expect[g] {
			t.Errorf("unexpected forward %s (all: %v)", g, got)
		}
	}
	if s.console == nil || s.console.addr != "127.0.0.1:18222" || s.console.password != "pw" {
		t.Errorf("console: %+v", s.console)
	}

	s, err = parseArgs([]string{"--console", ":18222", "1@x"}, io.Discard, "env-pw")
	if err != nil || s.console.addr != ":18222" || s.console.password != "env-pw" {
		t.Errorf("explicit all-interface console: %+v %v", s.console, err)
	}
}

func TestArgErrors(t *testing.T) {
	cases := map[string][]string{
		"nothing to forward":   {},
		"used twice":           {"8080@a", "8080@b"},
		"port must be 1-65535": {"70000@a"},
		"must have the form":   {"8080"},
		"IPv6 in brackets":     {"8080@2001:db8::6"},
		"the host is missing":  {"8080@:80"},
	}
	for want, args := range cases {
		_, err := parseArgs(args, io.Discard, "")
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%v: want error containing %q, got %v", args, want, err)
		}
	}
	if _, err := parseArgs([]string{"-h"}, io.Discard, ""); !errors.Is(err, flag.ErrHelp) {
		t.Errorf("-h: %v", err)
	}
}
