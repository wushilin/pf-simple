package main

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const token = "serve-token-0123456789abcdefghijkl"

func TestParse(t *testing.T) {
	ok := func(args ...string) *options {
		t.Helper()
		o, err := parse(args, "", "", io.Discard)
		if err != nil || o == nil {
			t.Fatalf("parse(%q) = %+v, %v", args, o, err)
		}
		return o
	}
	fails := func(want string, args ...string) {
		t.Helper()
		if o, err := parse(args, "", "", io.Discard); err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("parse(%q) = %+v, %v; want an error with %q", args, o, err, want)
		}
	}

	o := ok("serve", "https://relay.example.com/", "K3F9-x2mq-7hpa", "22", "--name", "Office SSH", "-s", token)
	if o.endpoint != "127.0.0.1:22" || o.name != "Office SSH" || o.generated || o.serveToken != token {
		t.Fatalf("serve = %+v", o)
	}
	// Without a word, serve makes one up.
	o = ok("serve", "https://relay.example.com/", "10.0.0.6:5432", "--name=DB", "--serve-token="+token)
	if !o.generated || len(o.word) != 14 || o.endpoint != "10.0.0.6:5432" || o.name != "DB" {
		t.Fatalf("serve without a word = %+v", o)
	}
	if o := ok("connect", "https://relay.example.com/", "k3f9-x2mq-7hpa", "2222"); o.endpoint != "127.0.0.1:2222" {
		t.Fatalf("connect = %+v", o)
	}
	if o := ok("connect", "https://relay.example.com/", "k3f9-x2mq-7hpa", "-", "-k"); o.endpoint != "-" || !o.insecure {
		t.Fatalf("connect over stdio = %+v", o)
	}
	for _, spelling := range []string{"stdio", "STDIO", "StdIO"} {
		if o := ok("connect", "https://relay.example.com/", "k3f9-x2mq-7hpa", spelling); o.endpoint != "-" {
			t.Fatalf("connect %s = %+v", spelling, o)
		}
	}
	if o := ok("serve", "https://relay.example.com/", "Stdio", "--name", "x", "-s", token); o.endpoint != "-" || !o.generated {
		t.Fatalf("serve stdio = %+v", o)
	}

	fails("needs a name", "serve", "https://relay.example.com/", "22", "-s", token)
	// Without a serve token the registration is anonymous.
	if o := ok("serve", "https://relay.example.com/", "22", "--name", "x"); o.serveToken != "" || !o.generated {
		t.Fatalf("anonymous serve = %+v", o)
	}
	fails("at least 32", "serve", "https://relay.example.com/", "22", "--name", "x", "-s", "short")
	// A client token, on either side.
	if o := ok("serve", "https://relay.example.com/", "22", "--name", "x", "--client-token=hunter22"); o.clientToken != "hunter22" {
		t.Fatalf("serve with a client token = %+v", o)
	}
	if o := ok("connect", "https://relay.example.com/", "k3f9-x2mq-7hpa", "stdio", "-t", "hunter22"); o.clientToken != "hunter22" {
		t.Fatalf("connect with a client token = %+v", o)
	}
	if o := ok("connect", "https://relay.example.com/", "k3f9-x2mq-7hpa", "stdio", "--ca", "/etc/pf/ca.crt"); o.ca != "/etc/pf/ca.crt" {
		t.Fatalf("connect with a CA = %+v", o)
	}
	fails("contradict", "connect", "https://relay.example.com/", "k3f9-x2mq-7hpa", "2222", "--ca=/x/ca.crt", "-k")
	fails("at least 8", "connect", "https://relay.example.com/", "k3f9-x2mq-7hpa", "2222", "-t", "short")
	fails("without spaces", "connect", "https://relay.example.com/", "k3f9-x2mq-7hpa", "2222", "-t", "has a space")
	fails("three groups", "connect", "https://relay.example.com/", "asdf123", "2222")
	fails("https", "connect", "http://relay.example.com/", "k3f9-x2mq-7hpa", "2222")
	fails("usage", "connect", "https://relay.example.com/", "2222") // connect cannot make up a word
	fails("unknown flag", "connect", "--nope")

	dir := t.TempDir()
	path := filepath.Join(dir, "client.toml")
	write := func(body string) {
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(`server = "https://relay.example.com/"
word = "k3f9-x2mq-7hpa"
target = "192.168.44.132:22"
listen = "2222"
name = "Office SSH"
serve_token = "` + token + `"
`)
	o = ok("serve", "-c", path)
	if o.endpoint != "192.168.44.132:22" || o.word != "k3f9-x2mq-7hpa" || o.name != "Office SSH" || o.serveToken != token || o.generated {
		t.Fatalf("serve -c = %+v", o)
	}
	// The same file serves connect, which takes listen instead of target.
	if o = ok("connect", "--config="+path); o.endpoint != "127.0.0.1:2222" {
		t.Fatalf("connect -c = %+v", o)
	}
	fails("cannot be combined", "serve", "-c", path, "-k")
	fails("cannot be combined", "serve", "-c", path, "https://relay.example.com/")

	write("server = \"https://relay.example.com/\"\ntarget = \"22\"\nname = \"x\"\nserve_tokens = \"typo\"\n")
	fails("unknown keys: serve_tokens", "serve", "-c", path)
	write("server = \"https://relay.example.com/\"\nword = \"k3f9-x2mq-7hpa\"\n")
	fails("listen is missing", "connect", "-c", path)
	write("server = \"https://relay.example.com/\"\nlisten = \"2222\"\n")
	fails("word is missing", "connect", "-c", path)
}
