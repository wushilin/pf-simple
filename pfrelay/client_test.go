package pfrelay

import (
	"net/http"
	"strings"
	"testing"

	"github.com/wushilin/pf-simple/internal/tunnel"
)

func TestNormalizeBase(t *testing.T) {
	for in, want := range map[string]string{
		"https://relay.example.com":                      "https://relay.example.com/pf",
		"https://relay.example.com/":                     "https://relay.example.com/pf",
		"https://relay.example.com:8443":                 "https://relay.example.com:8443/pf",
		"https://relay.example.com/pf":                   "https://relay.example.com/pf",
		"https://relay.example.com/pf/":                  "https://relay.example.com/pf",
		"https://relay.example.com:8443/xzfe-aeeg-e2da/": "https://relay.example.com:8443/xzfe-aeeg-e2da",
		"https://relay.example.com/a/b.c_d~e-f":          "https://relay.example.com/a/b.c_d~e-f",
		" https://relay.example.com/x ":                  "https://relay.example.com/x",
	} {
		if got, err := normalizeBase(in); err != nil || got != want {
			t.Errorf("normalizeBase(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, in := range []string{
		"http://relay.example.com/", "relay.example.com", "wss://relay.example.com/",
		"https://relay.example.com/?x=1", "https://relay.example.com/?", "https://relay.example.com/#f",
		"https://u:p@relay.example.com/", "https://relay.example.com//", "https://relay.example.com/a//b",
		"https://relay.example.com/.", "https://relay.example.com/..", "https://relay.example.com/a/../b",
		"https://relay.example.com/a%2Fb", "https://relay.example.com/a%41", "https://relay.example.com/a b",
		"https://relay.example.com/" + strings.Repeat("a", 65),
		"https://relay.example.com" + strings.Repeat("/abcdefghi", 21),
	} {
		if got, err := normalizeBase(in); err == nil {
			t.Errorf("normalizeBase(%q) = %q, want an error", in, got)
		}
	}
}

// What a run depends on decides the lowest version it offers, and a server
// that answers with less is refused.
func TestClientOffersWhatItNeeds(t *testing.T) {
	c, err := NewClient("https://relay.example.com/", "k3f9-x2mq-7hpa", nil)
	if err != nil {
		t.Fatal(err)
	}
	c.Agent = "pf-client 9.9.9"
	offered := func(endpoint string) string {
		h := http.Header{}
		c.offer(endpoint, h)
		if h.Get(tunnel.HeaderVersion) != "pf-client 9.9.9" {
			t.Errorf("version header = %q", h.Get(tunnel.HeaderVersion))
		}
		return h.Get(tunnel.HeaderProto)
	}
	old, current := http.Header{}, http.Header{}
	current.Set(tunnel.HeaderProto, "1")

	// A plain tunnel works with anything.
	c.ServeToken = "serve-token-0123456789abcdefghijkl"
	if got := offered("serve"); got != tunnel.ProtoRange(0, tunnel.ProtoMax) {
		t.Errorf("plain serve offers %s", got)
	}
	if got := offered("connect"); got != tunnel.ProtoRange(0, tunnel.ProtoMax) {
		t.Errorf("plain connect offers %s", got)
	}
	if err := c.answered("serve", old); err != nil {
		t.Errorf("plain serve against an old server = %v", err)
	}

	// A client token needs a server that says it will check it.
	c.ClientToken = "open-sesame"
	for _, endpoint := range []string{"serve", "connect", "check"} {
		if got := offered(endpoint); got != tunnel.ProtoRange(1, tunnel.ProtoMax) {
			t.Errorf("%s with a client token offers %s", endpoint, got)
		}
		if err := c.answered(endpoint, old); err == nil || !strings.Contains(err.Error(), "too old for a client token") {
			t.Errorf("%s with a client token against an old server = %v", endpoint, err)
		}
		if err := c.answered(endpoint, current); err != nil {
			t.Errorf("%s with a client token against a current server = %v", endpoint, err)
		}
	}
	// Bringing a connection to the server depends on nothing new.
	if got := offered("accept"); got != tunnel.ProtoRange(0, tunnel.ProtoMax) {
		t.Errorf("accept offers %s", got)
	}

	// So does serving without a serve token.
	c.ClientToken, c.ServeToken = "", ""
	if err := c.answered("serve", old); err == nil || !strings.Contains(err.Error(), "serving without a serve token") {
		t.Errorf("anonymous serve against an old server = %v", err)
	}
	if err := c.answered("connect", old); err != nil {
		t.Errorf("a plain connect against an old server = %v", err)
	}
}
