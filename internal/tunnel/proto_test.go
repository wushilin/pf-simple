package tunnel

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func TestProtoRange(t *testing.T) {
	for in, want := range map[string][2]int{"": {0, 0}, "1": {1, 1}, "0-1": {0, 1}, " 1-3 ": {1, 3}} {
		min, max, err := ParseProtoRange(in)
		if err != nil || min != want[0] || max != want[1] {
			t.Errorf("ParseProtoRange(%q) = %d, %d, %v; want %v", in, min, max, err, want)
		}
	}
	for _, bad := range []string{"x", "2-1", "-1", "1-", "1-2-3", "1-9999999999"} {
		if _, _, err := ParseProtoRange(bad); err == nil {
			t.Errorf("ParseProtoRange(%q) was accepted", bad)
		}
	}
	// The highest version both sides have.
	for _, c := range []struct {
		min, max, proto int
		ok              bool
	}{
		{0, 0, 0, true},               // a peer from before versions
		{0, ProtoMax, ProtoMax, true}, // one of this age
		{ProtoMax, ProtoMax, ProtoMax, true},
		{0, ProtoMax + 5, ProtoMax, true},      // a newer peer that still speaks ours
		{ProtoMax + 1, ProtoMax + 5, 0, false}, // one that no longer does
	} {
		proto, ok := Negotiate(c.min, c.max)
		if ok != c.ok || (ok && proto != c.proto) {
			t.Errorf("Negotiate(%d, %d) = %d, %v; want %d, %v", c.min, c.max, proto, ok, c.proto, c.ok)
		}
	}
	if got := ProtoMismatch(ProtoMax+1, ProtoMax+5); !strings.Contains(got, "upgrade the server") {
		t.Errorf("mismatch with a newer client = %q", got)
	}
}

// Protocol 1 is sealed: these are the names and numbers released binaries
// rely on. A change here is a change to the protocol, which needs a new
// version instead; see proto.go and AGENTS.md.
func TestProtocolOneIsSealed(t *testing.T) {
	for got, want := range map[string]string{
		Path:              "/pf/api/tunnel",
		HeaderWord:        "X-PF-Tunnel-Word",
		HeaderServe:       "X-PF-Serve-Token",
		HeaderConn:        "X-PF-Tunnel-Conn",
		HeaderName:        "X-PF-Tunnel-Name",
		HeaderTarget:      "X-PF-Tunnel-Target",
		HeaderError:       "X-PF-Tunnel-Error",
		HeaderClientHash:  "X-PF-Client-Token-SHA256",
		HeaderClientToken: "X-PF-Client-Token",
		HeaderProto:       "X-PF-Tunnel-Proto",
		HeaderVersion:     "X-PF-Version",
		msgEOF:            "eof",
		msgErrPrefix:      "err:",
	} {
		if got != want {
			t.Errorf("protocol 1 has %q, the code has %q", want, got)
		}
	}
	if ProtoMin != 0 {
		t.Errorf("ProtoMin = %d: peers from before 0.14.0 are still spoken to", ProtoMin)
	}
	if ProtoMax < 1 || protoRelease[1] != "0.14.0" {
		t.Errorf("protocol 1 belongs to 0.14.0; ProtoMax = %d, release %q", ProtoMax, protoRelease[1])
	}
	if got, err := json.Marshal(ServerInfo{Version: "v", ProtoMin: 0, ProtoMax: 1, Token: "t"}); err != nil || string(got) != `{"version":"v","protoMin":0,"protoMax":1,"token":"t"}` {
		t.Errorf("the version probe's answer is %s", got)
	}
	if featureProto[FeatureClientToken].proto != 1 || featureProto[FeatureAnonymousServe].proto != 1 {
		t.Error("client tokens and serving without a serve token are part of protocol 1")
	}
}

// What a run depends on decides the lowest version it offers, and a server
// that answers with less is refused.
func TestClientOffersWhatItNeeds(t *testing.T) {
	c, err := NewClient("https://relay.example.com/", "k3f9-x2mq-7hpa", nil)
	if err != nil {
		t.Fatal(err)
	}
	c.Version = "9.9.9"
	offered := func(endpoint string) string {
		h := http.Header{}
		c.offer(endpoint, h)
		if h.Get(HeaderVersion) != "pf-client 9.9.9" {
			t.Errorf("version header = %q", h.Get(HeaderVersion))
		}
		return h.Get(HeaderProto)
	}
	old, current := http.Header{}, http.Header{}
	current.Set(HeaderProto, "1")

	// A plain tunnel works with anything.
	c.ServeToken = "serve-token-0123456789abcdefghijkl"
	if got := offered("serve"); got != ProtoRange(0, ProtoMax) {
		t.Errorf("plain serve offers %s", got)
	}
	if got := offered("connect"); got != ProtoRange(0, ProtoMax) {
		t.Errorf("plain connect offers %s", got)
	}
	if err := c.answered("serve", old); err != nil {
		t.Errorf("plain serve against an old server = %v", err)
	}

	// A client token needs a server that says it will check it.
	c.ClientToken = "open-sesame"
	for _, endpoint := range []string{"serve", "connect", "check"} {
		if got := offered(endpoint); got != ProtoRange(1, ProtoMax) {
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
	if got := offered("accept"); got != ProtoRange(0, ProtoMax) {
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
