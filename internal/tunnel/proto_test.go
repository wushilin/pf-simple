package tunnel

import (
	"encoding/json"
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
