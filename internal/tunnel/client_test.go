package tunnel

import (
	"strings"
	"testing"
)

func TestCheckSecret(t *testing.T) {
	ok := strings.Repeat("a", MinSecret)
	for _, tc := range []struct {
		secret string
		want   string // "" means accepted
	}{
		{ok, ""},
		{strings.Repeat("x", MaxSecret), ""},
		{ok[:MinSecret-1], "at least 32 characters"},
		{strings.Repeat("x", MaxSecret+1), "at most 128"},
		{ok[:MinSecret-1] + " ", "printable ASCII"},
		{ok + "é", "printable ASCII"},
	} {
		err := CheckSecret("serve token", tc.secret)
		if (err == nil) != (tc.want == "") || (err != nil && !strings.Contains(err.Error(), tc.want)) {
			t.Errorf("CheckSecret(%q) = %v, want %q", tc.secret, err, tc.want)
		}
	}
}

func TestNormalizeBase(t *testing.T) {
	for in, want := range map[string]string{
		"https://relay.example.com":      "https://relay.example.com",
		"https://relay.example.com/":     "https://relay.example.com",
		"https://relay.example.com:8443": "https://relay.example.com:8443",
		"https://relay.example.com/pf/":  "https://relay.example.com",
	} {
		if got, err := normalizeBase(in); err != nil || got != want {
			t.Errorf("normalizeBase(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, in := range []string{"http://relay.example.com/", "relay.example.com", "https://relay.example.com/other", "wss://relay.example.com/"} {
		if got, err := normalizeBase(in); err == nil {
			t.Errorf("normalizeBase(%q) = %q, want an error", in, got)
		}
	}
}

func TestWords(t *testing.T) {
	for in, want := range map[string]string{
		"k3f9-x2mq-7hpa":   "k3f9-x2mq-7hpa",
		"K3F9-X2MQ-7HPA":   "k3f9-x2mq-7hpa",
		" k3f9-X2mq-7hpa ": "k3f9-x2mq-7hpa",
		"O0o0-1iIl-zzzz":   "o0o0-1iil-zzzz", // a typed word may use any letter or digit
	} {
		if got, err := NormalizeWord(in); err != nil || got != want {
			t.Errorf("NormalizeWord(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, in := range []string{"", "asdf123", "k3f9x2mq7hpa", "k3f9-x2mq-7hp", "k3f9-x2mq-7hpa-1", "k3f9_x2mq_7hpa", "k3f9-x2mq-7hp!", "k3f9-x2mq-7hpé"} {
		if got, err := NormalizeWord(in); err == nil {
			t.Errorf("NormalizeWord(%q) = %q, want an error", in, got)
		}
	}
	seen := map[string]bool{}
	for i := 0; i < 200; i++ {
		w, err := NewWord()
		if err != nil {
			t.Fatal(err)
		}
		// A generated word never holds characters that look alike.
		if got, err := NormalizeWord(w); err != nil || got != w || seen[w] || strings.ContainsAny(w, "0o1il") {
			t.Fatalf("NewWord() = %q (%v), repeated: %v", w, err, seen[w])
		}
		seen[w] = true
	}
}
