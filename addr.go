package main

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

// normalizeListen accepts "host:port" or a bare port. A bare port binds to
// defaultHost: "" (every interface) for forwards, 127.0.0.1 for the console.
func normalizeListen(s, defaultHost string) (string, error) {
	s = strings.TrimSpace(s)
	if isPort(s) {
		return net.JoinHostPort(defaultHost, s), nil
	}
	if isDigits(s) {
		return "", fmt.Errorf("invalid listen address %q: port must be 1-65535", s)
	}
	host, port, err := net.SplitHostPort(s)
	if err != nil {
		return "", fmt.Errorf("invalid listen address %q: use host:port or just a port", s)
	}
	if !isPort(port) {
		return "", fmt.Errorf("invalid listen address %q: port must be 1-65535", s)
	}
	return net.JoinHostPort(host, port), nil
}

// normalizeTarget accepts "host:port" or a host alone, which reuses
// defaultPort (the listen port). IPv6 hosts need brackets: "[2001:db8::6]".
func normalizeTarget(s, defaultPort string) (string, error) {
	s = strings.TrimSpace(s)
	host, port, err := net.SplitHostPort(s)
	if err != nil {
		switch {
		case strings.HasPrefix(s, "[") && strings.HasSuffix(s, "]"):
			host = s[1 : len(s)-1]
		case s != "" && !strings.Contains(s, ":"):
			host = s
		default:
			return "", fmt.Errorf("invalid target address %q: use host:port or just a host (IPv6 in brackets)", s)
		}
		port = defaultPort
	}
	if host == "" {
		return "", fmt.Errorf("invalid target address %q: the host is missing", s)
	}
	if !isPort(port) {
		return "", fmt.Errorf("invalid target address %q: port must be 1-65535", s)
	}
	return net.JoinHostPort(host, port), nil
}

func isPort(s string) bool {
	n, err := strconv.Atoi(s)
	return err == nil && n >= 1 && n <= 65535 && strconv.Itoa(n) == s
}

func isDigits(s string) bool {
	return s != "" && strings.Trim(s, "0123456789") == ""
}
