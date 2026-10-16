package main

import (
	"fmt"
	"math"
	"strconv"
	"strings"
	"sync"
	"time"
)

// limiter is a token bucket shared by every pipe of one forward in one
// direction. Callers move a chunk first and then wait off the debt, so the
// splice path keeps moving bytes in the kernel.
type limiter struct {
	rate  float64 // bytes per second
	burst float64

	mu     sync.Mutex
	tokens float64
	last   time.Time
}

func newLimiter(bytesPerSec float64) *limiter {
	if bytesPerSec <= 0 {
		return nil
	}
	burst := float64(limitedChunk(bytesPerSec))
	return &limiter{rate: bytesPerSec, burst: burst, tokens: burst, last: time.Now()}
}

// limitedChunk sizes copies so a limited flow moves about 20 chunks a second,
// which keeps even a few hundred bytes per second smooth.
func limitedChunk(bytesPerSec float64) int {
	n := int(bytesPerSec / 20)
	return max(256, min(n, copyChunkSize))
}

// reserve charges n bytes and returns how long the caller must wait.
func (l *limiter) reserve(n int64) time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	l.tokens = math.Min(l.burst, l.tokens+now.Sub(l.last).Seconds()*l.rate)
	l.last = now
	l.tokens -= float64(n)
	if l.tokens >= 0 {
		return 0
	}
	return time.Duration(-l.tokens / l.rate * float64(time.Second))
}

// waitAll charges n bytes to every non-nil limiter and sleeps until all of
// them allow it, returning early when cancel closes.
func waitAll(n int64, cancel <-chan struct{}, limiters ...*limiter) {
	if n <= 0 {
		return
	}
	var d time.Duration
	for _, l := range limiters {
		if l != nil {
			d = max(d, l.reserve(n))
		}
	}
	if d <= 0 {
		return
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
	case <-cancel:
	}
}

// parseRate reads a bandwidth such as "100Mbit", "2.5 Gbps", "800KB/s" or
// "64MiB/s" and returns bytes per second. Bit units and KB/MB/GB are decimal;
// KiB/MiB/GiB are binary.
func parseRate(s string) (float64, error) {
	orig := s
	s = strings.TrimSpace(s)
	s = strings.TrimSuffix(s, "/s")
	i := strings.IndexFunc(s, func(r rune) bool { return (r < '0' || r > '9') && r != '.' })
	if i <= 0 {
		return 0, fmt.Errorf("invalid rate %q: want a number and a unit, like 100Mbit or 50MB/s", orig)
	}
	n, err := strconv.ParseFloat(s[:i], 64)
	if err != nil || n <= 0 {
		return 0, fmt.Errorf("invalid rate %q: the number must be positive", orig)
	}
	unit := strings.TrimSpace(s[i:])
	multipliers := map[string]float64{
		"bit": 1.0 / 8, "bps": 1.0 / 8,
		"kbit": 1e3 / 8, "kbps": 1e3 / 8, "mbit": 1e6 / 8, "mbps": 1e6 / 8,
		"gbit": 1e9 / 8, "gbps": 1e9 / 8,
		"b": 1, "kb": 1e3, "mb": 1e6, "gb": 1e9,
		"kib": 1 << 10, "mib": 1 << 20, "gib": 1 << 30,
	}
	// "B" means bytes and "b" bits only in the short forms; accept both cases
	// for the spelled-out units.
	key := strings.ToLower(unit)
	if unit == "b" || unit == "Kb" || unit == "Mb" || unit == "Gb" {
		key += "it"
	}
	m, ok := multipliers[key]
	if !ok {
		return 0, fmt.Errorf("invalid rate %q: unknown unit %q (use bit, Kbit, Mbit, Gbit, B, KB, MB, GB, KiB, MiB or GiB, optionally with /s)", orig, unit)
	}
	return n * m, nil
}

// fmtByteRate formats bytes per second with binary units for logs.
func fmtByteRate(bytesPerSec float64) string {
	v := bytesPerSec
	for _, u := range []string{"B/s", "KiB/s", "MiB/s", "GiB/s"} {
		if v < 1024 || u == "GiB/s" {
			return strconv.FormatFloat(math.Round(v*100)/100, 'f', -1, 64) + " " + u
		}
		v /= 1024
	}
	return ""
}
