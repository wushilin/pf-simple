//go:build !linux

package main

import "net"

// copyStream has no splice(2) outside Linux, so it uses a 64KiB buffer.
func copyStream(dst, src net.Conn, f *flow) error {
	return copyBuffered(dst, src, f)
}
