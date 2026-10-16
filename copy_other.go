//go:build !linux

package main

import "net"

// copyStream has no splice(2) outside Linux, so it uses a 64KiB buffer.
func copyStream(dst, src net.Conn, activity func()) error {
	return copyBuffered(dst, src, activity)
}
