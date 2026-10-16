//go:build linux

package main

import (
	"errors"
	"io"
	"net"
	"syscall"
)

const (
	spliceMove     = 0x1 // SPLICE_F_MOVE
	spliceNonblock = 0x2 // SPLICE_F_NONBLOCK
	fSetPipeSize   = 1031
)

// copyStream moves src to dst with splice(2) through a 64KiB kernel pipe, so
// payload bytes never enter user space. Both sockets stay non-blocking: on
// EAGAIN the RawConn callbacks return false and the goroutine parks in the
// netpoller, so Close from another goroutine still interrupts the copy.
//
// Go's own TCPConn.ReadFrom also splices, but it loops until its byte limit or
// EOF, which would hide small trickles of traffic from the idle timer. This
// loop reports activity after every chunk it forwards.
func copyStream(dst, src net.Conn, activity func()) error {
	srcTCP, ok1 := src.(*net.TCPConn)
	dstTCP, ok2 := dst.(*net.TCPConn)
	if !ok1 || !ok2 {
		return copyBuffered(dst, src, activity)
	}
	srcRaw, err := srcTCP.SyscallConn()
	if err != nil {
		return copyBuffered(dst, src, activity)
	}
	dstRaw, err := dstTCP.SyscallConn()
	if err != nil {
		return copyBuffered(dst, src, activity)
	}

	var pipe [2]int
	if err := syscall.Pipe2(pipe[:], syscall.O_CLOEXEC|syscall.O_NONBLOCK); err != nil {
		return copyBuffered(dst, src, activity)
	}
	defer syscall.Close(pipe[0])
	defer syscall.Close(pipe[1])
	// Best effort: the default is 16 pages, which is larger than 64KiB on
	// kernels with 64KiB pages.
	_, _, _ = syscall.Syscall(syscall.SYS_FCNTL, uintptr(pipe[1]), fSetPipeSize, copyChunkSize)

	spliced := false
	for {
		// Socket -> pipe. The pipe is always empty here, so EAGAIN means the
		// socket has no data yet.
		var inPipe int64
		var serr error
		err := srcRaw.Read(func(fd uintptr) bool {
			inPipe, serr = spliceRetry(int(fd), pipe[1], copyChunkSize)
			return serr != syscall.EAGAIN
		})
		if err == nil {
			err = serr
		}
		if errors.Is(err, syscall.EINVAL) && !spliced {
			// The kernel refused to splice this socket and nothing was consumed.
			return copyBuffered(dst, src, activity)
		}
		if err != nil {
			return err
		}
		if inPipe == 0 {
			return nil // src reached EOF (peer sent FIN)
		}
		spliced = true

		// Pipe -> socket, until the pipe is empty again.
		for inPipe > 0 {
			var n int64
			err := dstRaw.Write(func(fd uintptr) bool {
				n, serr = spliceRetry(pipe[0], int(fd), int(inPipe))
				return serr != syscall.EAGAIN
			})
			if err == nil {
				err = serr
			}
			if err != nil {
				return err
			}
			if n == 0 {
				return io.ErrShortWrite // no progress; avoid spinning
			}
			inPipe -= n
		}
		activity()
	}
}

func spliceRetry(from, to, n int) (int64, error) {
	for {
		moved, err := syscall.Splice(from, nil, to, nil, n, spliceMove|spliceNonblock)
		if err != syscall.EINTR {
			return moved, err
		}
	}
}
