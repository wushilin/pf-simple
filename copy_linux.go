//go:build linux

package main

import (
	"context"
	"errors"
	"io"
	"net"
	"syscall"
	"time"
	"unsafe"
)

const (
	spliceMove     = 0x1 // SPLICE_F_MOVE
	spliceNonblock = 0x2 // SPLICE_F_NONBLOCK

	// While lingering, a read that is not full waits lingerTime once for
	// more, then copies whatever is in the pipe. See copyStream; a
	// low_latency listener never lingers.
	lingerTime = 5 * time.Millisecond
	// lingerGap: reads further apart than this are not one stream.
	lingerGap = 5 * time.Millisecond
	// hintRecheck is how often the size hint is measured again.
	hintRecheck = 100 * time.Millisecond
)

// copyStream moves src to dst with splice(2) through a kernel pipe, so
// payload bytes never enter user space. Both sockets stay non-blocking: on
// EAGAIN the RawConn callbacks return false and the goroutine parks in the
// netpoller, so Close from another goroutine still interrupts the copy.
//
// Go's own TCPConn.ReadFrom also splices, but it loops until its byte limit or
// EOF, which would hide small trickles of traffic from the idle timer. This
// loop counts bytes and reports activity after every chunk it forwards.
func copyStream(dst, src net.Conn, f *flow) error {
	srcTCP, ok1 := src.(*net.TCPConn)
	dstTCP, ok2 := dst.(*net.TCPConn)
	if !ok1 || !ok2 {
		return copyBuffered(dst, src, f)
	}
	srcRaw, err := srcTCP.SyscallConn()
	if err != nil {
		return copyBuffered(dst, src, f)
	}
	dstRaw, err := dstTCP.SyscallConn()
	if err != nil {
		return copyBuffered(dst, src, f)
	}

	var kpipe [2]int
	if err := syscall.Pipe2(kpipe[:], syscall.O_CLOEXEC|syscall.O_NONBLOCK); err != nil {
		return copyBuffered(dst, src, f)
	}
	defer syscall.Close(kpipe[0])
	defer syscall.Close(kpipe[1])
	// The pipe keeps its default 16 slots (64KiB with 4KiB pages). Setting
	// its size would gain nothing there, and with 64KiB pages it would cut
	// the pipe to a single slot.

	chunk := f.chunk()
	spliced := false
	eof := false
	var lastRead, checked time.Time
	// Each direction decides alone, from its own reads; nothing is shared
	// with the other direction.
	//
	// lingering is the mode. Linger in: a read that is not full sleeps
	// lingerTime, tops up with one more splice, then copies. Linger out:
	// every read copies at once. A top-up that gets nothing flips it out:
	// nothing kept arriving, as with a request waiting for its reply or a
	// stream too slow to batch. Every hintRecheck it flips back in, and the
	// next linger tells again. Reads further apart than lingerGap are not a
	// stream and never linger.
	//
	// full is the size hint: a read this big copies at once. It starts at the
	// chunk and drops to what the pipe really holds: from a network card each
	// packet takes one of the pipe's 16 slots, so it holds 16 packets (23168
	// bytes at MSS 1448), while local traffic fills it to 64KiB. The first
	// linger after each recheck measures it, with one ioctl: a top-up that
	// takes less than was waiting means the pipe filled. Any read bigger than
	// it raises it.
	//
	// A speed limit does not change this. Below the limit a flow reads short
	// like any other; at the limit, bytes queue while the limiter waits and
	// the reads come back full. The limiter charges the bytes actually read,
	// so a linger does not change the enforced speed.
	lingering := f.linger
	full := int64(chunk)
	measure := false
	for {
		// Socket -> pipe. The pipe is always empty here, so EAGAIN means the
		// socket has no data yet.
		var inPipe int64
		var serr error
		err := srcRaw.Read(func(fd uintptr) bool {
			inPipe, serr = spliceRetry(int(fd), kpipe[1], chunk)
			return serr != syscall.EAGAIN
		})
		if err == nil {
			err = serr
		}
		if errors.Is(err, syscall.EINVAL) && !spliced {
			// The kernel refused to splice this socket and nothing was consumed.
			return copyBuffered(dst, src, f)
		}
		if err != nil {
			return err
		}
		if inPipe == 0 {
			return nil // src reached EOF (peer sent FIN)
		}
		now := time.Now()
		if now.Sub(checked) >= hintRecheck {
			checked = now
			lingering, full, measure = f.linger, int64(chunk), true
		}
		if lingering && inPipe < full && now.Sub(lastRead) < lingerGap {
			time.Sleep(lingerTime)
			waiting := int64(-1)
			if measure {
				waiting, measure = int64(queued(srcRaw)), false
			}
			var more int64
			_ = srcRaw.Read(func(fd uintptr) bool {
				more, serr = spliceRetry(int(fd), kpipe[1], chunk-int(inPipe))
				return true // never wait: copy what came, whatever it is
			})
			switch {
			case serr == nil && more == 0:
				eof = true // copy what is in the pipe, then stop
			case serr == nil || serr == syscall.EAGAIN:
				more = max(more, 0)
				switch {
				case more < min(waiting, int64(chunk)-inPipe):
					// Less than was waiting: the pipe filled (bytes arriving
					// meanwhile only add to what was waiting).
					full = inPipe + more
				case more == 0:
					lingering = false // nothing arrived: linger out
				}
				inPipe += more
			}
			// Any other error comes back from the next read.
			now = time.Now()
		}
		full = max(full, inPipe)
		lastRead = now
		spliced = true
		f.gotRead(inPipe)
		if !f.throttle(inPipe) {
			return context.Canceled
		}

		// Pipe -> socket, until the pipe is empty again.
		for inPipe > 0 {
			var n int64
			err := dstRaw.Write(func(fd uintptr) bool {
				n, serr = spliceRetry(kpipe[0], int(fd), int(inPipe))
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
			f.wrote(n)
		}
		if eof {
			return nil
		}
	}
}

// queued returns the bytes waiting in the socket's receive queue, or -1 if
// it cannot tell.
func queued(rc syscall.RawConn) int {
	n := int32(-1)
	_ = rc.Control(func(fd uintptr) {
		if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, fd, syscall.TIOCINQ, uintptr(unsafe.Pointer(&n))); e != 0 {
			n = -1
		}
	})
	return int(n)
}

func spliceRetry(from, to, n int) (int64, error) {
	for {
		moved, err := syscall.Splice(from, nil, to, nil, n, spliceMove|spliceNonblock)
		if err != syscall.EINTR {
			return moved, err
		}
	}
}
