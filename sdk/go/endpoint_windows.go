//go:build windows

package hirzla

import (
	"errors"
	"net"
)

// ErrUnsafeEndpoint reports an endpoint the SDK cannot check.
var ErrUnsafeEndpoint = errors.New("hirzla: the core endpoint is not private to the user")

// The core listens on a named pipe under Windows (docs/api-locale.md § 2.2). Opening one with
// SECURITY_IDENTIFICATION needs golang.org/x/sys/windows, which this module does not take
// yet: Dial is not supported on Windows. Use NewClient with a pipe opened by the caller.
func checkSocketDir(string) error {
	return errors.New("hirzla: Dial is not supported on Windows yet")
}

func checkPeer(net.Conn) error { return nil }
