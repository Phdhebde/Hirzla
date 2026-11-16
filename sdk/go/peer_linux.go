//go:build linux

package hirzla

import (
	"net"
	"os"
	"syscall"
)

// checkPeer reads the credentials of the process behind the socket (SO_PEERCRED) and
// refuses one that runs under another user. The executable of the core is not checked: a
// hardened core is not dumpable, so its /proc/<pid>/exe is unreadable (docs/api-locale.md
// § 3.3).
func checkPeer(conn net.Conn) error {
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return ErrUnsafeEndpoint
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return ErrUnsafeEndpoint
	}
	var cred *syscall.Ucred
	var cerr error
	err = raw.Control(func(fd uintptr) {
		cred, cerr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	})
	if err != nil || cerr != nil || cred == nil || int(cred.Uid) != os.Geteuid() {
		return ErrUnsafeEndpoint
	}
	return nil
}
