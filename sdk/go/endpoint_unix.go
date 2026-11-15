//go:build unix

package hirzla

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
)

// ErrUnsafeEndpoint reports a socket directory that is not private to the user, or a
// process behind the socket that runs under another user.
var ErrUnsafeEndpoint = errors.New("hirzla: the core endpoint is not private to the user")

// checkSocketDir applies docs/api-locale.md § 2.1 on the client side: the directory of the
// socket is a real directory (not a symbolic link), owned by the effective user, with no
// right for the group or the others.
func checkSocketDir(path string) error {
	if !filepath.IsAbs(path) {
		return ErrUnsafeEndpoint
	}
	fi, err := os.Lstat(filepath.Dir(path))
	if err != nil || !fi.IsDir() || fi.Mode()&os.ModeSymlink != 0 || fi.Mode().Perm()&0o077 != 0 {
		return ErrUnsafeEndpoint
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || int(st.Uid) != os.Geteuid() {
		return ErrUnsafeEndpoint
	}
	return nil
}
