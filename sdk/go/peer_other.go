//go:build unix && !linux

package hirzla

import "net"

// checkPeer: the standard library gives no portable peer credentials outside Linux
// (getpeereid needs golang.org/x/sys, which this module does not take). The private socket
// directory, checked by checkSocketDir, is the protection there.
func checkPeer(net.Conn) error { return nil }
