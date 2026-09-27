package core

// Outbound connections the daemon makes on the operator's say-so: webhooks,
// enrichment sources, update manifests. They may go to the internet or to
// the LAN (a webhook receiver on the NAS is normal), but never to addresses
// that only make sense as an attack from inside the box: link-local (where
// cloud metadata services live, 169.254.169.254), unspecified, or multicast.
// The check runs on the address actually dialled, after DNS, so a name that
// resolves somewhere else later (DNS rebinding) is caught too.

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"syscall"
	"time"
)

// blockedDestination reports addresses no outbound request may reach.
func blockedDestination(ip net.IP) bool {
	return ip == nil || ip.IsUnspecified() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsInterfaceLocalMulticast() || ip.IsMulticast()
}

var guardDialer = &net.Dialer{
	Timeout:   15 * time.Second,
	KeepAlive: 30 * time.Second,
	Control: func(network, address string, _ syscall.RawConn) error {
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			return err
		}
		if blockedDestination(net.ParseIP(host)) {
			return fmt.Errorf("refusing to connect to %s: link-local, multicast and unspecified addresses are never a destination", host)
		}
		return nil
	},
}

// GuardedDial dials like net.Dialer but refuses blocked destinations.
func GuardedDial(ctx context.Context, network, addr string) (net.Conn, error) {
	return guardDialer.DialContext(ctx, network, addr)
}

// Every client that uses the default transport (most of them) is guarded.
func init() {
	if t, ok := http.DefaultTransport.(*http.Transport); ok {
		c := t.Clone()
		c.DialContext = GuardedDial
		http.DefaultTransport = c
	}
}

// MaxResponse caps how much of a response body the daemon reads from a
// service it only needs a status or a short reply from.
const MaxResponse = 1 << 20
