// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package patchbranch

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/outward"
)

// dialBudget bounds establishing one connection, the interactive budget every
// other outbound connection here keeps. What a fetch takes after that is
// bounded by the transfer rate git is told to hold, not by this.
const dialBudget = outward.Timeout

// guard is the one door git has to the network.
//
// Git makes its own connections, so the dialer every other outbound request
// here goes through never sees them. Pointed at this as its proxy, git asks
// for a tunnel to a host and a port, and this decides: the one host the
// repository is on, the https port, and an address outside this network and
// outside what an administrator excluded — checked on the address the name
// resolved to, at the moment of connecting, so a name that answers
// differently the second time it is asked gains nothing.
//
// The tunnel carries TLS end to end. Nothing here reads or can read what
// passes through it.
type guard struct {
	listener net.Listener
	server   *http.Server
	host     string
	excluded outward.Excluded
	// port is the one port a tunnel may be to, and reachable the check an
	// address has to pass. The https port and the excluded list everywhere but
	// the test that opens a tunnel to a server on this machine.
	port      string
	reachable func(address string) error
	// refused is the last reason a tunnel was turned down, so the failure a
	// fetch reports can say why rather than that the proxy said no.
	mu      sync.Mutex
	refused error
}

// openGuard starts a guard for one repository's host, listening on loopback.
func openGuard(host string, excluded outward.Excluded) (*guard, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("open the proxy git reaches out through: %w", err)
	}
	g := &guard{
		listener: listener, host: strings.ToLower(host), excluded: excluded,
		port: "443", reachable: excluded.Reachable,
	}
	g.server = &http.Server{
		Handler:           http.HandlerFunc(g.tunnel),
		ReadHeaderTimeout: dialBudget,
	}
	go func() { _ = g.server.Serve(listener) }()
	return g, nil
}

// address is what git is told its proxy is.
func (g *guard) address() string { return "http://" + g.listener.Addr().String() }

// close stops the guard taking new tunnels. One already open is git's
// connection and ends when git closes its side, or a moment after the far
// end closes.
func (g *guard) close() {
	_ = g.server.Close()
}

// lastRefusal is why the most recent tunnel was turned down, or nil.
func (g *guard) lastRefusal() error {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.refused
}

func (g *guard) refuse(w http.ResponseWriter, err error) {
	g.mu.Lock()
	g.refused = err
	g.mu.Unlock()
	http.Error(w, err.Error(), http.StatusForbidden)
}

// tunnel answers one request for a connection.
func (g *guard) tunnel(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodConnect {
		g.refuse(w, errors.New("refused a request that was not for a tunnel: git reaches a repository over https"))
		return
	}
	host, port, err := net.SplitHostPort(r.Host)
	if err != nil || port != g.port {
		g.refuse(w, fmt.Errorf("refused a tunnel to %s: a repository is reached on the https port", r.Host))
		return
	}
	host = strings.ToLower(host)
	if host != g.host {
		g.refuse(w, fmt.Errorf("refused a tunnel to %s: this fetch is from %s", host, g.host))
		return
	}
	if g.excluded.Host(host) {
		g.refuse(w, fmt.Errorf("refused a tunnel to %s: an administrator excluded it", host))
		return
	}
	dialer := &net.Dialer{
		Timeout: dialBudget,
		Control: func(_, address string, _ syscall.RawConn) error {
			return g.reachable(address)
		},
	}
	ctx, cancel := context.WithTimeout(r.Context(), dialBudget)
	defer cancel()
	upstream, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(host, port))
	if err != nil {
		g.refuse(w, fmt.Errorf("could not reach %s: %w", host, err))
		return
	}
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		_ = upstream.Close()
		g.refuse(w, errors.New("the proxy cannot hand over the connection"))
		return
	}
	w.WriteHeader(http.StatusOK)
	client, buffered, err := hijacker.Hijack()
	if err != nil {
		_ = upstream.Close()
		return
	}
	// What git sent after the request line and before the tunnel opened is
	// the start of its TLS handshake, and belongs to the far end.
	if n := buffered.Reader.Buffered(); n > 0 {
		pending, _ := buffered.Peek(n)
		if _, err := upstream.Write(pending); err != nil {
			_ = client.Close()
			_ = upstream.Close()
			return
		}
	}
	splice(client, upstream)
}

// splice copies both ways until either side closes, then closes both.
func splice(a, b net.Conn) {
	done := make(chan struct{}, 2)
	copying := func(to, from net.Conn) {
		_, _ = io.Copy(to, from)
		// Half-close where the connection allows it, so the other direction
		// can finish what it is sending.
		if closer, ok := to.(interface{ CloseWrite() error }); ok {
			_ = closer.CloseWrite()
		}
		done <- struct{}{}
	}
	go copying(a, b)
	go copying(b, a)
	<-done
	// The second direction is given a moment to finish, and no longer: a peer
	// that stops reading must not hold the tunnel open.
	select {
	case <-done:
	case <-time.After(dialBudget):
	}
	_ = a.Close()
	_ = b.Close()
}
