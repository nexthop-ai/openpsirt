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

// Excluded is where an administrator said a repository is never fetched from.
//
// Two kinds of entry. A name covers itself and every host under it, so
// `corp.example.com` covers `git.corp.example.com`. A network covers every
// address in it, and is checked against the address a name resolved to rather
// than the name, so a public name pointing into it is refused too.
//
// On top of what is refused regardless: loopback, private, link-local and
// shared address space, which no repository a report names is reached inside
// (REQ-69 and REQ-78).
type Excluded struct {
	names    []string
	networks []*net.IPNet
}

// ParseExcluded reads a comma-separated list of names and networks.
func ParseExcluded(list string) (Excluded, error) {
	var out Excluded
	for _, entry := range strings.Split(list, ",") {
		entry = strings.ToLower(strings.TrimSpace(entry))
		if entry == "" {
			continue
		}
		if strings.Contains(entry, "/") {
			_, network, err := net.ParseCIDR(entry)
			if err != nil {
				return Excluded{}, fmt.Errorf("%q is not a network — write it as 10.0.0.0/8", entry)
			}
			out.networks = append(out.networks, network)
			continue
		}
		if ip := net.ParseIP(entry); ip != nil {
			bits := 8 * len(ip.To4())
			if bits == 0 {
				bits = 128
			}
			out.networks = append(out.networks, &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
			continue
		}
		name := strings.TrimPrefix(entry, ".")
		if !hostName.MatchString(name) {
			return Excluded{}, fmt.Errorf("%q is neither a host name nor a network", entry)
		}
		out.names = append(out.names, name)
	}
	return out, nil
}

// Host reports whether a host is one an administrator excluded by name.
func (e Excluded) Host(host string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	for _, name := range e.names {
		if host == name || strings.HasSuffix(host, "."+name) {
			return true
		}
	}
	if ip := net.ParseIP(host); ip != nil {
		return e.address(ip)
	}
	return false
}

// address reports whether an address is in a network an administrator
// excluded.
func (e Excluded) address(ip net.IP) bool {
	for _, network := range e.networks {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

// Reachable refuses an address inside this network or in one an
// administrator excluded.
func (e Excluded) Reachable(address string) error {
	if err := outward.Reachable(address); err != nil {
		return err
	}
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		host = address
	}
	if ip := net.ParseIP(host); ip != nil && e.address(ip) {
		return fmt.Errorf("refused a connection to %s: an administrator excluded it", ip)
	}
	return nil
}

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
	excluded Excluded
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
func openGuard(host string, excluded Excluded) (*guard, error) {
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
