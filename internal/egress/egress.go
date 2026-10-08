// Package egress is the only place in Tavian that opens outbound connections
// (ADR-0008). Destinations are limited to the endpoints of configured
// backends; backends that must stay internal (and every backend under the
// air-gapped profile) may only resolve to internal addresses.
package egress

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/bredda/tavian/internal/config"
)

// ErrDestinationNotAllowed is returned for any dial that policy forbids.
var ErrDestinationNotAllowed = errors.New("egress: destination not allowed")

// Guard decides whether a connection may be opened.
type Guard struct {
	profile  config.Profile
	snap     *config.Holder
	internal []*net.IPNet
	dialer   net.Dialer
	lookup   func(ctx context.Context, host string) ([]net.IP, error)
}

// New builds a Guard. internalCIDRs defines what counts as internal.
func New(profile config.Profile, snap *config.Holder, internalCIDRs []string) (*Guard, error) {
	g := &Guard{
		profile: profile,
		snap:    snap,
		dialer:  net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second},
	}
	for _, c := range internalCIDRs {
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			return nil, fmt.Errorf("egress: invalid internal CIDR %q: %w", c, err)
		}
		g.internal = append(g.internal, n)
	}
	g.lookup = func(ctx context.Context, host string) ([]net.IP, error) {
		addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
		if err != nil {
			return nil, err
		}
		ips := make([]net.IP, 0, len(addrs))
		for _, a := range addrs {
			ips = append(ips, a.IP)
		}
		return ips, nil
	}
	return g, nil
}

func (g *Guard) isInternal(ip net.IP) bool {
	for _, n := range g.internal {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// DialContext implements the dial function of http.Transport.
func (g *Guard) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("%w: malformed address %q", ErrDestinationNotAllowed, addr)
	}
	key := net.JoinHostPort(strings.ToLower(host), port)

	s := g.snap.Load()
	if s == nil {
		return nil, fmt.Errorf("%w: no configuration loaded", ErrDestinationNotAllowed)
	}
	class, ok := s.Endpoints[key]
	if !ok {
		return nil, fmt.Errorf("%w: %s is not a configured endpoint (backend or identity provider)", ErrDestinationNotAllowed, key)
	}

	var ips []net.IP
	if ip := net.ParseIP(host); ip != nil {
		ips = []net.IP{ip}
	} else if ips, err = g.lookup(ctx, host); err != nil {
		return nil, fmt.Errorf("egress: resolve %s: %w", host, err)
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("egress: %s resolved to no address", host)
	}

	// Every resolved address is checked, not just the one we dial, so a
	// split-horizon or rebinding answer mixing internal and public addresses
	// is refused outright.
	if g.profile == config.ProfileAirGapped || class == config.ClassInternal {
		for _, ip := range ips {
			if !g.isInternal(ip) {
				return nil, fmt.Errorf("%w: %s (class %s, profile %s) resolves to non-internal address %s",
					ErrDestinationNotAllowed, key, class, g.profile, ip)
			}
		}
	}

	var lastErr error
	for _, ip := range ips {
		conn, err := g.dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
		if err == nil {
			return conn, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

// HTTPClient returns a client whose only way out is the guard.
func (g *Guard) HTTPClient(responseHeaderTimeout time.Duration) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			// Never honour HTTP(S)_PROXY from the environment: all egress goes
			// through DialContext. An explicit outbound proxy option comes later.
			Proxy:                 nil,
			DialContext:           g.DialContext,
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          100,
			MaxIdleConnsPerHost:   32,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ResponseHeaderTimeout: responseHeaderTimeout,
		},
		// A redirect is an unreviewed destination: hand it back to the caller.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}
