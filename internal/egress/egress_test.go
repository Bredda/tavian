package egress

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/bredda/tavian/internal/config"
)

func holder(profile config.Profile, endpoints map[string]config.DestinationClass) *config.Holder {
	h := &config.Holder{}
	h.Store(&config.Snapshot{Profile: profile, Endpoints: endpoints})
	return h
}

func newGuard(t *testing.T, profile config.Profile, endpoints map[string]config.DestinationClass) *Guard {
	t.Helper()
	g, err := New(profile, holder(profile, endpoints), config.DefaultInternalCIDRs())
	if err != nil {
		t.Fatal(err)
	}
	return g
}

func stubLookup(g *Guard, host, ip string) {
	g.lookup = func(_ context.Context, h string) ([]net.IP, error) {
		if h == host {
			return []net.IP{net.ParseIP(ip)}, nil
		}
		return nil, errors.New("no such host")
	}
}

func listener(t *testing.T) (host, port string) {
	t.Helper()
	ts := httptest.NewServer(http.NotFoundHandler())
	t.Cleanup(ts.Close)
	u, _ := url.Parse(ts.URL)
	return u.Hostname(), u.Port()
}

func TestAllowsConfiguredInternalEndpoint(t *testing.T) {
	host, port := listener(t)
	g := newGuard(t, config.ProfileAirGapped, map[string]config.DestinationClass{
		net.JoinHostPort(host, port): config.ClassInternal,
	})
	conn, err := g.DialContext(context.Background(), "tcp", net.JoinHostPort(host, port))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	_ = conn.Close()
}

func TestRefusesUnconfiguredEndpoint(t *testing.T) {
	host, port := listener(t)
	g := newGuard(t, config.ProfileOpenEgress, map[string]config.DestinationClass{
		"other.example.com:443": config.ClassPublicExternal,
	})
	_, err := g.DialContext(context.Background(), "tcp", net.JoinHostPort(host, port))
	if !errors.Is(err, ErrDestinationNotAllowed) {
		t.Fatalf("err = %v, want ErrDestinationNotAllowed", err)
	}
}

func TestInternalBackendMustResolveInternally(t *testing.T) {
	g := newGuard(t, config.ProfileControlledEgress, map[string]config.DestinationClass{
		"llm.corp:8000": config.ClassInternal,
	})
	stubLookup(g, "llm.corp", "93.184.216.34") // public address: DNS poisoned or misconfigured
	_, err := g.DialContext(context.Background(), "tcp", "llm.corp:8000")
	if !errors.Is(err, ErrDestinationNotAllowed) {
		t.Fatalf("err = %v, want ErrDestinationNotAllowed", err)
	}
}

func TestAirGappedRequiresInternalAddressForEveryBackend(t *testing.T) {
	g := newGuard(t, config.ProfileAirGapped, map[string]config.DestinationClass{
		"llm.corp:8000": config.ClassApprovedExternal, // cannot pass Compile in this profile, but defence in depth
	})
	stubLookup(g, "llm.corp", "8.8.8.8")
	_, err := g.DialContext(context.Background(), "tcp", "llm.corp:8000")
	if !errors.Is(err, ErrDestinationNotAllowed) {
		t.Fatalf("err = %v, want ErrDestinationNotAllowed", err)
	}
}

func TestMixedAnswerIsRefused(t *testing.T) {
	g := newGuard(t, config.ProfileControlledEgress, map[string]config.DestinationClass{
		"llm.corp:8000": config.ClassInternal,
	})
	g.lookup = func(context.Context, string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("10.0.0.5"), net.ParseIP("8.8.8.8")}, nil
	}
	_, err := g.DialContext(context.Background(), "tcp", "llm.corp:8000")
	if !errors.Is(err, ErrDestinationNotAllowed) {
		t.Fatalf("err = %v, want ErrDestinationNotAllowed", err)
	}
}

func TestExternalBackendMayResolvePublicallyUnderControlledEgress(t *testing.T) {
	host, port := listener(t) // stands in for the external provider
	g := newGuard(t, config.ProfileControlledEgress, map[string]config.DestinationClass{
		"eu.provider.example:" + port: config.ClassApprovedExternal,
	})
	stubLookup(g, "eu.provider.example", host)
	conn, err := g.DialContext(context.Background(), "tcp", "eu.provider.example:"+port)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	_ = conn.Close()
}

func TestHostMatchingIsCaseInsensitive(t *testing.T) {
	host, port := listener(t)
	g := newGuard(t, config.ProfileOpenEgress, map[string]config.DestinationClass{
		"eu.provider.example:" + port: config.ClassPublicExternal,
	})
	stubLookup(g, "EU.Provider.Example", host)
	conn, err := g.DialContext(context.Background(), "tcp", "EU.Provider.Example:"+port)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	_ = conn.Close()
}

func TestNoConfigurationLoaded(t *testing.T) {
	g, _ := New(config.ProfileOpenEgress, &config.Holder{}, nil)
	if _, err := g.DialContext(context.Background(), "tcp", "x:1"); !errors.Is(err, ErrDestinationNotAllowed) {
		t.Fatalf("err = %v", err)
	}
}

func TestInvalidCIDR(t *testing.T) {
	if _, err := New(config.ProfileOpenEgress, &config.Holder{}, []string{"not-a-cidr"}); err == nil {
		t.Fatal("expected error")
	}
}

func TestHTTPClientDoesNotFollowRedirectsOrUseProxy(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte("should not be reached"))
	}))
	defer target.Close()
	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusFound)
	}))
	defer redirector.Close()

	u, _ := url.Parse(redirector.URL)
	g := newGuard(t, config.ProfileAirGapped, map[string]config.DestinationClass{
		u.Host: config.ClassInternal,
	})
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
	client := g.HTTPClient(5 * time.Second)
	resp, err := client.Get(redirector.URL)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Errorf("status = %d, want the 302 to be handed back, not followed", resp.StatusCode)
	}
}

func TestPinnedEndpointIsAllowedAndMustBeInternal(t *testing.T) {
	host, port := listener(t) // 127.0.0.1, internal
	// No endpoint in the snapshot: only the pin lets the dial through.
	g := newGuard(t, config.ProfileAirGapped, map[string]config.DestinationClass{})
	g.Pin("DB.internal:" + port)
	stubLookup(g, "db.internal", host)
	conn, err := g.DialContext(context.Background(), "tcp", "db.internal:"+port)
	if err != nil {
		t.Fatalf("pinned internal endpoint refused: %v", err)
	}
	_ = conn.Close()

	// The same name resolving outside the internal ranges is refused, even
	// under a profile that allows external backends: a database is never external.
	open := newGuard(t, config.ProfileOpenEgress, map[string]config.DestinationClass{})
	open.Pin("db.internal:" + port)
	stubLookup(open, "db.internal", "8.8.8.8")
	if _, err := open.DialContext(context.Background(), "tcp", "db.internal:"+port); !errors.Is(err, ErrDestinationNotAllowed) {
		t.Errorf("err = %v, want ErrDestinationNotAllowed", err)
	}

	// Pinning one endpoint does not open the others.
	if _, err := g.DialContext(context.Background(), "tcp", "other.internal:"+port); !errors.Is(err, ErrDestinationNotAllowed) {
		t.Errorf("unpinned endpoint: err = %v", err)
	}
}
