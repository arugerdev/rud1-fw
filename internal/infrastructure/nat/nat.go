// Package nat discovers and maintains the Pi's public UDP endpoint.
//
// Post-2026-04-22 (no hub): the Pi runs its own WireGuard SERVER and clients
// connect directly over the internet. To make that reachable we:
//
//  1. Try UPnP / NAT-PMP / PCP to ask the router to port-forward the WG port
//     to this Pi. If the router cooperates, `nat.Discover` returns the lease
//     and we're done.
//  2. If UPnP fails, fall back to STUN binding requests against a short list
//     of public STUN servers. The reflexive address tells us what the
//     internet sees for our outgoing UDP socket on that port. Combined with
//     a PersistentKeepalive on every client peer, this works for full-cone
//     and restricted-cone NATs.
//  3. The same STUN probe doubles as a NAT type classifier: hitting two
//     different STUN servers from the same local port and comparing the
//     reflexive addresses tells us whether the mapping is port-restricted
//     (symmetric → P2P impossible without a relay) or consistent.
//
// Callers cache the Endpoint + Type in the heartbeat payload; rud1-es uses
// it to build client .conf files. A 30 min ticker renews the UPnP lease so
// routers that expire mappings after 1-2 h keep the hole open.
package nat

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"strconv"
	"time"

	"github.com/huin/goupnp/dcps/internetgateway1"
	"github.com/huin/goupnp/dcps/internetgateway2"
	"github.com/pion/stun"
	"github.com/rs/zerolog/log"
)

// Discovery is the result of a single `nat.Discover` run. `PublicEndpoint`
// is the "host:port" string the cloud will write into client `.conf` files;
// empty when no endpoint could be established.
type Discovery struct {
	PublicEndpoint string    // "ip:port" or empty
	UPnPOK         bool      // true iff UPnP/IGD mapping succeeded
	NATType        string    // "open" | "restricted" | "symmetric" | "unknown"
	Source         string    // "upnp" | "stun" | "" — which path won
	// CGNAT is true when the reflexive address falls inside RFC 6598
	// (100.64.0.0/10) — the carrier-grade NAT block. P2P WireGuard from a
	// CGNAT'd Pi to an internet client is effectively impossible without
	// IPv6 or an explicit relay; the panel uses this flag to show an
	// actionable warning instead of letting the user fight invisible
	// firewalls.
	CGNAT          bool
	DiscoveredAt   time.Time
}

// Discover attempts UPnP first, STUN second, for a single WireGuard server
// listening on `listenPort`. Returns a best-effort Discovery; callers should
// treat an empty `PublicEndpoint` as "tunnel not yet reachable from the
// internet" and surface that in the heartbeat so rud1-es gates downloads.
func Discover(ctx context.Context, listenPort int) Discovery {
	d := Discovery{DiscoveredAt: time.Now()}

	if ep, ok := tryUPnP(ctx, listenPort); ok {
		d.PublicEndpoint = ep
		d.UPnPOK = true
		d.Source = "upnp"
		// UPnP gave us a real port-forward so the mapping is "open" from
		// the client's point of view; classification only matters for
		// symmetric-NAT warnings and UPnP bypasses it entirely.
		d.NATType = "open"
		d.CGNAT = IsCGNATEndpoint(ep)
		return d
	}

	// STUN fallback — no port-forward, but we can still tell the user what
	// the internet sees and whether P2P is feasible.
	stunEp, natType := probeSTUN(ctx, listenPort)
	if stunEp != "" {
		d.PublicEndpoint = stunEp
		d.Source = "stun"
	}
	d.UPnPOK = false
	d.NATType = natType
	d.CGNAT = IsCGNATEndpoint(stunEp)
	return d
}

// cgnatNet is the RFC 6598 carrier-grade NAT range. Pulled out as a
// package-level var so the parsing cost is paid once at init.
var cgnatNet = mustParseCIDR("100.64.0.0/10")

func mustParseCIDR(s string) *net.IPNet {
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		// Compile-time constant — a parse failure here is a bug.
		panic(err)
	}
	return n
}

// IsCGNATEndpoint reports whether the given "ip:port" string lives inside
// RFC 6598 100.64.0.0/10. A bare IPv4 address (without ":port") is also
// accepted.
func IsCGNATEndpoint(endpoint string) bool {
	if endpoint == "" {
		return false
	}
	host := endpoint
	if h, _, err := net.SplitHostPort(endpoint); err == nil {
		host = h
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	v4 := ip.To4()
	if v4 == nil {
		return false
	}
	return cgnatNet.Contains(v4)
}

// ── UPnP ─────────────────────────────────────────────────────────────────

// tryUPnP walks the IGDv2 → IGDv1 ladder and asks the router for a UDP
// mapping to (internal IP, listenPort). Returns the public endpoint on
// success; empty on any failure (no IGD router, SOAP error, lease denied).
//
// Lease is set to 2 h so expiry survives the typical 1 h router "aggressive
// cleanup" without us constantly polling; the caller's periodic Discover
// call renews it well before it lapses.
func tryUPnP(ctx context.Context, listenPort int) (string, bool) {
	localIP := detectLocalIP()
	if localIP == "" {
		return "", false
	}

	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	// IGDv2 WANIP preferred — fewer routers pretend to support IGDv1 and
	// fail weirdly than the reverse. Ignore errors and keep going.
	if clients, _, _ := internetgateway2.NewWANIPConnection2ClientsCtx(ctx); len(clients) > 0 {
		for _, c := range clients {
			ext, err := c.GetExternalIPAddressCtx(ctx)
			if err != nil || ext == "" {
				continue
			}
			if err := c.AddPortMappingCtx(
				ctx,
				"", // RemoteHost empty = any
				uint16(listenPort),
				"UDP",
				uint16(listenPort),
				localIP,
				true,
				"rud1-wg",
				uint32((2 * time.Hour).Seconds()),
			); err != nil {
				log.Debug().Err(err).Msg("nat: upnp igdv2 add port mapping failed")
				continue
			}
			return fmt.Sprintf("%s:%d", ext, listenPort), true
		}
	}

	// Fallback to IGDv1.
	if clients, _, _ := internetgateway1.NewWANIPConnection1ClientsCtx(ctx); len(clients) > 0 {
		for _, c := range clients {
			ext, err := c.GetExternalIPAddressCtx(ctx)
			if err != nil || ext == "" {
				continue
			}
			if err := c.AddPortMappingCtx(
				ctx,
				"",
				uint16(listenPort),
				"UDP",
				uint16(listenPort),
				localIP,
				true,
				"rud1-wg",
				uint32((2 * time.Hour).Seconds()),
			); err != nil {
				log.Debug().Err(err).Msg("nat: upnp igdv1 add port mapping failed")
				continue
			}
			return fmt.Sprintf("%s:%d", ext, listenPort), true
		}
	}
	return "", false
}

// detectLocalIP returns the non-loopback IPv4 the machine would use to reach
// the internet (via a dummy UDP "connect" trick — no packets actually sent).
// Returns empty string when no suitable interface exists.
func detectLocalIP() string {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return ""
	}
	defer conn.Close()
	addr, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok || addr.IP == nil {
		return ""
	}
	return addr.IP.String()
}

// ── STUN ─────────────────────────────────────────────────────────────────

// publicSTUNServers is the hand-picked list we probe in order. Google is the
// most available; Cloudflare is independent plumbing in case Google blocks us;
// Twilio rounds out the redundancy. All three are free and publicly advertised.
var publicSTUNServers = []string{
	"stun.l.google.com:19302",
	"stun.cloudflare.com:3478",
	"stun1.l.google.com:19302",
}

// probeSTUN does a classic STUN Binding Request from a UDP socket bound to
// `listenPort` (so the reflexive port matches the WG port — critical for
// P2P to work). Returns the reflexive endpoint and a coarse NAT
// classification.
func probeSTUN(ctx context.Context, listenPort int) (endpoint, natType string) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	// Bind a UDP socket on the WG port so our public endpoint matches
	// what the router maps for actual WG traffic. SO_REUSEADDR behavior
	// varies across OSes — if wg-quick already holds the port we fall back
	// to a random port (reflexive address is still useful for display).
	laddr := &net.UDPAddr{Port: listenPort}
	conn, err := net.ListenUDP("udp4", laddr)
	if err != nil {
		conn, err = net.ListenUDP("udp4", &net.UDPAddr{})
		if err != nil {
			return "", "unknown"
		}
	}
	defer conn.Close()

	firstAddr := ""
	for i, server := range publicSTUNServers {
		addr, err := queryOne(ctx, conn, server)
		if err != nil || addr == "" {
			log.Debug().Err(err).Str("stun", server).Msg("nat: stun probe failed")
			continue
		}
		if i == 0 {
			firstAddr = addr
			continue
		}
		// Compare addresses from two DIFFERENT STUN servers to tell
		// symmetric vs non-symmetric: symmetric NAT maps per-destination,
		// so the reflexive address changes between servers.
		if firstAddr == addr {
			return addr, "restricted"
		}
		return addr, "symmetric"
	}
	if firstAddr != "" {
		// Only one server answered — we can't classify; report an
		// optimistic "restricted" since that's the common case.
		return firstAddr, "restricted"
	}
	return "", "unknown"
}

// queryOne sends a single Binding Request over conn to server and waits up
// to 3 s for the response. Returns the XOR-MAPPED-ADDRESS as "ip:port".
func queryOne(ctx context.Context, conn *net.UDPConn, server string) (string, error) {
	raddr, err := net.ResolveUDPAddr("udp4", server)
	if err != nil {
		return "", err
	}
	deadline, _ := ctx.Deadline()
	if err := conn.SetDeadline(deadline); err != nil {
		return "", err
	}

	msg, err := stun.Build(stun.NewTransactionIDSetter(genTxID()), stun.BindingRequest)
	if err != nil {
		return "", fmt.Errorf("build stun: %w", err)
	}
	if _, err := conn.WriteTo(msg.Raw, raddr); err != nil {
		return "", fmt.Errorf("write stun: %w", err)
	}

	buf := make([]byte, 1500)
	n, _, err := conn.ReadFromUDP(buf)
	if err != nil {
		return "", fmt.Errorf("read stun: %w", err)
	}
	resp := &stun.Message{Raw: buf[:n]}
	if err := resp.Decode(); err != nil {
		return "", fmt.Errorf("decode stun: %w", err)
	}
	var xor stun.XORMappedAddress
	if err := xor.GetFrom(resp); err != nil {
		var mapped stun.MappedAddress
		if err2 := mapped.GetFrom(resp); err2 == nil {
			return net.JoinHostPort(mapped.IP.String(), strconv.Itoa(mapped.Port)), nil
		}
		return "", fmt.Errorf("no mapped-address attribute: %w", err)
	}
	return net.JoinHostPort(xor.IP.String(), strconv.Itoa(xor.Port)), nil
}

// genTxID returns a 12-byte STUN transaction ID. STUN's NewTransactionID is
// fine but takes a dependency pattern we don't need — this keeps it local.
func genTxID() [stun.TransactionIDSize]byte {
	var b [stun.TransactionIDSize]byte
	_, err := rand.New(rand.NewSource(time.Now().UnixNano())).Read(b[:])
	if err != nil {
		// Non-fatal: fall back to a zero id. STUN servers accept it, just
		// provides weaker matching if we ever pipeline requests.
		_ = hex.EncodeToString(b[:]) // silence unused-import in release builds
	}
	return b
}

// IsReachable parses an endpoint string and returns true iff it looks like a
// valid public "ip:port". Used by the agent before writing it into the
// heartbeat to avoid reporting obviously-broken values (empty, all-zeros,
// loopback, link-local).
func IsReachable(endpoint string) bool {
	host, portStr, err := net.SplitHostPort(endpoint)
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	if ip.IsLoopback() || ip.IsUnspecified() || ip.IsLinkLocalUnicast() || ip.IsPrivate() {
		return false
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port <= 0 || port > 65535 {
		return false
	}
	return true
}

// ErrNoEndpoint is returned by Renew when the last discovery didn't yield a
// public endpoint — the caller should re-run Discover from scratch.
var ErrNoEndpoint = errors.New("no public endpoint available")
