package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	wireguard "github.com/rud1-es/rud1-fw/internal/infrastructure/vpn"
	apimiddleware "github.com/rud1-es/rud1-fw/internal/server/middleware"
)

// peersSummaryDecoded mirrors the wire shape but binds nullable fields to
// pointers so tests can distinguish "missing" from "zero".
type peersSummaryDecoded struct {
	WindowSeconds           int64   `json:"windowSeconds"`
	Now                     int64   `json:"now"`
	Interface               string  `json:"interface"`
	PeerCount               int     `json:"peerCount"`
	TotalHandshakes         int     `json:"totalHandshakes"`
	MeanHandshakeAgeSeconds *int64  `json:"meanHandshakeAgeSeconds"`
	StaleCount              int     `json:"staleCount"`
	FreshCount              int     `json:"freshCount"`
	NeverCount              int     `json:"neverCount"`
	LastActivePeer          *string `json:"lastActivePeer"`
}

// newTestVPNPeersSummaryHandler builds a handler backed by a fixed peer
// slice — avoids shelling out to wg in unit tests. Matches the
// dependency-injection style used by other handler tests where the
// underlying data source isn't available off a live interface.
func newTestVPNPeersSummaryHandler(iface string, peers []wireguard.RuntimePeer) *VPNPeersSummaryHandler {
	return &VPNPeersSummaryHandler{
		iface: iface,
		peersFn: func(_ string) ([]wireguard.RuntimePeer, error) {
			return peers, nil
		},
	}
}

// decodePeersSummary unmarshals a JSON body produced by the handler and
// fails the test with a descriptive error if the body is malformed.
func decodePeersSummary(t *testing.T, body []byte) peersSummaryDecoded {
	t.Helper()
	var got peersSummaryDecoded
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("unmarshal body: %v (body=%s)", err, string(body))
	}
	return got
}

// TestVPNPeersSummary_UnauthorizedReturns403 wires the handler behind the
// same BearerAuth middleware server.New uses and asserts a request carrying
// a wrong token is rejected with 403 before the handler runs. A completely
// missing header returns 401, so we deliberately send a malformed Bearer
// to exercise the token-mismatch branch.
func TestVPNPeersSummary_UnauthorizedReturns403(t *testing.T) {
	h := newTestVPNPeersSummaryHandler("wg0", nil)

	r := chi.NewRouter()
	r.Group(func(r chi.Router) {
		r.Use(apimiddleware.BearerAuth("secret-token"))
		r.Get("/api/vpn/peers/summary", h.Summary)
	})

	req := httptest.NewRequest(http.MethodGet, "/api/vpn/peers/summary", nil)
	req.Header.Set("Authorization", "Bearer wrong-token")
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 — body=%s", rr.Code, rr.Body.String())
	}
}

// TestVPNPeersSummary_InvalidWindowReturns400 covers the strict-parse path:
// anything outside {1h, 6h, 24h, 7d} is rejected with 400 and a JSON body
// naming the accepted values. Deliberately stricter than iter 19's
// uptime-summary handler (which clamps quietly) — see parseVPNPeers
// SummaryWindow for the rationale.
func TestVPNPeersSummary_InvalidWindowReturns400(t *testing.T) {
	h := newTestVPNPeersSummaryHandler("wg0", nil)

	cases := []string{"5m", "48h", "garbage", "1", "1h ago", "0h"}
	for _, raw := range cases {
		t.Run(raw, func(t *testing.T) {
			// url.QueryEscape so spaces etc. don't blow up the test
			// harness before the handler runs — the real parse rejection
			// is inside Summary.
			req := httptest.NewRequest(http.MethodGet, "/api/vpn/peers/summary?window="+url.QueryEscape(raw), nil)
			rr := httptest.NewRecorder()
			h.Summary(rr, req)

			if rr.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400 — body=%s", rr.Code, rr.Body.String())
			}
			var body map[string]string
			if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
				t.Fatalf("unmarshal body: %v (body=%s)", err, rr.Body.String())
			}
			if body["error"] == "" {
				t.Fatalf("error field missing from 400 response body=%s", rr.Body.String())
			}
		})
	}
}

// TestVPNPeersSummary_DefaultWindowWhenMissing asserts that a request
// without a `window=` query defaults to 24h (86400 seconds) — matches the
// most common dashboard bucket and mirrors iter 19's default.
func TestVPNPeersSummary_DefaultWindowWhenMissing(t *testing.T) {
	h := newTestVPNPeersSummaryHandler("wg0", nil)

	req := httptest.NewRequest(http.MethodGet, "/api/vpn/peers/summary", nil)
	rr := httptest.NewRecorder()
	h.Summary(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 — body=%s", rr.Code, rr.Body.String())
	}
	got := decodePeersSummary(t, rr.Body.Bytes())
	wantSecs := int64((24 * time.Hour).Seconds())
	if got.WindowSeconds != wantSecs {
		t.Fatalf("windowSeconds = %d, want %d", got.WindowSeconds, wantSecs)
	}
}

// TestVPNPeersSummary_EmptyPeerListReturnsZeros asserts an interface with
// no peers yields zero counts, nil mean-age, nil lastActivePeer, and the
// echoed window — the "cold start" state the VPN dashboard renders
// immediately after a fresh install.
func TestVPNPeersSummary_EmptyPeerListReturnsZeros(t *testing.T) {
	h := newTestVPNPeersSummaryHandler("wg0", nil)

	req := httptest.NewRequest(http.MethodGet, "/api/vpn/peers/summary?window=6h", nil)
	rr := httptest.NewRecorder()
	h.Summary(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 — body=%s", rr.Code, rr.Body.String())
	}
	got := decodePeersSummary(t, rr.Body.Bytes())

	if got.PeerCount != 0 {
		t.Fatalf("peerCount = %d, want 0", got.PeerCount)
	}
	if got.TotalHandshakes != 0 {
		t.Fatalf("totalHandshakes = %d, want 0", got.TotalHandshakes)
	}
	if got.FreshCount != 0 || got.StaleCount != 0 || got.NeverCount != 0 {
		t.Fatalf("counts = {fresh=%d, stale=%d, never=%d}, want all 0", got.FreshCount, got.StaleCount, got.NeverCount)
	}
	if got.MeanHandshakeAgeSeconds != nil {
		t.Fatalf("meanHandshakeAgeSeconds = %v, want null", *got.MeanHandshakeAgeSeconds)
	}
	if got.LastActivePeer != nil {
		t.Fatalf("lastActivePeer = %v, want null", *got.LastActivePeer)
	}
	if got.Interface != "wg0" {
		t.Fatalf("interface = %q, want %q", got.Interface, "wg0")
	}
	if got.WindowSeconds != int64((6 * time.Hour).Seconds()) {
		t.Fatalf("windowSeconds = %d, want %d", got.WindowSeconds, int64((6 * time.Hour).Seconds()))
	}
	if got.Now <= 0 {
		t.Fatalf("now = %d, want > 0", got.Now)
	}
}

// TestVPNPeersSummary_ComputesAggregatesCorrectly seeds a hand-picked peer
// set covering every bucket (fresh, stale, never, plus one just outside
// the window) and asserts every numeric field lines up with the computed
// aggregate. The "just outside the window" peer still contributes to
// mean-age and stale counts (it has handshook in the past, just not
// recently) but NOT to totalHandshakes (which is scoped to the window).
func TestVPNPeersSummary_ComputesAggregatesCorrectly(t *testing.T) {
	now := time.Now().UTC()
	// Handshake ages: 30s (fresh), 5min (stale, inside 1h window),
	// 2h (stale, outside 1h window), never.
	peers := []wireguard.RuntimePeer{
		{PublicKey: "fresh", LatestHshake: now.Add(-30 * time.Second)},
		{PublicKey: "stale-inside", LatestHshake: now.Add(-5 * time.Minute)},
		{PublicKey: "stale-outside", LatestHshake: now.Add(-2 * time.Hour)},
		{PublicKey: "never"},
	}
	h := newTestVPNPeersSummaryHandler("wg0", peers)

	req := httptest.NewRequest(http.MethodGet, "/api/vpn/peers/summary?window=1h", nil)
	rr := httptest.NewRecorder()
	h.Summary(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 — body=%s", rr.Code, rr.Body.String())
	}
	got := decodePeersSummary(t, rr.Body.Bytes())

	if got.PeerCount != 4 {
		t.Fatalf("peerCount = %d, want 4", got.PeerCount)
	}
	// Window = 1h: fresh (30s) + stale-inside (5min) are inside.
	// stale-outside (2h) is NOT counted toward totalHandshakes.
	if got.TotalHandshakes != 2 {
		t.Fatalf("totalHandshakes = %d, want 2", got.TotalHandshakes)
	}
	if got.FreshCount != 1 {
		t.Fatalf("freshCount = %d, want 1", got.FreshCount)
	}
	// Stale = everything older than 3min that did handshake at least once.
	// Peers 'stale-inside' and 'stale-outside' both qualify (5min, 2h).
	if got.StaleCount != 2 {
		t.Fatalf("staleCount = %d, want 2", got.StaleCount)
	}
	if got.NeverCount != 1 {
		t.Fatalf("neverCount = %d, want 1", got.NeverCount)
	}
	// lastActivePeer = most recent handshake (fresh at -30s).
	if got.LastActivePeer == nil || *got.LastActivePeer != "fresh" {
		t.Fatalf("lastActivePeer = %v, want \"fresh\"", got.LastActivePeer)
	}
	// meanHandshakeAgeSeconds is averaged across 3 samples:
	// (30 + 300 + 7200) / 3 = 2510. Allow +/- 2s slack for the test
	// clock advancing between peer construction and handler execution.
	if got.MeanHandshakeAgeSeconds == nil {
		t.Fatalf("meanHandshakeAgeSeconds = nil, want ~2510")
	}
	want := int64((30 + 300 + 7200) / 3)
	if diff := *got.MeanHandshakeAgeSeconds - want; diff < -2 || diff > 2 {
		t.Fatalf("meanHandshakeAgeSeconds = %d, want %d (+/-2)", *got.MeanHandshakeAgeSeconds, want)
	}
}

// TestVPNPeersSummary_PlatformUnsupportedReturns503 asserts the handler
// translates wireguard.ErrVPNUnsupported into a 503 so the dashboard can
// render "not supported on this host" instead of silently showing zeros.
func TestVPNPeersSummary_PlatformUnsupportedReturns503(t *testing.T) {
	h := &VPNPeersSummaryHandler{
		iface: "wg0",
		peersFn: func(_ string) ([]wireguard.RuntimePeer, error) {
			return nil, wireguard.ErrVPNUnsupported
		},
	}

	req := httptest.NewRequest(http.MethodGet, "/api/vpn/peers/summary", nil)
	rr := httptest.NewRecorder()
	h.Summary(rr, req)

	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503 — body=%s", rr.Code, rr.Body.String())
	}
}
