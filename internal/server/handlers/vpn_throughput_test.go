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

// throughputDecoded mirrors the wire shape — kept local so a future
// payload extension doesn't silently drift out of sync with tests.
type throughputDecoded struct {
	WindowSeconds   int64                   `json:"windowSeconds"`
	Now             int64                   `json:"now"`
	Interface       string                  `json:"interface"`
	PeerCount       int                     `json:"peerCount"`
	ActivePeerCount int                     `json:"activePeerCount"`
	TotalBytesTx    uint64                  `json:"totalBytesTx"`
	TotalBytesRx    uint64                  `json:"totalBytesRx"`
	ActiveBytesTx   uint64                  `json:"activeBytesTx"`
	ActiveBytesRx   uint64                  `json:"activeBytesRx"`
	TopPeers        []throughputDecodedPeer `json:"topPeers"`
}

type throughputDecodedPeer struct {
	PublicKey  string `json:"publicKey"`
	BytesTx    uint64 `json:"bytesTx"`
	BytesRx    uint64 `json:"bytesRx"`
	TotalBytes uint64 `json:"totalBytes"`
}

// newTestVPNThroughputHandler injects a stub peer source so tests don't
// need a live wg interface. Same dependency-injection style as
// /summary's test harness.
func newTestVPNThroughputHandler(iface string, peers []wireguard.RuntimePeer) *VPNThroughputHandler {
	return &VPNThroughputHandler{
		iface: iface,
		peersFn: func(_ string) ([]wireguard.RuntimePeer, error) {
			return peers, nil
		},
	}
}

func decodeThroughput(t *testing.T, body []byte) throughputDecoded {
	t.Helper()
	var got throughputDecoded
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("unmarshal body: %v (body=%s)", err, string(body))
	}
	return got
}

// TestVPNThroughput_UnauthorizedReturns403 wires the handler behind the
// shared BearerAuth middleware and asserts a wrong token short-circuits
// before the handler runs. Mirrors the equivalent guard test for
// /summary so the bearer envelope stays uniform across the VPN family.
func TestVPNThroughput_UnauthorizedReturns403(t *testing.T) {
	h := newTestVPNThroughputHandler("wg0", nil)

	r := chi.NewRouter()
	r.Group(func(r chi.Router) {
		r.Use(apimiddleware.BearerAuth("secret-token"))
		r.Get("/api/vpn/throughput", h.Throughput)
	})

	req := httptest.NewRequest(http.MethodGet, "/api/vpn/throughput", nil)
	req.Header.Set("Authorization", "Bearer wrong-token")
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 — body=%s", rr.Code, rr.Body.String())
	}
}

// TestVPNThroughput_InvalidWindowReturns400 covers strict-parse — every
// shape that's not in {1h, 6h, 24h, 7d} is rejected with 400. Same
// rationale as /summary: the VPN dashboard renders four buttons; a
// stray value is a client bug to surface, not silently clamp.
func TestVPNThroughput_InvalidWindowReturns400(t *testing.T) {
	h := newTestVPNThroughputHandler("wg0", nil)

	cases := []string{"5m", "48h", "garbage", "1", "1h ago", "0h"}
	for _, raw := range cases {
		t.Run(raw, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/api/vpn/throughput?window="+url.QueryEscape(raw), nil)
			rr := httptest.NewRecorder()
			h.Throughput(rr, req)

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

// TestVPNThroughput_DefaultWindowWhenMissing — bare /throughput must
// default to 24h (86400s). Matches the dashboard's most common bucket.
func TestVPNThroughput_DefaultWindowWhenMissing(t *testing.T) {
	h := newTestVPNThroughputHandler("wg0", nil)

	req := httptest.NewRequest(http.MethodGet, "/api/vpn/throughput", nil)
	rr := httptest.NewRecorder()
	h.Throughput(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 — body=%s", rr.Code, rr.Body.String())
	}
	got := decodeThroughput(t, rr.Body.Bytes())
	wantSecs := int64((24 * time.Hour).Seconds())
	if got.WindowSeconds != wantSecs {
		t.Fatalf("windowSeconds = %d, want %d", got.WindowSeconds, wantSecs)
	}
}

// TestVPNThroughput_EmptyPeerListReturnsZeros — the cold-start state.
// All counters zero, topPeers an empty slice (NOT null), iface echoed.
func TestVPNThroughput_EmptyPeerListReturnsZeros(t *testing.T) {
	h := newTestVPNThroughputHandler("wg0", nil)

	req := httptest.NewRequest(http.MethodGet, "/api/vpn/throughput?window=6h", nil)
	rr := httptest.NewRecorder()
	h.Throughput(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 — body=%s", rr.Code, rr.Body.String())
	}
	got := decodeThroughput(t, rr.Body.Bytes())

	if got.PeerCount != 0 || got.ActivePeerCount != 0 {
		t.Fatalf("peerCount=%d activePeerCount=%d, want 0/0", got.PeerCount, got.ActivePeerCount)
	}
	if got.TotalBytesTx != 0 || got.TotalBytesRx != 0 {
		t.Fatalf("total bytes = (%d,%d), want (0,0)", got.TotalBytesTx, got.TotalBytesRx)
	}
	if got.ActiveBytesTx != 0 || got.ActiveBytesRx != 0 {
		t.Fatalf("active bytes = (%d,%d), want (0,0)", got.ActiveBytesTx, got.ActiveBytesRx)
	}
	if got.TopPeers == nil {
		t.Fatalf("topPeers = null, want empty slice")
	}
	if len(got.TopPeers) != 0 {
		t.Fatalf("topPeers length = %d, want 0", len(got.TopPeers))
	}
	if got.Interface != "wg0" {
		t.Fatalf("interface = %q, want wg0", got.Interface)
	}
}

// TestVPNThroughput_ComputesAggregatesCorrectly seeds a hand-picked
// peer set across every relevant bucket and asserts every aggregate.
//
// Setup (window = 1h):
//
//   - p-active-fresh: handshook 30s ago, 1000 tx, 2000 rx → counts
//     toward total + active
//   - p-active-stale-inside: handshook 5min ago, 500 tx, 0 rx → counts
//     toward total + active (still inside 1h window)
//   - p-stale-outside: handshook 2h ago, 100 tx, 100 rx → counts
//     toward total only (outside window)
//   - p-zero-bytes: handshook 30s ago, 0/0 → counts toward
//     activePeerCount but NOT topPeers
//   - p-never: never handshook, 0/0 → contributes nothing
//
// Total tx = 1000+500+100+0+0 = 1600. Active tx = 1000+500+0 = 1500.
// Top peers (sorted desc by combined): fresh(3000), stale-inside(500),
// stale-outside(200). Zero-byte and never peers excluded.
func TestVPNThroughput_ComputesAggregatesCorrectly(t *testing.T) {
	now := time.Now().UTC()
	peers := []wireguard.RuntimePeer{
		{PublicKey: "p-active-fresh", LatestHshake: now.Add(-30 * time.Second), BytesTx: 1000, BytesRx: 2000},
		{PublicKey: "p-active-stale-inside", LatestHshake: now.Add(-5 * time.Minute), BytesTx: 500, BytesRx: 0},
		{PublicKey: "p-stale-outside", LatestHshake: now.Add(-2 * time.Hour), BytesTx: 100, BytesRx: 100},
		{PublicKey: "p-zero-bytes", LatestHshake: now.Add(-30 * time.Second), BytesTx: 0, BytesRx: 0},
		{PublicKey: "p-never"},
	}
	h := newTestVPNThroughputHandler("wg0", peers)

	req := httptest.NewRequest(http.MethodGet, "/api/vpn/throughput?window=1h", nil)
	rr := httptest.NewRecorder()
	h.Throughput(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 — body=%s", rr.Code, rr.Body.String())
	}
	got := decodeThroughput(t, rr.Body.Bytes())

	if got.PeerCount != 5 {
		t.Fatalf("peerCount = %d, want 5", got.PeerCount)
	}
	// Active = handshook within 1h: fresh, stale-inside, zero-bytes.
	if got.ActivePeerCount != 3 {
		t.Fatalf("activePeerCount = %d, want 3", got.ActivePeerCount)
	}
	if got.TotalBytesTx != 1600 || got.TotalBytesRx != 2100 {
		t.Fatalf("total = (%d,%d), want (1600,2100)", got.TotalBytesTx, got.TotalBytesRx)
	}
	if got.ActiveBytesTx != 1500 || got.ActiveBytesRx != 2000 {
		t.Fatalf("active = (%d,%d), want (1500,2000)", got.ActiveBytesTx, got.ActiveBytesRx)
	}

	if len(got.TopPeers) != 3 {
		t.Fatalf("topPeers len = %d, want 3 (zero/never excluded)", len(got.TopPeers))
	}
	// Sorted descending by combined.
	wantOrder := []string{"p-active-fresh", "p-active-stale-inside", "p-stale-outside"}
	for i, want := range wantOrder {
		if got.TopPeers[i].PublicKey != want {
			t.Fatalf("topPeers[%d] = %q, want %q", i, got.TopPeers[i].PublicKey, want)
		}
	}
	if got.TopPeers[0].TotalBytes != 3000 {
		t.Fatalf("topPeers[0].totalBytes = %d, want 3000", got.TopPeers[0].TotalBytes)
	}
}

// TestVPNThroughput_TopPeersCappedAtFive — feeding more than five
// non-zero peers must clamp the list to vpnThroughputTopPeersLimit (5).
// Catches a regression where the cap was missed and the response
// payload grew unbounded on a fleet device with hundreds of peers.
func TestVPNThroughput_TopPeersCappedAtFive(t *testing.T) {
	now := time.Now().UTC()
	// 8 peers, descending byte order so we can assert the top-5 are the
	// "biggest" five.
	peers := []wireguard.RuntimePeer{
		{PublicKey: "p1", LatestHshake: now, BytesTx: 8000, BytesRx: 0},
		{PublicKey: "p2", LatestHshake: now, BytesTx: 7000, BytesRx: 0},
		{PublicKey: "p3", LatestHshake: now, BytesTx: 6000, BytesRx: 0},
		{PublicKey: "p4", LatestHshake: now, BytesTx: 5000, BytesRx: 0},
		{PublicKey: "p5", LatestHshake: now, BytesTx: 4000, BytesRx: 0},
		{PublicKey: "p6", LatestHshake: now, BytesTx: 3000, BytesRx: 0},
		{PublicKey: "p7", LatestHshake: now, BytesTx: 2000, BytesRx: 0},
		{PublicKey: "p8", LatestHshake: now, BytesTx: 1000, BytesRx: 0},
	}
	h := newTestVPNThroughputHandler("wg0", peers)

	req := httptest.NewRequest(http.MethodGet, "/api/vpn/throughput", nil)
	rr := httptest.NewRecorder()
	h.Throughput(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 — body=%s", rr.Code, rr.Body.String())
	}
	got := decodeThroughput(t, rr.Body.Bytes())

	if len(got.TopPeers) != 5 {
		t.Fatalf("topPeers len = %d, want 5 (cap)", len(got.TopPeers))
	}
	wantTop := []string{"p1", "p2", "p3", "p4", "p5"}
	for i, want := range wantTop {
		if got.TopPeers[i].PublicKey != want {
			t.Fatalf("topPeers[%d] = %q, want %q", i, got.TopPeers[i].PublicKey, want)
		}
	}
}

// TestVPNThroughput_PlatformUnsupportedReturns503 — a wireguard.
// ErrVPNUnsupported from the source maps to 503 (not 500), so the
// dashboard can render "not supported on this host" rather than a
// generic backend failure.
func TestVPNThroughput_PlatformUnsupportedReturns503(t *testing.T) {
	h := &VPNThroughputHandler{
		iface: "wg0",
		peersFn: func(_ string) ([]wireguard.RuntimePeer, error) {
			return nil, wireguard.ErrVPNUnsupported
		},
	}

	req := httptest.NewRequest(http.MethodGet, "/api/vpn/throughput", nil)
	rr := httptest.NewRecorder()
	h.Throughput(rr, req)

	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503 — body=%s", rr.Code, rr.Body.String())
	}
}
