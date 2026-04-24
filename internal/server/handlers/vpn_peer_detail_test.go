package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	wireguard "github.com/rud1-es/rud1-fw/internal/infrastructure/vpn"
	apimiddleware "github.com/rud1-es/rud1-fw/internal/server/middleware"
)

// peerDetailDecoded mirrors vpnPeerDetailResponse but with pointer fields so
// tests can distinguish "missing" from "zero" — the same trick the
// peers-summary tests use to assert against null mean-age.
type peerDetailDecoded struct {
	PublicKey                  string   `json:"publicKey"`
	AllowedIPs                 []string `json:"allowedIPs"`
	Endpoint                   *string  `json:"endpoint"`
	BytesTx                    uint64   `json:"bytesTx"`
	BytesRx                    uint64   `json:"bytesRx"`
	PersistentKeepaliveSeconds int      `json:"persistentKeepaliveSeconds"`
	LatestHandshakeUnix        *int64   `json:"latestHandshakeUnix"`
	HandshakeAgeSeconds        *int64   `json:"handshakeAgeSeconds"`
	Interface                  string   `json:"interface"`
}

// validTestPubkey is a syntactically-correct 44-char base64 WireGuard key
// used everywhere we need the validation guard to pass. It does NOT match
// any real device key — tests that need a "match" path stub the peerFn to
// return this same string back.
const validTestPubkey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

// newTestVPNPeerDetailHandler builds a handler with a fixed peerFn —
// avoids shelling out to wg in unit tests, mirrors the iter 22 summary
// helper.
func newTestVPNPeerDetailHandler(iface string, peer wireguard.RuntimePeer, err error) *VPNPeerDetailHandler {
	return &VPNPeerDetailHandler{
		iface: iface,
		peerFn: func(_, _ string) (wireguard.RuntimePeer, error) {
			return peer, err
		},
	}
}

// withPubkey injects a chi URL param so the handler can be invoked
// directly without going through the router. Mirrors the helper used
// by the usbip session-detail test.
func withPubkey(req *http.Request, pubkey string) *http.Request {
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("pubkey", pubkey)
	return req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
}

// TestVPNPeerDetail_UnauthorizedReturns403 wires the handler behind the same
// BearerAuth middleware server.New uses and asserts a request carrying a
// wrong token is rejected before the handler runs. Mirrors iter 22's
// summary auth test.
func TestVPNPeerDetail_UnauthorizedReturns403(t *testing.T) {
	h := newTestVPNPeerDetailHandler("wg0", wireguard.RuntimePeer{}, wireguard.ErrPeerNotFound)

	r := chi.NewRouter()
	r.Group(func(r chi.Router) {
		r.Use(apimiddleware.BearerAuth("secret-token"))
		r.Get("/api/vpn/peers/{pubkey}", h.Detail)
	})

	req := httptest.NewRequest(http.MethodGet, "/api/vpn/peers/"+validTestPubkey, nil)
	req.Header.Set("Authorization", "Bearer wrong-token")
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 — body=%s", rr.Code, rr.Body.String())
	}
}

// TestVPNPeerDetail_InvalidPubkeyReturns400 covers the format guard:
// any pubkey that isn't exactly 44 chars of valid base64 decoding to 32
// bytes is rejected with code INVALID_PUBKEY before the peerFn is
// invoked. Each case is run as a sub-test so a regression on one variant
// is easy to localise.
func TestVPNPeerDetail_InvalidPubkeyReturns400(t *testing.T) {
	// Stub returns a dummy peer if reached — but the test asserts it
	// is NEVER reached (the format guard short-circuits first).
	called := false
	h := &VPNPeerDetailHandler{
		iface: "wg0",
		peerFn: func(_, _ string) (wireguard.RuntimePeer, error) {
			called = true
			return wireguard.RuntimePeer{}, nil
		},
	}

	cases := map[string]string{
		"empty":         "",
		"too short":     "AAAA",
		"43 chars":      "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",  // 43, missing pad
		"45 chars":      "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", // 45 with extra pad
		"non-base64":    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA!=", // '!' is not a b64 char
		"url-safe alph": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA-_", // '-' / '_' rejected
		"all spaces":    "                                            ", // 44 spaces (will trim to "")
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			called = false
			req := withPubkey(
				httptest.NewRequest(http.MethodGet, "/api/vpn/peers/x", nil),
				raw,
			)
			rr := httptest.NewRecorder()
			h.Detail(rr, req)

			if rr.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400 — body=%s", rr.Code, rr.Body.String())
			}
			var body map[string]string
			if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
				t.Fatalf("unmarshal body: %v (body=%s)", err, rr.Body.String())
			}
			if body["code"] != "INVALID_PUBKEY" {
				t.Fatalf("code = %q, want %q", body["code"], "INVALID_PUBKEY")
			}
			if body["error"] == "" {
				t.Fatalf("error message missing from 400 body=%s", rr.Body.String())
			}
			if called {
				t.Fatalf("peerFn was invoked despite invalid pubkey — guard leaks to backend")
			}
		})
	}
}

// TestVPNPeerDetail_UnknownPubkeyReturns404 asserts the handler translates
// wireguard.ErrPeerNotFound into a 404 with code NOT_FOUND. The pubkey is
// well-formed so the format guard passes; the stub returns the sentinel.
func TestVPNPeerDetail_UnknownPubkeyReturns404(t *testing.T) {
	h := newTestVPNPeerDetailHandler("wg0", wireguard.RuntimePeer{}, wireguard.ErrPeerNotFound)

	req := withPubkey(
		httptest.NewRequest(http.MethodGet, "/api/vpn/peers/x", nil),
		validTestPubkey,
	)
	rr := httptest.NewRecorder()
	h.Detail(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 — body=%s", rr.Code, rr.Body.String())
	}
	var body map[string]string
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal body: %v", err)
	}
	if body["code"] != "NOT_FOUND" {
		t.Fatalf("code = %q, want %q", body["code"], "NOT_FOUND")
	}
}

// TestVPNPeerDetail_ReturnsPeerDetail seeds a fully-populated peer, calls
// the handler, and asserts every field round-trips correctly — including
// pointer-to-time math (handshakeAgeSeconds ≈ now - latest, with a small
// slack for the test clock advancing between stub setup and handler exec).
func TestVPNPeerDetail_ReturnsPeerDetail(t *testing.T) {
	now := time.Now().UTC()
	latest := now.Add(-42 * time.Second)
	peer := wireguard.RuntimePeer{
		PublicKey:           validTestPubkey,
		AllowedIPs:          "10.0.0.5/32, fdc0::5/128",
		Endpoint:            "1.2.3.4:51820",
		LatestHshake:        latest,
		BytesRx:             67890,
		BytesTx:             12345,
		PersistentKeepalive: 25,
	}
	h := newTestVPNPeerDetailHandler("wg0", peer, nil)

	req := withPubkey(
		httptest.NewRequest(http.MethodGet, "/api/vpn/peers/x", nil),
		validTestPubkey,
	)
	rr := httptest.NewRecorder()
	h.Detail(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 — body=%s", rr.Code, rr.Body.String())
	}
	var got peerDetailDecoded
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal body: %v (body=%s)", err, rr.Body.String())
	}

	if got.PublicKey != validTestPubkey {
		t.Fatalf("publicKey = %q, want %q", got.PublicKey, validTestPubkey)
	}
	if got.Interface != "wg0" {
		t.Fatalf("interface = %q, want %q", got.Interface, "wg0")
	}
	if got.BytesTx != 12345 {
		t.Fatalf("bytesTx = %d, want 12345", got.BytesTx)
	}
	if got.BytesRx != 67890 {
		t.Fatalf("bytesRx = %d, want 67890", got.BytesRx)
	}
	if got.PersistentKeepaliveSeconds != 25 {
		t.Fatalf("persistentKeepaliveSeconds = %d, want 25", got.PersistentKeepaliveSeconds)
	}
	// AllowedIPs split + trimmed — the kernel emits "a/32, b/128" with
	// post-comma whitespace and we want the JSON consumer to see two
	// clean entries.
	if len(got.AllowedIPs) != 2 || got.AllowedIPs[0] != "10.0.0.5/32" || got.AllowedIPs[1] != "fdc0::5/128" {
		t.Fatalf("allowedIPs = %v, want [10.0.0.5/32 fdc0::5/128]", got.AllowedIPs)
	}
	if got.Endpoint == nil || *got.Endpoint != "1.2.3.4:51820" {
		t.Fatalf("endpoint = %v, want 1.2.3.4:51820", got.Endpoint)
	}
	if got.LatestHandshakeUnix == nil {
		t.Fatalf("latestHandshakeUnix = nil, want %d", latest.Unix())
	}
	if *got.LatestHandshakeUnix != latest.Unix() {
		t.Fatalf("latestHandshakeUnix = %d, want %d", *got.LatestHandshakeUnix, latest.Unix())
	}
	if got.HandshakeAgeSeconds == nil {
		t.Fatalf("handshakeAgeSeconds = nil, want ~42")
	}
	// Slack for the test clock advancing between stub setup and the
	// handler reading time.Now — 42s ± 2s is plenty.
	if diff := *got.HandshakeAgeSeconds - 42; diff < -2 || diff > 2 {
		t.Fatalf("handshakeAgeSeconds = %d, want 42 (+/-2)", *got.HandshakeAgeSeconds)
	}
}

// TestVPNPeerDetail_NeverHandshakedReturnsNullFields asserts a peer with a
// zero LatestHshake (never connected) yields JSON nulls for both the
// timestamp and the derived age. The UI distinguishes "never handshook"
// from "0 seconds ago" via these nulls.
func TestVPNPeerDetail_NeverHandshakedReturnsNullFields(t *testing.T) {
	peer := wireguard.RuntimePeer{
		PublicKey:  validTestPubkey,
		AllowedIPs: "10.0.0.7/32",
		// Endpoint omitted — "(none)" is normalised to "" by ListPeers,
		// which surfaces as JSON null in the response.
	}
	h := newTestVPNPeerDetailHandler("wg0", peer, nil)

	req := withPubkey(
		httptest.NewRequest(http.MethodGet, "/api/vpn/peers/x", nil),
		validTestPubkey,
	)
	rr := httptest.NewRecorder()
	h.Detail(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 — body=%s", rr.Code, rr.Body.String())
	}
	// Decode into a raw map first so we can assert the fields are JSON
	// null, not the zero value of an int64. encoding/json emits null for
	// nil pointer fields which is exactly what the contract requires.
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(rr.Body.Bytes(), &raw); err != nil {
		t.Fatalf("unmarshal raw body: %v", err)
	}
	for _, key := range []string{"latestHandshakeUnix", "handshakeAgeSeconds", "endpoint"} {
		v, ok := raw[key]
		if !ok {
			t.Fatalf("field %q missing from response — must be present and null", key)
		}
		if string(v) != "null" {
			t.Fatalf("%s = %s, want null", key, string(v))
		}
	}
	// AllowedIPs should still come through as a non-null array even
	// for a never-handshook peer (the routing entry is configured at
	// `wg set` time, before any handshake).
	var got peerDetailDecoded
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal typed body: %v", err)
	}
	if len(got.AllowedIPs) != 1 || got.AllowedIPs[0] != "10.0.0.7/32" {
		t.Fatalf("allowedIPs = %v, want [10.0.0.7/32]", got.AllowedIPs)
	}
}

// TestVPNPeerDetail_PlatformUnsupportedReturns503 asserts the handler
// translates wireguard.ErrVPNUnsupported into a 503 — same pattern as
// iter 22's summary endpoint, so a non-Linux dev host degrades gracefully
// instead of returning a misleading 500/404.
func TestVPNPeerDetail_PlatformUnsupportedReturns503(t *testing.T) {
	h := newTestVPNPeerDetailHandler("wg0", wireguard.RuntimePeer{}, wireguard.ErrVPNUnsupported)

	req := withPubkey(
		httptest.NewRequest(http.MethodGet, "/api/vpn/peers/x", nil),
		validTestPubkey,
	)
	rr := httptest.NewRecorder()
	h.Detail(rr, req)

	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503 — body=%s", rr.Code, rr.Body.String())
	}
}
