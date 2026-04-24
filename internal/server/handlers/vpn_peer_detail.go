package handlers

import (
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/rs/zerolog/log"

	wireguard "github.com/rud1-es/rud1-fw/internal/infrastructure/vpn"
)

// VPNPeerDetailHandler serves GET /api/vpn/peers/{pubkey}.
//
// Companion to iter 22's /api/vpn/peers/summary: that endpoint precomputes
// the dashboard tile aggregates; this one is the per-peer drill-down the UI
// opens when the operator taps a row in the peer list. Returning a single
// object (rather than a one-element array) keeps the client-side binding
// boring — same shape as iter 21's /api/usbip/sessions/{busId}.
//
// The peerFn indirection matches /summary's design: tests stub it out so
// they don't need a live wg interface, and production wiring passes
// wireguard.PeerDetail directly.
type VPNPeerDetailHandler struct {
	iface  string
	peerFn func(iface, pubkey string) (wireguard.RuntimePeer, error)
}

// NewVPNPeerDetailHandler wires a handler against the given WG interface.
// Empty iface is accepted for tests; production wiring always passes the
// real wg0-equivalent.
func NewVPNPeerDetailHandler(iface string) *VPNPeerDetailHandler {
	return &VPNPeerDetailHandler{iface: iface, peerFn: wireguard.PeerDetail}
}

// vpnPeerDetailResponse is the wire shape of the drill-down. Nullable
// fields use pointers so the UI can distinguish "we don't have this datum
// yet" (e.g. peer never handshook ⇒ latestHandshakeUnix = null) from
// "the value is literally zero" (which would be a misleading rendering).
//
// Field names mirror iter 22's summary where they overlap (interface,
// publicKey) and the camelCase conventions used by iter 21's session
// detail (allowedIPs, bytesTx, bytesRx). AllowedIPs is split into a
// JSON array — the kernel returns a comma-separated string but every
// caller (rud1-app, rud1-es Connect tab) wants to render the CIDRs as
// a chip list, so doing the split here saves boilerplate at every site.
type vpnPeerDetailResponse struct {
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

// wgPubkeyByteLen is the raw key length for Curve25519 (32 bytes); base64
// encoding produces 44 chars including the trailing '=' pad. Anything else
// is rejected client-side so we never hand garbage to the wireguard tools.
const wgPubkeyByteLen = 32

// Detail handles GET /api/vpn/peers/{pubkey}.
//
// Path param:
//
//	pubkey — WireGuard peer public key, 44-char base64 (32 bytes raw).
//	         Validated locally before hitting the backend so a malformed
//	         pubkey never reaches `wg show`.
//
// Responses:
//
//	200 — vpnPeerDetailResponse for the matched peer.
//	400 — pubkey missing or malformed (error code "INVALID_PUBKEY").
//	404 — pubkey well-formed but absent from the live interface (code
//	      "NOT_FOUND").
//	500 — backend enumeration failed (binary missing, iface down).
//	503 — platform doesn't support WireGuard (e.g. Windows dev).
func (h *VPNPeerDetailHandler) Detail(w http.ResponseWriter, r *http.Request) {
	raw := strings.TrimSpace(chi.URLParam(r, "pubkey"))
	if !validWGPublicKey(raw) {
		// Distinct error code so rud1-app can render "invalid key format"
		// without parsing the human-readable message. We deliberately do
		// NOT fall through to the backend on a malformed pubkey — that
		// would leak attempt-strings into the wg-show argv (and via
		// process accounting, into syslog).
		writeErrorCode(w, http.StatusBadRequest, "INVALID_PUBKEY", "publicKey must be a 44-char base64 WireGuard key")
		return
	}

	peer, err := h.peerFn(h.iface, raw)
	if err != nil {
		switch {
		case errors.Is(err, wireguard.ErrVPNUnsupported):
			writeError(w, http.StatusServiceUnavailable, "vpn peer detail unavailable on this platform")
		case errors.Is(err, wireguard.ErrPeerNotFound):
			writeErrorCode(w, http.StatusNotFound, "NOT_FOUND", "peer not found on interface")
		default:
			log.Warn().Err(err).Str("iface", h.iface).Msg("vpn peer detail: lookup failed")
			writeError(w, http.StatusInternalServerError, "failed to look up WireGuard peer")
		}
		return
	}

	now := time.Now().UTC()

	resp := vpnPeerDetailResponse{
		PublicKey:                  peer.PublicKey,
		AllowedIPs:                 splitAllowedIPs(peer.AllowedIPs),
		BytesTx:                    peer.BytesTx,
		BytesRx:                    peer.BytesRx,
		PersistentKeepaliveSeconds: peer.PersistentKeepalive,
		Interface:                  h.iface,
	}
	if peer.Endpoint != "" {
		ep := peer.Endpoint
		resp.Endpoint = &ep
	}
	if !peer.LatestHshake.IsZero() {
		hs := peer.LatestHshake.Unix()
		// handshakeAgeSeconds is clamped to >=0 so a tiny clock skew
		// between time.Now and a freshly-recorded handshake doesn't
		// produce a negative age (the UI would render that as "in the
		// future" which is nonsensical).
		age := int64(now.Sub(peer.LatestHshake).Seconds())
		if age < 0 {
			age = 0
		}
		resp.LatestHandshakeUnix = &hs
		resp.HandshakeAgeSeconds = &age
	}

	writeJSON(w, http.StatusOK, resp)
}

// validWGPublicKey reports whether s parses as a Curve25519 public key in
// the canonical 44-char base64 form (32 raw bytes + one '=' pad). Stricter
// than a regex-based check: any base64 that doesn't decode to exactly 32
// bytes is rejected, including keys padded with the URL-safe alphabet.
//
// Rejecting before we shell out matters for two reasons: (a) `wg show`
// arguments end up in process listings + syslog, and we don't want to leak
// caller-supplied attempt strings; (b) on a malformed key the wg tooling
// would print a vague "invalid key" stderr that doesn't round-trip through
// our error layer cleanly.
func validWGPublicKey(s string) bool {
	if len(s) != 44 {
		return false
	}
	// StdEncoding (not RawStdEncoding): a real WG pubkey always carries the
	// '=' pad. URLEncoding would accept '-' / '_' which the WG kernel side
	// would reject anyway.
	decoded, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return false
	}
	return len(decoded) == wgPubkeyByteLen
}

// splitAllowedIPs turns the kernel's comma-separated AllowedIPs string into
// a JSON-friendly slice. Empty input → empty slice (so the JSON renders as
// `[]`, never `null` — clients that iterate without a nil-check stay
// happy). Whitespace around each entry is trimmed because `wg show dump`
// occasionally emits "10.0.0.5/32, fdc0::5/128" with a space after the
// comma and we don't want that to leak into the rendered chip label.
func splitAllowedIPs(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return []string{}
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// writeErrorCode is a small extension over writeError that adds a stable
// machine-readable "code" alongside the human "error" message. Used for
// the two negative cases (INVALID_PUBKEY, NOT_FOUND) where the brief
// asked for a discriminated error so the UI can route on it without
// parsing the prose. Other handlers in this package can adopt the same
// shape opportunistically as they're touched.
func writeErrorCode(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, map[string]string{
		"error": msg,
		"code":  code,
	})
}
