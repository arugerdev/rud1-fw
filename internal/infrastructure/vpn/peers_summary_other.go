//go:build !linux

package wireguard

import "errors"

// ErrVPNUnsupported is returned by PeersForSummary on non-Linux platforms
// where the WireGuard userspace tools (wg, wg-quick) aren't available.
// Handlers can inspect this via errors.Is to emit a 503 instead of a
// misleading 500.
var ErrVPNUnsupported = errors.New("vpn peers summary: not supported on this platform")

// PeersForSummary is a stub on non-Linux platforms — returns
// ErrVPNUnsupported so the handler can degrade gracefully. The non-summary
// ListPeers path already returns (nil, nil) on simulated hardware for
// backward compatibility with pre-summary callers; this function takes the
// stricter stance because the summary endpoint is meant to surface real
// numbers only.
func PeersForSummary(iface string) ([]RuntimePeer, error) {
	return nil, ErrVPNUnsupported
}
