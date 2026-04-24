//go:build linux

package wireguard

import "errors"

// ErrVPNUnsupported is returned by PeersForSummary on platforms where the
// WireGuard userspace tools (wg, wg-quick) are not available. On Linux it is
// never returned by the live implementation but is declared here so
// platform-neutral handler code can reference it without build tags.
var ErrVPNUnsupported = errors.New("vpn peers summary: not supported on this platform")

// PeersForSummary returns the live peer set for the given WireGuard
// interface, suitable for aggregation by the /api/vpn/peers/summary handler.
//
// On Linux this wraps ListPeers verbatim — the summary handler consumes the
// same fields (LatestHshake, PublicKey) that ListPeers already returns. A
// nil slice with nil error is a valid answer (no peers configured yet) and
// the handler renders that as zero counts.
func PeersForSummary(iface string) ([]RuntimePeer, error) {
	return ListPeers(iface)
}
