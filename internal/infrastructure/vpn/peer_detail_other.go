//go:build !linux

package wireguard

import "errors"

// ErrPeerNotFound is the sentinel handlers translate to 404. Declared on
// every build target so cross-platform handler code can reference it
// without build tags, even though the non-linux PeerDetail stub never
// reaches the "match a pubkey" path (it short-circuits with
// ErrVPNUnsupported).
var ErrPeerNotFound = errors.New("vpn peer detail: peer not found")

// PeerDetail is a stub on non-Linux platforms — returns ErrVPNUnsupported
// so the handler can degrade to a 503 instead of returning a fake "peer
// not found" that would mislead the dashboard. Mirrors PeersForSummary's
// stricter stance over the older ListPeers contract.
func PeerDetail(iface, pubkey string) (RuntimePeer, error) {
	return RuntimePeer{}, ErrVPNUnsupported
}
