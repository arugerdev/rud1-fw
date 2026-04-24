//go:build linux

package wireguard

import (
	"errors"

	"github.com/rud1-es/rud1-fw/internal/platform"
)

// ErrPeerNotFound is returned by PeerDetail when the supplied pubkey is
// well-formed but no peer with that key is currently installed on the live
// interface. Handlers translate this into a 404 (versus 500/503 for "wg
// failed entirely" or "platform doesn't support WG"), so the VPN dashboard
// can render "this peer was revoked" without surfacing a backend error.
//
// Declared in the linux build file because PeerDetail itself is Linux-only;
// the non-linux stub returns ErrVPNUnsupported before any pubkey is ever
// matched.
var ErrPeerNotFound = errors.New("vpn peer detail: peer not found")

// PeerDetail returns the live RuntimePeer for the given (iface, pubkey)
// pair, suitable for the /api/vpn/peers/{pubkey} drill-down endpoint.
//
// Implemented in terms of ListPeers + linear scan rather than calling
// `wg show <iface> peer <pubkey>` (which would require an extra exec): the
// peer count on a Pi-class device tops out at the low hundreds, so a
// single-pass scan over the dump output is cheaper than a second fork.
//
// On simulated hardware ListPeers returns (nil, nil) which we surface as
// ErrPeerNotFound — there is no peer to look up. Live failures of
// `wg show dump` (binary missing, iface down) propagate as-is.
func PeerDetail(iface, pubkey string) (RuntimePeer, error) {
	if platform.SimulateHardware() {
		// Match the ListPeers contract: simulated hardware has no peers
		// to describe, so any drill-down is a 404. Returning the sentinel
		// keeps callers uniform across the simulated/live path.
		return RuntimePeer{}, ErrPeerNotFound
	}
	peers, err := ListPeers(iface)
	if err != nil {
		return RuntimePeer{}, err
	}
	for _, p := range peers {
		if p.PublicKey == pubkey {
			return p, nil
		}
	}
	return RuntimePeer{}, ErrPeerNotFound
}
