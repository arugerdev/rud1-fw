// Package network models the host network configuration surfaced by the
// agent (interfaces, IP addresses, default gateway, DNS servers).
package network

import "context"

// Interface is a single NIC as reported by the host.
type Interface struct {
	Name       string   `json:"name"`
	MAC        string   `json:"mac"`
	MTU        int      `json:"mtu"`
	Up         bool     `json:"up"`
	IPv4       []string `json:"ipv4"`
	IPv6       []string `json:"ipv6"`
	IsLoopback bool     `json:"is_loopback"`
	IsWireless bool     `json:"is_wireless"`
}

// Status is the aggregated network view returned by /api/network/status.
type Status struct {
	Hostname   string      `json:"hostname"`
	Interfaces []Interface `json:"interfaces"`
	Gateway    string      `json:"gateway"`
	DNS        []string    `json:"dns"`
	Internet   bool        `json:"internet"`
}

// Service exposes network use cases consumed by the HTTP handlers.
type Service interface {
	Status(ctx context.Context) (*Status, error)
	Ping(ctx context.Context, host string) (latencyMs float64, err error)
}
