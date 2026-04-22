// Package device models the device identity (the Raspberry Pi running
// the agent) and the registration lifecycle.
package device

import (
	"context"
	"time"
)

// Status enumerates the runtime state of this agent as reported to the cloud.
type Status string

const (
	StatusProvisioning Status = "PROVISIONING"
	StatusConnecting   Status = "CONNECTING"
	StatusOnline       Status = "ONLINE"
	StatusOffline      Status = "OFFLINE"
	StatusError        Status = "ERROR"
)

// Identity represents the device's stable identity after registration.
//
// Post-2026-04-22 (no hub): the Pi is the source of truth for
// RegistrationCode + RegistrationPin. Both are generated at first boot and
// persisted in /boot/rud1-identity.json (FAT partition, survives reinstalls)
// by `platform.BootIdentity`. The `storage.DeviceStore` keeps the runtime
// copy next to the other agent state so the heartbeat loop doesn't touch
// /boot on every tick.
type Identity struct {
	DeviceID         string    `json:"device_id"`
	SerialNumber     string    `json:"serial_number"`
	Hostname         string    `json:"hostname"`
	RegistrationCode string    `json:"registration_code"`
	// RegistrationPin is a 6-digit numeric PIN paired with the code. Printed
	// on the sticker + encoded in the QR that bootstraps the add-device
	// flow. Immutable after first boot.
	RegistrationPin string    `json:"registration_pin"`
	RegisteredAt    time.Time `json:"registered_at"`
}

// Info is the summary returned by the local API /api/system/info.
type Info struct {
	DeviceID     string `json:"device_id"`
	Hostname     string `json:"hostname"`
	AgentVersion string `json:"agent_version"`
	Platform     string `json:"platform"`
	Arch         string `json:"arch"`
	Simulated    bool   `json:"simulated"`
	Status       Status `json:"status"`
	Uptime       int64  `json:"uptime_seconds"`
}

// Repository persists the device identity between restarts.
type Repository interface {
	Load(ctx context.Context) (*Identity, error)
	Save(ctx context.Context, id *Identity) error
	Clear(ctx context.Context) error
}

// Service exposes the device-identity use cases.
type Service interface {
	Current(ctx context.Context) (*Info, error)
	Register(ctx context.Context, code string) (*Identity, error)
	Reset(ctx context.Context) error
}
