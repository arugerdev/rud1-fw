package usblister

import (
	"errors"
	"strings"

	"github.com/rud1-es/rud1-fw/internal/config"
)

// ErrPolicyDenied is returned when a device is rejected by the USB policy.
var ErrPolicyDenied = errors.New("usb policy: device not permitted to be shared")

// ErrDeviceNotFound is returned when a busId is not present among the
// physically attached USB devices — policy cannot be evaluated without
// knowing the device's vendor/product/serial.
var ErrDeviceNotFound = errors.New("usb device not found")

// PolicyDecider evaluates USBPolicyConfig against a Device.
//
// An empty Allow list is treated as "allow all". Deny rules always
// trump Allow rules and are checked first.
type PolicyDecider struct {
	cfg *config.USBPolicyConfig
}

// NewPolicyDecider builds a decider from the firmware's USB policy config.
func NewPolicyDecider(cfg *config.USBPolicyConfig) *PolicyDecider {
	return &PolicyDecider{cfg: cfg}
}

// Check returns nil if the device is permitted, ErrPolicyDenied otherwise.
func (p *PolicyDecider) Check(dev Device) error {
	if p == nil || p.cfg == nil {
		return nil // no policy configured → allow all
	}
	for _, rule := range p.cfg.Deny {
		if ruleMatches(rule, dev) {
			return ErrPolicyDenied
		}
	}
	if len(p.cfg.Allow) == 0 {
		return nil // empty allow list == allow all (deny rules already passed)
	}
	for _, rule := range p.cfg.Allow {
		if ruleMatches(rule, dev) {
			return nil
		}
	}
	return ErrPolicyDenied
}

// FindByBusID locates a device in the host's USB tree by bus ID.
func FindByBusID(busID string) (Device, error) {
	devs, err := List()
	if err != nil {
		return Device{}, err
	}
	for _, d := range devs {
		if d.BusID == busID {
			return d, nil
		}
	}
	return Device{}, ErrDeviceNotFound
}

func ruleMatches(rule config.USBPolicyRule, dev Device) bool {
	if !eqHex(rule.VendorID, dev.VendorID) {
		return false
	}
	if !eqHex(rule.ProductID, dev.ProductID) {
		return false
	}
	if rule.Serial != "" && rule.Serial != dev.Serial {
		return false
	}
	return true
}

// eqHex compares two hex-ID strings case-insensitively, tolerating optional
// "0x" prefixes and whitespace.
func eqHex(a, b string) bool {
	return normHex(a) == normHex(b)
}

func normHex(s string) string {
	s = strings.TrimSpace(strings.ToLower(s))
	s = strings.TrimPrefix(s, "0x")
	return s
}

// NormalizeHexID canonicalises a USB vendor/product ID into the form used
// throughout the codebase: lowercase, no "0x" prefix, no whitespace.
// Exported so handlers that accept policy-rule input can pre-normalise
// before writing them back to config.
func NormalizeHexID(s string) string { return normHex(s) }

// ValidHexID reports whether s is a well-formed 4-digit USB vendor/product
// ID (after normalisation). USB IDs are always 16-bit, so we require 1..4
// hex chars (usually 4, but leading zeros may be dropped by humans).
func ValidHexID(s string) bool {
	s = normHex(s)
	if s == "" || len(s) > 4 {
		return false
	}
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9':
		case r >= 'a' && r <= 'f':
		default:
			return false
		}
	}
	return true
}
