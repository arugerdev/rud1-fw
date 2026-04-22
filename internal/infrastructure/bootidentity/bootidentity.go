// Package bootidentity owns the immutable (RegistrationCode, RegistrationPin)
// pair a Rud1 device was born with.
//
// The pair is generated once at first boot and persisted to
// platform.BootIdentityPath() (typically /boot/rud1-identity.json on
// production, so it survives an OS reinstall as long as the SD card is
// preserved). The factory can also pre-seed the file before shipping — the
// agent only generates a new identity when the file is genuinely missing.
//
// Code format is `RUD1-XXXX-XXXX-XXXX-XXXX` using Crockford base32 (24
// alphanumeric chars across 4 groups + fixed prefix). That matches the
// regex enforced by rud1-es in modules/device/domain/schemas.ts. The PIN
// is 6 numeric digits, zero-padded.
package bootidentity

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/rud1-es/rud1-fw/internal/platform"
)

// File is the JSON shape written to disk. Version is reserved for future
// rotations without breaking old agents. Kept small so a sticker-scanning
// pipeline can parse it.
type File struct {
	Version          int    `json:"version"`
	RegistrationCode string `json:"registration_code"`
	RegistrationPin  string `json:"registration_pin"`
	GeneratedAt      string `json:"generated_at"`
}

// Identity is the in-memory subset callers actually use.
type Identity struct {
	RegistrationCode string
	RegistrationPin  string
}

// EnsureIdentity loads the identity from disk, generating a fresh one atomically
// if the file is missing. Subsequent calls always return the persisted values
// unchanged — the code/PIN are immutable for the lifetime of the SD card.
//
// `path` should normally be platform.BootIdentityPath(); overridable for tests.
func EnsureIdentity(path string) (Identity, error) {
	if existing, err := loadIdentity(path); err == nil {
		return existing, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return Identity{}, err
	}

	id, err := generateIdentity()
	if err != nil {
		return Identity{}, err
	}
	if err := writeIdentity(path, id); err != nil {
		return Identity{}, err
	}
	log.Info().
		Str("code", id.RegistrationCode).
		Str("path", path).
		Msg("bootidentity: fresh identity generated")
	return id, nil
}

// QRDeeplink returns the `rud1://add?code=...&pin=...` URI that encodes both
// fields for a one-scan registration from rud1-desktop.
func (i Identity) QRDeeplink() string {
	return fmt.Sprintf("rud1://add?code=%s&pin=%s", i.RegistrationCode, i.RegistrationPin)
}

// ── internals ────────────────────────────────────────────────────────────

func loadIdentity(path string) (Identity, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Identity{}, err
	}
	var f File
	if err := json.Unmarshal(data, &f); err != nil {
		return Identity{}, fmt.Errorf("parse identity: %w", err)
	}
	if !validCode(f.RegistrationCode) {
		return Identity{}, fmt.Errorf("persisted code %q is malformed", f.RegistrationCode)
	}
	if !validPin(f.RegistrationPin) {
		return Identity{}, fmt.Errorf("persisted pin is malformed")
	}
	return Identity{
		RegistrationCode: f.RegistrationCode,
		RegistrationPin:  f.RegistrationPin,
	}, nil
}

func writeIdentity(path string, id Identity) error {
	if err := platform.EnsureDir(filepath.Dir(path)); err != nil {
		return fmt.Errorf("ensure identity dir: %w", err)
	}
	f := File{
		Version:          1,
		RegistrationCode: id.RegistrationCode,
		RegistrationPin:  id.RegistrationPin,
		GeneratedAt:      time.Now().UTC().Format(time.RFC3339),
	}
	data, err := json.MarshalIndent(&f, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	// 0o400: readable only by root. The agent runs as root on the Pi so this
	// is fine; it keeps any accidentally-unprivileged process from leaking
	// the PIN.
	if err := os.WriteFile(tmp, data, 0o400); err != nil {
		return fmt.Errorf("write identity: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("finalise identity: %w", err)
	}
	return nil
}

func generateIdentity() (Identity, error) {
	code, err := generateCode()
	if err != nil {
		return Identity{}, err
	}
	pin, err := generatePin()
	if err != nil {
		return Identity{}, err
	}
	return Identity{RegistrationCode: code, RegistrationPin: pin}, nil
}

// Hex prefix/suffix matches the canonical regex enforced by rud1-es:
//   /^RUD1-[A-F0-9]{8}-[A-F0-9]{8}$/
//
// We draw 8 random bytes = 64 bits, render as two 8-hex groups. 2^64
// possibilities → collision probability negligible for any realistic fleet
// size.
func generateCode() (string, error) {
	var b [8]byte
	if _, err := io.ReadFull(rand.Reader, b[:]); err != nil {
		return "", fmt.Errorf("crypto rand: %w", err)
	}
	return fmt.Sprintf("RUD1-%08X-%08X",
		binary.BigEndian.Uint32(b[0:4]),
		binary.BigEndian.Uint32(b[4:8]),
	), nil
}

// Pin is 6 uniformly-random digits (10^6 space). The cloud's rate limit caps
// brute-force at 10 attempts per code per day, so realistic worst-case time
// to guess is ~273 years.
func generatePin() (string, error) {
	var b [4]byte
	if _, err := io.ReadFull(rand.Reader, b[:]); err != nil {
		return "", fmt.Errorf("crypto rand: %w", err)
	}
	n := binary.BigEndian.Uint32(b[:]) % 1_000_000
	return fmt.Sprintf("%06d", n), nil
}

func validCode(s string) bool {
	if !strings.HasPrefix(s, "RUD1-") || len(s) != len("RUD1-XXXXXXXX-XXXXXXXX") {
		return false
	}
	parts := strings.Split(s, "-")
	if len(parts) != 3 {
		return false
	}
	for _, g := range parts[1:] {
		if len(g) != 8 {
			return false
		}
		for _, c := range g {
			if !(c >= '0' && c <= '9') && !(c >= 'A' && c <= 'F') {
				return false
			}
		}
	}
	return true
}

func validPin(s string) bool {
	if len(s) != 6 {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}
