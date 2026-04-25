// Package handlers — system timezone read/write endpoints.
//
// Endpoints:
//
//	GET  /api/system/timezone — current TZ + suggested zones
//	POST /api/system/timezone — set TZ (persisted via timedatectl)
//
// Validation strategy: the wire payload is matched against the contents of
// `/usr/share/zoneinfo` (the same database `timedatectl set-timezone` reads
// from). This keeps the agent honest — we never invoke timedatectl with a
// string the kernel will reject. On simulated hardware (Windows dev) the
// validation falls back to a small curated allow-list and the actual
// timedatectl invocation is skipped.
package handlers

import (
	"encoding/json"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/rud1-es/rud1-fw/internal/infrastructure/audit/configlog"
	"github.com/rud1-es/rud1-fw/internal/platform"
)

// SystemTimezoneHandler serves the timezone endpoints. Read-only operations
// don't touch state on the handler; the mutex guards the Set path so two
// concurrent POSTs can't race timedatectl invocations.
//
// auditLog is optional: nil falls back to configlog.LoggerNoop so tests and
// dev mode (no writable audit dir) keep working without the caller having to
// thread a logger through every constructor.
type SystemTimezoneHandler struct {
	mu       sync.Mutex
	auditLog auditLogger
}

// NewSystemTimezoneHandler — zero-config; the caller wires it into the
// authenticated /api/system/* group in server.go. auditLog may be nil to
// disable the persistent audit trail (tests use this).
func NewSystemTimezoneHandler() *SystemTimezoneHandler {
	return &SystemTimezoneHandler{auditLog: configlog.LoggerNoop{}}
}

// SetAuditLogger swaps in a real audit logger after construction. Wired
// from agent.go where the configlog.DiskLogger is built. Calling with
// nil reverts to the no-op logger so handlers never panic on a missing
// dependency.
func (h *SystemTimezoneHandler) SetAuditLogger(l auditLogger) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if l == nil {
		h.auditLog = configlog.LoggerNoop{}
		return
	}
	h.auditLog = l
}

type systemTimezoneResponse struct {
	Current   string   `json:"current"`
	Source    string   `json:"source"` // "timedatectl" | "tz_env" | "etc_localtime" | "fallback"
	UTCOffset int      `json:"utcOffsetSeconds"`
	Suggested []string `json:"suggested"`
}

// fallbackTimezones is the curated short-list returned when /usr/share/zoneinfo
// isn't readable (Windows dev, container without tzdata). Mirrors the most
// common operator regions for our deployment footprint.
var fallbackTimezones = []string{
	"UTC",
	"Europe/Madrid",
	"Europe/London",
	"Europe/Paris",
	"Europe/Berlin",
	"Europe/Lisbon",
	"Europe/Rome",
	"Europe/Amsterdam",
	"Europe/Dublin",
	"Atlantic/Canary",
	"America/New_York",
	"America/Chicago",
	"America/Los_Angeles",
	"America/Mexico_City",
	"America/Bogota",
	"America/Buenos_Aires",
	"America/Santiago",
	"America/Sao_Paulo",
	"Africa/Casablanca",
	"Asia/Dubai",
	"Asia/Tokyo",
	"Australia/Sydney",
}

// Get — GET /api/system/timezone. Returns the current TZ name (best-effort:
// timedatectl → /etc/localtime → $TZ env → "UTC") and a suggested list of
// zones the UI can use as defaults. The full /usr/share/zoneinfo tree is
// ~600 entries; we cap the response to a curated list to keep mobile
// payloads sub-2KB.
func (h *SystemTimezoneHandler) Get(w http.ResponseWriter, _ *http.Request) {
	current, source := readCurrentTimezone()
	_, offset := time.Now().Zone()
	resp := systemTimezoneResponse{
		Current:   current,
		Source:    source,
		UTCOffset: offset,
		Suggested: suggestedTimezones(),
	}
	writeJSON(w, http.StatusOK, resp)
}

type setTimezoneRequest struct {
	Timezone string `json:"timezone"`
}

// Set — POST /api/system/timezone. Validates the requested zone exists in
// /usr/share/zoneinfo (or in the fallback list on simulated hardware) and
// then invokes `timedatectl set-timezone <tz>`. On simulated hardware the
// invocation is skipped — the validation still applies so dev callers see
// the same error shape they'd see in prod.
//
// Every successful or failed mutation is appended to the persistent audit
// log. Audit failures are warn-logged and never propagate to the caller —
// the originating request always wins.
func (h *SystemTimezoneHandler) Set(w http.ResponseWriter, r *http.Request) {
	var req setTimezoneRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	tz := strings.TrimSpace(req.Timezone)
	if tz == "" {
		writeError(w, http.StatusBadRequest, "timezone required")
		return
	}
	if !isValidTimezone(tz) {
		writeError(w, http.StatusBadRequest, "unknown timezone")
		// Log validation failure so a flood of bad requests is visible.
		h.audit(r, tz, "", false, "unknown timezone")
		return
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	prev, _ := readCurrentTimezone()

	if !platform.SimulateHardware() {
		ctx := r.Context()
		cmd := exec.CommandContext(ctx, "timedatectl", "set-timezone", tz)
		if out, err := cmd.CombinedOutput(); err != nil {
			log.Warn().Err(err).Str("tz", tz).Str("out", strings.TrimSpace(string(out))).Msg("timedatectl set-timezone failed")
			h.audit(r, tz, prev, false, "timedatectl: "+err.Error())
			writeError(w, http.StatusInternalServerError, "failed to set timezone")
			return
		}
	}

	current, source := readCurrentTimezone()
	log.Info().Str("tz", tz).Str("applied", current).Str("source", source).Msg("timezone updated")
	h.audit(r, tz, prev, true, "")
	_, offset := time.Now().Zone()
	writeJSON(w, http.StatusOK, systemTimezoneResponse{
		Current:   current,
		Source:    source,
		UTCOffset: offset,
		Suggested: suggestedTimezones(),
	})
}

// audit appends one configlog.Entry for a timezone mutation. Failures
// are best-effort: a warn log + return, never a 500 to the caller.
func (h *SystemTimezoneHandler) audit(r *http.Request, requested, previous string, ok bool, errMsg string) {
	if h.auditLog == nil {
		return
	}
	var next any
	if ok {
		next = map[string]any{"timezone": requested}
	}
	entry := configlog.Entry{
		Action:   "system.timezone.set",
		Actor:    "operator",
		Previous: map[string]any{"timezone": previous},
		Next:     next,
		OK:       ok,
		Error:    errMsg,
	}
	if err := h.auditLog.Append(r.Context(), entry); err != nil {
		log.Warn().Err(err).Str("action", entry.Action).Msg("audit append failed (non-fatal)")
	}
}

// readCurrentTimezone returns (name, source) using the most authoritative
// signal available. Sources, in order:
//
//  1. `timedatectl show --property=Timezone --value` (Linux only)
//  2. /etc/localtime symlink target → derived path under zoneinfo
//  3. $TZ environment variable
//  4. "UTC" fallback
func readCurrentTimezone() (string, string) {
	if platform.IsLinux() && !platform.SimulateHardware() {
		out, err := exec.Command("timedatectl", "show", "--property=Timezone", "--value").Output()
		if err == nil {
			tz := strings.TrimSpace(string(out))
			if tz != "" {
				return tz, "timedatectl"
			}
		}
		if target, err := os.Readlink("/etc/localtime"); err == nil {
			if name := timezoneFromLocaltimePath(target); name != "" {
				return name, "etc_localtime"
			}
		}
	}
	if env := strings.TrimSpace(os.Getenv("TZ")); env != "" {
		return env, "tz_env"
	}
	return "UTC", "fallback"
}

// timezoneFromLocaltimePath extracts a TZ name like "Europe/Madrid" from a
// /etc/localtime symlink target like "/usr/share/zoneinfo/Europe/Madrid" or
// "../usr/share/zoneinfo/Europe/Madrid". Returns "" on failure.
func timezoneFromLocaltimePath(target string) string {
	target = filepath.ToSlash(target)
	const marker = "/zoneinfo/"
	i := strings.Index(target, marker)
	if i < 0 {
		return ""
	}
	name := strings.TrimPrefix(target[i+len(marker):], "/")
	if name == "" || strings.Contains(name, "..") {
		return ""
	}
	return name
}

// isValidTimezone verifies that the given zone exists in
// /usr/share/zoneinfo. On systems without tzdata (Windows dev), it falls
// back to membership in fallbackTimezones so callers can still exercise
// the wizard end-to-end.
func isValidTimezone(tz string) bool {
	if tz == "" || strings.Contains(tz, "..") || strings.HasPrefix(tz, "/") {
		return false
	}
	zoneinfo := zoneinfoRoot()
	if zoneinfo != "" {
		path := filepath.Join(zoneinfo, filepath.FromSlash(tz))
		// Refuse to resolve paths outside the zoneinfo tree.
		rel, err := filepath.Rel(zoneinfo, path)
		if err != nil || strings.HasPrefix(rel, "..") {
			return false
		}
		if info, err := os.Stat(path); err == nil && !info.IsDir() {
			return true
		}
	}
	for _, candidate := range fallbackTimezones {
		if candidate == tz {
			return true
		}
	}
	return false
}

// suggestedTimezones returns a deduplicated list of zones the UI can show.
// On systems with tzdata, this means: the curated fallback list (always
// shown, in operator-friendly order) PLUS any extra zones that happen to be
// installed under /usr/share/zoneinfo and look like valid Region/City
// entries. The list is capped so we never ship a 600-entry payload.
func suggestedTimezones() []string {
	out := make([]string, 0, 64)
	seen := make(map[string]bool, 64)
	for _, tz := range fallbackTimezones {
		if !seen[tz] {
			seen[tz] = true
			out = append(out, tz)
		}
	}
	zoneinfo := zoneinfoRoot()
	if zoneinfo == "" {
		return out
	}
	extra := make([]string, 0, 256)
	_ = filepath.Walk(zoneinfo, func(path string, info os.FileInfo, err error) error {
		if err != nil || info == nil || info.IsDir() {
			return nil
		}
		rel, rerr := filepath.Rel(zoneinfo, path)
		if rerr != nil {
			return nil
		}
		rel = filepath.ToSlash(rel)
		if !looksLikeZoneName(rel) {
			return nil
		}
		if !seen[rel] {
			seen[rel] = true
			extra = append(extra, rel)
		}
		return nil
	})
	sort.Strings(extra)
	const cap = 256
	for _, tz := range extra {
		if len(out) >= cap {
			break
		}
		out = append(out, tz)
	}
	return out
}

// looksLikeZoneName filters out the synthetic files under /usr/share/zoneinfo
// that aren't IANA region/city entries — `posix/`, `right/`, `Etc/`, the
// uppercase shortcuts, and any single-segment names. Region/City format is
// a sufficient heuristic for the suggestion list (the strict validator
// above remains the source of truth on writes).
func looksLikeZoneName(rel string) bool {
	if strings.HasPrefix(rel, "posix/") || strings.HasPrefix(rel, "right/") {
		return false
	}
	parts := strings.Split(rel, "/")
	if len(parts) < 2 {
		return false
	}
	region := parts[0]
	if region == "Etc" || region == "SystemV" || region == "US" {
		return false
	}
	first := region[0]
	if first < 'A' || first > 'Z' {
		return false
	}
	return true
}

// zoneinfoRoot returns the canonical zoneinfo root on systems where it
// exists, or "" otherwise. On simulated hardware we still consult the dir
// if present (helps testing on Linux dev machines) but never error if it
// isn't.
func zoneinfoRoot() string {
	const root = "/usr/share/zoneinfo"
	if info, err := os.Stat(root); err == nil && info.IsDir() {
		return root
	}
	return ""
}
