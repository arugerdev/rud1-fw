package handlers

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/rud1-es/rud1-fw/internal/config"
	usblister "github.com/rud1-es/rud1-fw/internal/infrastructure/usb"
)

// revocationLogSize is the maximum number of revocation entries kept in
// memory. Entries are surfaced to rud1-app so the operator can see which
// bus IDs were unbound by a policy sweep (and why). 32 is plenty for a
// poll-every-5s UI — older entries get overwritten silently.
const revocationLogSize = 32

// RevocationReason enumerates why a previously-exported bus ID was unbound
// by ReenforcePolicy. "policy" means the rule set no longer permits the
// device; "unplugged" means the device disappeared from the USB tree while
// still marked as exported in memory.
type RevocationReason string

const (
	RevocationReasonPolicy    RevocationReason = "policy"
	RevocationReasonUnplugged RevocationReason = "unplugged"
)

// RevocationEntry is one row in the /api/usbip/revocations response.
//
// For "unplugged" entries vendor/product/serial may be empty because the
// device was already gone from the tree by the time we noticed the stale
// export. For "policy" entries the fields are populated from the same
// usblister.Device struct that the policy decider just rejected, so
// rud1-app can surface a toast like "Revoked: SanDisk Ultra USB (1-1)".
type RevocationEntry struct {
	BusID       string           `json:"busId"`
	VendorID    string           `json:"vendorId,omitempty"`
	ProductID   string           `json:"productId,omitempty"`
	Serial      string           `json:"serial,omitempty"`
	VendorName  string           `json:"vendorName,omitempty"`
	ProductName string           `json:"productName,omitempty"`
	Reason      RevocationReason `json:"reason"`
	At          int64            `json:"at"` // unix seconds
}

// USBIPHandler manages USB/IP export operations and the attach-time policy.
//
// The handler holds a pointer to the process-wide Config so mutations to
// the USB policy (via PUT /api/usbip/policy) can be persisted back to
// disk via Config.Save(). A single sync.RWMutex serialises policy reads
// and writes: bind() takes RLock before calling PolicyDecider.Check, and
// SetPolicy takes the write lock while it rebuilds the decider, updates
// the config in memory, and flushes it to disk.
type USBIPHandler struct {
	server *usblister.USBIPServer
	full   *config.Config
	cfg    *config.USBConfig
	policy *usblister.PolicyDecider
	mu     sync.RWMutex

	// revMu guards the revocation ring buffer. Kept separate from `mu` so
	// ReenforcePolicy (which already holds mu.RLock for the policy snapshot)
	// can append without lock upgrade gymnastics.
	revMu  sync.Mutex
	revLog []RevocationEntry // ring buffer; len grows up to revocationLogSize
	revPos int               // next write index when len == revocationLogSize
}

// NewUSBIPHandler creates and (if enabled) starts the USB/IP server.
//
// full is the process-wide Config; the handler keeps a pointer so policy
// updates received over HTTP can be persisted to the same YAML file the
// agent booted from.
func NewUSBIPHandler(full *config.Config) *USBIPHandler {
	cfg := &full.USB
	srv := usblister.NewUSBIPServer(cfg.BindPort)
	if cfg.USBIPEnabled {
		if err := srv.Start(); err != nil {
			log.Warn().Err(err).Msg("usbipd start failed — USB/IP exports unavailable")
		} else {
			log.Info().Int("port", cfg.BindPort).Msg("usbipd started")
		}
	}
	return &USBIPHandler{
		server: srv,
		full:   full,
		cfg:    cfg,
		policy: usblister.NewPolicyDecider(&cfg.Policy),
	}
}

// Server exposes the underlying USBIPServer so the heartbeat loop can share
// the same instance and report the authoritative exported-device list.
func (h *USBIPHandler) Server() *usblister.USBIPServer { return h.server }

// Stop shuts down the USB/IP daemon.
func (h *USBIPHandler) Stop() { h.server.Stop() }

// isAuthorized checks whether the request comes from an authorized CIDR.
func (h *USBIPHandler) isAuthorized(r *http.Request) bool {
	if len(h.cfg.AuthorizedNets) == 0 {
		return true // no restrictions configured
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	for _, cidr := range h.cfg.AuthorizedNets {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

// Status handles GET /api/usbip/status.
func (h *USBIPHandler) Status(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"enabled":  h.cfg.USBIPEnabled,
		"port":     h.cfg.BindPort,
		"exported": h.server.ExportedDevices(),
	})
}

// Exportable handles GET /api/usbip/exportable.
func (h *USBIPHandler) Exportable(w http.ResponseWriter, r *http.Request) {
	if !h.isAuthorized(r) {
		writeError(w, http.StatusForbidden, "client IP not in authorized_nets")
		return
	}
	ids, err := usblister.ListExportable()
	if err != nil {
		log.Error().Err(err).Msg("list exportable failed")
		writeError(w, http.StatusInternalServerError, "failed to list exportable devices")
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"devices": ids})
}

type busRequest struct {
	BusID string `json:"busId"`
}

// bind enforces policy + authorization before delegating to the usbip daemon.
func (h *USBIPHandler) bind(busID string) (int, error) {
	dev, err := usblister.FindByBusID(busID)
	if err != nil {
		if errors.Is(err, usblister.ErrDeviceNotFound) {
			return http.StatusNotFound, err
		}
		return http.StatusInternalServerError, err
	}
	h.mu.RLock()
	policy := h.policy
	h.mu.RUnlock()
	if err := policy.Check(dev); err != nil {
		return http.StatusForbidden, err
	}
	if err := h.server.Export(busID); err != nil {
		return http.StatusInternalServerError, err
	}
	return http.StatusOK, nil
}

// Export handles POST /api/usbip/export — binds a USB device for remote access.
//
// Alias: Attach (POST /api/usbip/attach). Both routes share the same
// policy-checked code path.
func (h *USBIPHandler) Export(w http.ResponseWriter, r *http.Request) {
	if !h.isAuthorized(r) {
		writeError(w, http.StatusForbidden, "client IP not in authorized_nets")
		return
	}
	var req busRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.BusID == "" {
		writeError(w, http.StatusBadRequest, "busId required")
		return
	}
	status, err := h.bind(req.BusID)
	if err != nil {
		log.Warn().Err(err).Str("busId", req.BusID).Int("status", status).Msg("usbip bind rejected")
		writeError(w, status, err.Error())
		return
	}
	log.Info().Str("busId", req.BusID).Msg("usbip device shared")
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// Unexport handles DELETE /api/usbip/export — unbinds a USB device.
//
// Alias: Detach (DELETE /api/usbip/attach).
func (h *USBIPHandler) Unexport(w http.ResponseWriter, r *http.Request) {
	if !h.isAuthorized(r) {
		writeError(w, http.StatusForbidden, "client IP not in authorized_nets")
		return
	}
	var req busRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.BusID == "" {
		writeError(w, http.StatusBadRequest, "busId required")
		return
	}
	if err := h.server.Unexport(req.BusID); err != nil {
		log.Error().Err(err).Str("busId", req.BusID).Msg("usbip unbind failed")
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	log.Info().Str("busId", req.BusID).Msg("usbip device unshared")
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// Sessions handles GET /api/usbip/sessions — returns the live kernel state
// (bound / attached) per bus ID, read from sysfs usbip_status.
func (h *USBIPHandler) Sessions(w http.ResponseWriter, r *http.Request) {
	if !h.isAuthorized(r) {
		writeError(w, http.StatusForbidden, "client IP not in authorized_nets")
		return
	}
	sessions, err := usblister.ListSessions()
	if err != nil {
		log.Error().Err(err).Msg("list usbip sessions failed")
		writeError(w, http.StatusInternalServerError, "failed to list usbip sessions")
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"sessions": sessions})
}

// policyResponse is the shape of both GET and PUT /api/usbip/policy.
type policyResponse struct {
	Allow      []config.USBPolicyRule `json:"allow"`
	Deny       []config.USBPolicyRule `json:"deny"`
	Enforcing  bool                   `json:"enforcing"`
	Authorized []string               `json:"authorized"`
}

func (h *USBIPHandler) currentPolicyResponse() policyResponse {
	h.mu.RLock()
	defer h.mu.RUnlock()
	// Copy slices to avoid handing back shared mutable state.
	allow := append([]config.USBPolicyRule(nil), h.cfg.Policy.Allow...)
	deny := append([]config.USBPolicyRule(nil), h.cfg.Policy.Deny...)
	auth := append([]string(nil), h.cfg.AuthorizedNets...)
	return policyResponse{
		Allow:      allow,
		Deny:       deny,
		Enforcing:  len(allow) > 0,
		Authorized: auth,
	}
}

// Policy handles GET /api/usbip/policy — lets the local panel inspect which
// devices the operator has permitted to be shared.
func (h *USBIPHandler) Policy(w http.ResponseWriter, r *http.Request) {
	if !h.isAuthorized(r) {
		writeError(w, http.StatusForbidden, "client IP not in authorized_nets")
		return
	}
	writeJSON(w, http.StatusOK, h.currentPolicyResponse())
}

// policyUpdateRequest is the body accepted by PUT /api/usbip/policy.
//
// Slices may be omitted to mean "leave as-is"; nil is distinguished from
// an empty array via pointer-to-slice. An explicit empty array clears
// the list (e.g. sending {"allow": []} switches back to permissive mode).
type policyUpdateRequest struct {
	Allow *[]config.USBPolicyRule `json:"allow,omitempty"`
	Deny  *[]config.USBPolicyRule `json:"deny,omitempty"`
}

// normalizeAndValidateRules normalises vendor/product IDs to lowercase
// 4-hex form and rejects malformed entries. Duplicate rules are de-duped
// (vendor+product+serial tuple) so editing flows that append blindly
// don't grow the file forever.
func normalizeAndValidateRules(in []config.USBPolicyRule, listName string) ([]config.USBPolicyRule, error) {
	if in == nil {
		return nil, nil
	}
	out := make([]config.USBPolicyRule, 0, len(in))
	seen := make(map[string]struct{}, len(in))
	for i, r := range in {
		vid := usblister.NormalizeHexID(r.VendorID)
		pid := usblister.NormalizeHexID(r.ProductID)
		if !usblister.ValidHexID(vid) {
			return nil, fmt.Errorf("%s[%d]: vendorId %q is not a valid 1-4 digit hex id", listName, i, r.VendorID)
		}
		if !usblister.ValidHexID(pid) {
			return nil, fmt.Errorf("%s[%d]: productId %q is not a valid 1-4 digit hex id", listName, i, r.ProductID)
		}
		serial := r.Serial
		key := vid + ":" + pid + ":" + serial
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, config.USBPolicyRule{
			VendorID:  vid,
			ProductID: pid,
			Serial:    serial,
		})
	}
	return out, nil
}

// SetPolicy handles PUT /api/usbip/policy — replaces the USB/IP attach
// policy in memory and persists the mutation back to config.yaml.
//
// The body is a partial update: omitting "allow" or "deny" leaves that
// list untouched; sending an explicit empty array clears it. The response
// returns the full post-update policy (same shape as GET).
func (h *USBIPHandler) SetPolicy(w http.ResponseWriter, r *http.Request) {
	if !h.isAuthorized(r) {
		writeError(w, http.StatusForbidden, "client IP not in authorized_nets")
		return
	}
	var req policyUpdateRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body: "+err.Error())
		return
	}
	if req.Allow == nil && req.Deny == nil {
		writeError(w, http.StatusBadRequest, "body must contain allow and/or deny")
		return
	}

	var newAllow, newDeny []config.USBPolicyRule
	var err error
	if req.Allow != nil {
		newAllow, err = normalizeAndValidateRules(*req.Allow, "allow")
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
	}
	if req.Deny != nil {
		newDeny, err = normalizeAndValidateRules(*req.Deny, "deny")
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
	}

	h.mu.Lock()
	// Snapshot the current policy so we can roll back in-memory state if
	// the disk write fails.
	prevAllow := append([]config.USBPolicyRule(nil), h.cfg.Policy.Allow...)
	prevDeny := append([]config.USBPolicyRule(nil), h.cfg.Policy.Deny...)

	if req.Allow != nil {
		h.cfg.Policy.Allow = newAllow
	}
	if req.Deny != nil {
		h.cfg.Policy.Deny = newDeny
	}
	h.policy = usblister.NewPolicyDecider(&h.cfg.Policy)

	saveErr := h.full.Save()
	if saveErr != nil {
		// Rollback in-memory mutation so readers don't diverge from disk.
		h.cfg.Policy.Allow = prevAllow
		h.cfg.Policy.Deny = prevDeny
		h.policy = usblister.NewPolicyDecider(&h.cfg.Policy)
		h.mu.Unlock()
		log.Error().Err(saveErr).Msg("usbip: failed to persist policy update")
		writeError(w, http.StatusInternalServerError, "failed to persist policy: "+saveErr.Error())
		return
	}
	h.mu.Unlock()

	log.Info().
		Int("allow", len(h.cfg.Policy.Allow)).
		Int("deny", len(h.cfg.Policy.Deny)).
		Str("remote", r.RemoteAddr).
		Msg("usbip policy updated")

	// Re-enforce the new policy against bus IDs already exported: if the
	// operator just removed a rule, any device currently shared under it
	// must be unbound immediately — otherwise remote clients could still
	// attach to a device that is no longer in the allow list.
	// Runs in a goroutine so the HTTP response isn't blocked on `usbip unbind`.
	go func() {
		revoked, errs := h.ReenforcePolicy()
		if len(revoked) > 0 {
			log.Info().Strs("busIds", revoked).Msg("usbip: revoked exports after policy update")
		}
		for _, err := range errs {
			log.Warn().Err(err).Msg("usbip: policy re-enforcement error")
		}
	}()

	writeJSON(w, http.StatusOK, h.currentPolicyResponse())
}

// Attach handles POST /api/usbip/attach — semantic alias for Export.
// Used by the new UX in rud1-app / rud1-es Connect tab.
func (h *USBIPHandler) Attach(w http.ResponseWriter, r *http.Request) {
	h.Export(w, r)
}

// Detach handles DELETE /api/usbip/attach — semantic alias for Unexport.
func (h *USBIPHandler) Detach(w http.ResponseWriter, r *http.Request) {
	h.Unexport(w, r)
}

// ReenforcePolicy iterates the currently-exported bus IDs and unexports any
// device whose vendor/product (or serial) is no longer permitted by the
// active policy. It is also used to reap phantom exports for devices that
// have been physically unplugged.
//
// Returns (revoked, errs):
//   - revoked: bus IDs that were unbound by this sweep (denied by policy or
//     device missing from the USB tree).
//   - errs: per-device errors encountered while looking up / unbinding. The
//     sweep continues after each error so one stuck device does not block
//     policy enforcement on the rest.
//
// Called by SetPolicy (so an `allow` deletion immediately revokes any
// currently-shared device that no longer matches) and by the agent's
// periodic sweep loop (so remote detaches that race with a policy edit
// can't leave the device bound under a now-stale rule).
func (h *USBIPHandler) ReenforcePolicy() (revoked []string, errs []error) {
	h.mu.RLock()
	policy := h.policy
	h.mu.RUnlock()

	exported := h.server.ExportedDevices()
	for _, busID := range exported {
		dev, err := usblister.FindByBusID(busID)
		if err != nil {
			if errors.Is(err, usblister.ErrDeviceNotFound) {
				// Device was physically removed while still bound —
				// drop the export so the in-memory set matches reality.
				if unexErr := h.server.Unexport(busID); unexErr != nil {
					errs = append(errs, fmt.Errorf("unexport missing %s: %w", busID, unexErr))
					continue
				}
				revoked = append(revoked, busID)
				h.recordRevocation(RevocationEntry{
					BusID:  busID,
					Reason: RevocationReasonUnplugged,
					At:     time.Now().Unix(),
				})
				continue
			}
			errs = append(errs, fmt.Errorf("lookup %s: %w", busID, err))
			continue
		}
		if checkErr := policy.Check(dev); checkErr != nil {
			if unexErr := h.server.Unexport(busID); unexErr != nil {
				errs = append(errs, fmt.Errorf("unexport %s: %w", busID, unexErr))
				continue
			}
			revoked = append(revoked, busID)
			h.recordRevocation(RevocationEntry{
				BusID:       busID,
				VendorID:    dev.VendorID,
				ProductID:   dev.ProductID,
				Serial:      dev.Serial,
				VendorName:  dev.VendorName,
				ProductName: dev.ProductName,
				Reason:      RevocationReasonPolicy,
				At:          time.Now().Unix(),
			})
		}
	}
	return revoked, errs
}

// recordRevocation appends an entry to the in-memory ring buffer. Once
// the buffer is full, new entries overwrite the oldest slot; callers see
// a chronologically-sorted slice via Revocations().
func (h *USBIPHandler) recordRevocation(e RevocationEntry) {
	h.revMu.Lock()
	defer h.revMu.Unlock()
	if len(h.revLog) < revocationLogSize {
		h.revLog = append(h.revLog, e)
		return
	}
	h.revLog[h.revPos] = e
	h.revPos = (h.revPos + 1) % revocationLogSize
}

// Revocations returns the log entries in chronological order (oldest
// first). The returned slice is a copy — callers may mutate it freely.
func (h *USBIPHandler) Revocations() []RevocationEntry {
	h.revMu.Lock()
	defer h.revMu.Unlock()
	if len(h.revLog) < revocationLogSize {
		out := make([]RevocationEntry, len(h.revLog))
		copy(out, h.revLog)
		return out
	}
	out := make([]RevocationEntry, 0, revocationLogSize)
	out = append(out, h.revLog[h.revPos:]...)
	out = append(out, h.revLog[:h.revPos]...)
	return out
}

// RevocationsList handles GET /api/usbip/revocations — returns the last N
// bus IDs that ReenforcePolicy unbound, with timestamp and reason. The
// optional `since` query param (unix seconds) filters to entries strictly
// after that timestamp so rud1-app can poll without surfacing duplicate
// toasts.
func (h *USBIPHandler) RevocationsList(w http.ResponseWriter, r *http.Request) {
	if !h.isAuthorized(r) {
		writeError(w, http.StatusForbidden, "client IP not in authorized_nets")
		return
	}
	var since int64
	if raw := r.URL.Query().Get("since"); raw != "" {
		v, err := strconv.ParseInt(raw, 10, 64)
		if err != nil {
			writeError(w, http.StatusBadRequest, "since must be a unix-seconds integer")
			return
		}
		since = v
	}
	// limit: optional, 1..100. When omitted we return the full buffer so
	// pre-existing callers that poll for a full snapshot keep working.
	var limit int
	if raw := r.URL.Query().Get("limit"); raw != "" {
		v, err := strconv.Atoi(raw)
		if err != nil || v < 1 || v > 100 {
			writeError(w, http.StatusBadRequest, "limit must be an integer in [1,100]")
			return
		}
		limit = v
	}
	entries := h.Revocations()
	if since > 0 {
		filtered := make([]RevocationEntry, 0, len(entries))
		for _, e := range entries {
			if e.At > since {
				filtered = append(filtered, e)
			}
		}
		entries = filtered
	}
	// Apply limit AFTER `since`: keep the N newest entries (the buffer is
	// already chronological, so that's the tail).
	if limit > 0 && len(entries) > limit {
		entries = entries[len(entries)-limit:]
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"revocations": entries,
		"now":         time.Now().Unix(),
	})
}
