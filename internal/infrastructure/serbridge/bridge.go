// Package serbridge implements a TCP↔serial proxy for CDC-class USB
// devices (Arduinos, ESP32 dev boards, USB-serial dongles).
//
// Why this exists alongside USB/IP: the kernel `usbip_host` module
// crashes in `stub_rx_loop` when a CDC interface re-enumerates while
// URBs are in flight. avrdude triggers exactly that — it toggles DTR
// to reset the Arduino, the ATmega16U2 reinitialises its CDC interface,
// the in-flight URBs become invalid, the client's UNLINK PDU hits a
// freed URB on the Pi, kernel oops, stub dies, client sees "cannot set
// com-state". The bridge sidesteps the kernel module entirely:
// /dev/ttyACMx stays bound to cdc_acm on the Pi, we read/write bytes
// in userspace, and DTR/RTS toggles travel as RFC 2217 control packets
// over the same TCP stream.
//
// Trade-off: bridge mode loses the USB descriptors that some clients
// (Arduino IDE auto-detect) rely on — the user sees "COM port" instead
// of "Arduino Uno on USB". But the user controls the board selection
// manually anyway, and the upload protocol (STK500) only needs a serial
// stream, so the trade is favourable for the use case.
package serbridge

import (
	"errors"
	"fmt"
	"strconv"
	"sync"
	"time"
)

// SessionState tracks the lifecycle of a single open bridge session.
//
// A session starts in StateOpening (listener allocated, /dev/ttyACMx
// not yet opened — the kernel might still have ModemManager probing
// it), transitions to StateOpen once the serial port is exclusively
// held and we're forwarding bytes, and ends in StateClosed when either
// side disconnects or the operator calls Close. StateError is reserved
// for unrecoverable failures (device unplugged, port already in use)
// that make retrying the same session pointless — the caller should
// allocate a fresh session.
type SessionState string

const (
	StateOpening SessionState = "opening"
	StateOpen    SessionState = "open"
	StateClosed  SessionState = "closed"
	StateError   SessionState = "error"
)

// Session is the public view of one bridge — what the HTTP API
// surfaces back to the client and what shows up in the heartbeat.
//
// TCPPort is the listener port the desktop client should connect to.
// DevicePath is informational ("/dev/ttyACM0") and may shift across
// re-plug events; clients should treat BusID as the stable identity.
type Session struct {
	BusID      string       `json:"busId"`
	DevicePath string       `json:"devicePath"`
	TCPPort    int          `json:"tcpPort"`
	State      SessionState `json:"state"`
	OpenedAt   int64        `json:"openedAt"`           // unix seconds
	ClosedAt   int64        `json:"closedAt,omitempty"` // unix seconds
	Error      string       `json:"error,omitempty"`
	// Connected reports whether a TCP client is currently attached.
	// A session can be StateOpen with Connected=false during the gap
	// between Open() returning and the client actually connecting,
	// or after a client disconnects but before Close() is called.
	Connected bool `json:"connected"`
	// Last-applied serial line settings, surfaced for diagnostics so
	// the operator can see what RFC 2217 the client negotiated. Zero
	// values mean "not yet set / using kernel defaults".
	BaudRate int    `json:"baudRate,omitempty"`
	DataBits int    `json:"dataBits,omitempty"`
	Parity   string `json:"parity,omitempty"`
	StopBits string `json:"stopBits,omitempty"`
}

// Manager is the implementation surface — Linux gets the real proxy,
// other platforms get a stub. The agent depends on this interface so
// build tags don't need to bleed into the HTTP handlers.
type Manager interface {
	// Start brings up the manager. On Linux this is a no-op (each session
	// owns its own listener); the method exists for symmetry with
	// USBIPServer's lifecycle so the bootstrapper can call Start/Stop
	// without branching on type.
	Start() error
	// Stop closes every open session and refuses new opens. Idempotent.
	Stop()
	// Open allocates a session for the given bus id, opens the
	// corresponding /dev/ttyACMx, and starts the TCP listener. Returns
	// the populated Session (including TCPPort) so the caller can
	// hand it to the HTTP response. Errors when:
	//   - the device path can't be resolved from the bus id
	//   - the device is already exported as a session
	//   - all session slots (config.MaxSessions) are taken
	//   - the serial port is held by another process (ModemManager,
	//     a stale handle, etc.)
	Open(busID string) (*Session, error)
	// Close tears down the session for a bus id. Idempotent: closing a
	// non-existent or already-closed session is not an error.
	Close(busID string) error
	// Sessions returns a snapshot of every session known to the
	// manager — open, closed, or errored. Heartbeat reporting uses
	// this; the closed/errored entries roll off after ~5 minutes via
	// an internal sweep.
	Sessions() []Session
	// SessionFor returns the live session for a bus id, or nil. The
	// HTTP handler uses this to project a single bus id without
	// snapshotting the full list.
	SessionFor(busID string) *Session
	// OpenBusIDs returns just the bus IDs of currently-open sessions.
	// Used by the heartbeat builder so the cloud knows which devices
	// are bridge-mode active without serializing the full Session.
	OpenBusIDs() []string
	// Reset pulses DTR low for `pulseMs` milliseconds on the open
	// session for busID, then re-asserts DTR. Used by the HTTP reset
	// endpoint as a manual fallback for clients that don't synthesize
	// DTR via RFC 2217 (raw-TCP scopes, com0com pairs that don't
	// surface modem-control IOCTLs cleanly across the pair). Returns
	// ErrSessionNotFound when busID has no live session — callers
	// should Open() first. pulseMs <= 0 means "use the default
	// optiboot reset width" (50 ms).
	Reset(busID string, pulseMs int) error
}

// Errors surfaced from the public API. The HTTP handler maps each to
// a specific status code; tests assert on the sentinel values rather
// than message substrings.
var (
	ErrDisabled        = errors.New("serial bridge disabled in config")
	ErrAlreadyOpen     = errors.New("bridge already open for bus id")
	ErrNoFreeSlots     = errors.New("no free bridge sessions (MaxSessions reached)")
	ErrDeviceNotFound  = errors.New("no /dev/ttyACMx mapping for bus id")
	ErrDeviceBusy      = errors.New("serial device held by another process")
	ErrSessionNotFound = errors.New("no bridge session for bus id")
)

// FormatSerialSettings is a small display helper used by the HTTP and
// heartbeat layers so a "115200 8N1" chip can be rendered without each
// caller re-implementing the formatting. Empty / zero fields are
// silently skipped, so a session that only has BaudRate set surfaces
// as "115200" rather than "115200 0?0".
func FormatSerialSettings(baud, dataBits int, parity, stopBits string) string {
	parts := make([]string, 0, 2)
	if baud > 0 {
		parts = append(parts, strconv.Itoa(baud))
	}
	frame := ""
	if dataBits > 0 {
		frame = strconv.Itoa(dataBits)
	}
	if parity != "" {
		frame += parity
	}
	if stopBits != "" {
		frame += stopBits
	}
	if frame != "" {
		parts = append(parts, frame)
	}
	if len(parts) == 0 {
		return ""
	}
	return parts[0] + appendSep(parts[1:])
}

func appendSep(rest []string) string {
	if len(rest) == 0 {
		return ""
	}
	out := ""
	for _, p := range rest {
		out += " " + p
	}
	return out
}

// PortAllocator hands out TCP port numbers within the configured range,
// reusing freed slots so a long-running Pi doesn't drift its ports
// monotonically upward across thousands of open/close cycles. Exposed
// for the platform-specific manager to embed.
type PortAllocator struct {
	mu       sync.Mutex
	base     int
	max      int
	inUse    map[int]bool
	released []int
}

// NewPortAllocator initialises an allocator over [base, base+max).
// max <= 0 is rejected as invalid; the agent's bootstrap fast-fails
// rather than starting a manager that immediately rejects every Open.
func NewPortAllocator(base, max int) (*PortAllocator, error) {
	if base <= 0 || base+max > 65535 {
		return nil, fmt.Errorf("invalid port range %d..%d", base, base+max)
	}
	if max <= 0 {
		return nil, fmt.Errorf("max sessions must be > 0, got %d", max)
	}
	return &PortAllocator{
		base:  base,
		max:   max,
		inUse: make(map[int]bool, max),
	}, nil
}

// Allocate returns the next free port. Prefers released ports (LIFO)
// over fresh ones so the port set stays compact and predictable for
// firewall debugging. Returns ErrNoFreeSlots when the range is full.
func (a *PortAllocator) Allocate() (int, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if n := len(a.released); n > 0 {
		port := a.released[n-1]
		a.released = a.released[:n-1]
		a.inUse[port] = true
		return port, nil
	}
	for i := 0; i < a.max; i++ {
		p := a.base + i
		if !a.inUse[p] {
			a.inUse[p] = true
			return p, nil
		}
	}
	return 0, ErrNoFreeSlots
}

// Release marks a port available for reuse. No-op for ports outside
// the managed range — defensive against races where Close runs after
// the manager was reconfigured to a smaller range.
func (a *PortAllocator) Release(port int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if port < a.base || port >= a.base+a.max {
		return
	}
	if !a.inUse[port] {
		return
	}
	delete(a.inUse, port)
	a.released = append(a.released, port)
}

// InUse returns the count of currently-allocated ports. Used by the
// heartbeat to surface "3 of 8 bridge sessions used" load chips.
func (a *PortAllocator) InUse() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.inUse)
}

// Now is overridable for tests so the unix-second OpenedAt/ClosedAt
// stamps can be pinned without time.Now() jitter.
var Now = func() int64 { return time.Now().Unix() }
