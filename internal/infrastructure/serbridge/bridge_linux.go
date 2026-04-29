//go:build linux

package serbridge

import (
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/rs/zerolog/log"
)

// LinuxManager is the production implementation of the serial bridge.
//
// Layout: one TCP listener per session. The listener accepts at most one
// concurrent client (the panel's TCP-to-COM bridge in the desktop app);
// a second connection arriving while the first is live gets the EOF
// treatment so a stale handle on the operator's machine can't shadow
// the real session. We could allow multi-client read-only mirroring for
// debug-watch scenarios, but that's a future iteration — the MVP only
// supports one writer + one reader on the same wire.
//
// Concurrency: each session owns its own goroutine pair (TCP→serial,
// serial→TCP) plus a control goroutine that runs the RFC 2217 negotiator.
// The manager-level mutex guards the sessions map and is never held
// during I/O — the per-session struct has its own state mutex for the
// rare case where Open/Close races with the connection accept loop.
type LinuxManager struct {
	mu        sync.Mutex
	sessions  map[string]*linuxSession
	allocator *PortAllocator
	stopped   bool

	// resolveDevice maps bus id → /dev/ttyACMx path. Overridable for
	// tests so we can pin a fixture path without poking at /sys.
	resolveDevice func(busID string) (string, error)
}

// linuxSession is the manager's private view of a session. Public API
// callers see Session (the JSON-shaped projection); the difference is
// that linuxSession also holds the TCP listener, the file descriptor
// for the serial port, the cancellation channel, and the per-session
// mutex protecting state mutations.
type linuxSession struct {
	mu sync.Mutex

	pub      Session
	listener net.Listener
	serialFD *os.File
	stopCh   chan struct{}
	doneCh   chan struct{}
}

// NewLinuxManager wires up an allocator and an empty sessions map. The
// real listeners only come up on demand in Open() — there's no daemon
// goroutine here, so a never-used manager is essentially free.
func NewLinuxManager(basePort, maxSessions int) (*LinuxManager, error) {
	alloc, err := NewPortAllocator(basePort, maxSessions)
	if err != nil {
		return nil, err
	}
	return &LinuxManager{
		sessions:      make(map[string]*linuxSession),
		allocator:     alloc,
		resolveDevice: resolveDeviceFromBusID,
	}, nil
}

// Start is a no-op on Linux. Sessions allocate their own listeners
// lazily — there's no shared daemon process to spin up. The method
// satisfies the Manager interface so the bootstrap can call Start/Stop
// symmetrically with USBIPServer.
func (m *LinuxManager) Start() error { return nil }

// Stop closes every open session and refuses further opens. Calls to
// Open after Stop fail with ErrDisabled (the same code path config
// disabled emits) so callers don't have to special-case "shutting down".
func (m *LinuxManager) Stop() {
	m.mu.Lock()
	if m.stopped {
		m.mu.Unlock()
		return
	}
	m.stopped = true
	// Snapshot to avoid holding the lock during Close — closeSession
	// reacquires it.
	keys := make([]string, 0, len(m.sessions))
	for k := range m.sessions {
		keys = append(keys, k)
	}
	m.mu.Unlock()
	for _, k := range keys {
		_ = m.Close(k)
	}
}

// Open allocates a session, opens the serial device, binds a TCP
// listener, and spawns the I/O goroutines.
func (m *LinuxManager) Open(busID string) (*Session, error) {
	if busID == "" {
		return nil, fmt.Errorf("empty bus id")
	}

	m.mu.Lock()
	if m.stopped {
		m.mu.Unlock()
		return nil, ErrDisabled
	}
	if existing := m.sessions[busID]; existing != nil {
		// Idempotent: a second open on a bus id that's already alive
		// returns the existing session rather than failing. Matches
		// USBIPServer.Export semantics so the desktop's bindOnPi
		// precall doesn't surprise the user with a 409 after a panel
		// reload.
		existing.mu.Lock()
		if existing.pub.State == StateOpen || existing.pub.State == StateOpening {
			snap := existing.pub
			existing.mu.Unlock()
			m.mu.Unlock()
			return &snap, nil
		}
		// Existing session is closed/errored — let it be replaced.
		delete(m.sessions, busID)
		existing.mu.Unlock()
	}
	port, err := m.allocator.Allocate()
	if err != nil {
		m.mu.Unlock()
		return nil, err
	}

	devicePath, derr := m.resolveDevice(busID)
	if derr != nil {
		m.allocator.Release(port)
		m.mu.Unlock()
		return nil, fmt.Errorf("%w: %v", ErrDeviceNotFound, derr)
	}

	// Open the serial device with O_NONBLOCK to avoid hanging in case
	// the device disappears mid-open. We immediately drop the flag
	// after a successful open via fcntl so the I/O goroutines can use
	// blocking reads/writes — non-blocking would tight-loop.
	fd, oerr := os.OpenFile(devicePath, os.O_RDWR|syscall.O_NOCTTY|syscall.O_NONBLOCK, 0)
	if oerr != nil {
		m.allocator.Release(port)
		m.mu.Unlock()
		if isBusyErr(oerr) {
			return nil, fmt.Errorf("%w: %v", ErrDeviceBusy, oerr)
		}
		return nil, fmt.Errorf("open %s: %w", devicePath, oerr)
	}
	if err := setBlocking(fd); err != nil {
		_ = fd.Close()
		m.allocator.Release(port)
		m.mu.Unlock()
		return nil, fmt.Errorf("clear NONBLOCK on %s: %w", devicePath, err)
	}
	// Apply sane defaults so a client connecting before any RFC 2217
	// negotiation still gets a usable terminal. 8N1 is the universal
	// default for Arduinos; baud will be overridden by SET_BAUDRATE
	// on the first IAC SE the client sends.
	if err := configureTermios(fd, 115200, 8, "N", "1"); err != nil {
		_ = fd.Close()
		m.allocator.Release(port)
		m.mu.Unlock()
		return nil, fmt.Errorf("configure %s: %w", devicePath, err)
	}

	// Bind the TCP listener on every interface on the chosen port.
	// Source-IP allowlisting is enforced at accept-time by the HTTP
	// layer (it passes a func to the handler). Doing it on the listener
	// would require a custom dialer, and the firewall on the WG
	// interface already filters before TCP reaches us.
	ln, lerr := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if lerr != nil {
		_ = fd.Close()
		m.allocator.Release(port)
		m.mu.Unlock()
		return nil, fmt.Errorf("listen :%d: %w", port, lerr)
	}

	sess := &linuxSession{
		pub: Session{
			BusID:      busID,
			DevicePath: devicePath,
			TCPPort:    port,
			State:      StateOpening,
			OpenedAt:   Now(),
			BaudRate:   115200,
			DataBits:   8,
			Parity:     "N",
			StopBits:   "1",
		},
		listener: ln,
		serialFD: fd,
		stopCh:   make(chan struct{}),
		doneCh:   make(chan struct{}),
	}
	m.sessions[busID] = sess
	m.mu.Unlock()

	go m.acceptLoop(sess)

	sess.mu.Lock()
	sess.pub.State = StateOpen
	snap := sess.pub
	sess.mu.Unlock()
	log.Info().
		Str("busId", busID).
		Str("devicePath", devicePath).
		Int("tcpPort", port).
		Msg("serial bridge session opened")
	return &snap, nil
}

// Close tears down a session.
func (m *LinuxManager) Close(busID string) error {
	m.mu.Lock()
	sess, ok := m.sessions[busID]
	if !ok {
		m.mu.Unlock()
		return nil // idempotent — no error
	}
	delete(m.sessions, busID)
	port := sess.pub.TCPPort
	m.mu.Unlock()

	// Signal the accept loop and any in-flight connection to wind down.
	sess.mu.Lock()
	if sess.pub.State == StateClosed {
		sess.mu.Unlock()
		return nil
	}
	sess.pub.State = StateClosed
	sess.pub.ClosedAt = Now()
	close(sess.stopCh)
	if sess.listener != nil {
		_ = sess.listener.Close()
	}
	if sess.serialFD != nil {
		_ = sess.serialFD.Close()
	}
	sess.mu.Unlock()
	// Wait for the goroutines to exit so no late writes hit the closed
	// fd. 2s is generous — the loops respect stopCh on every iteration.
	select {
	case <-sess.doneCh:
	case <-time.After(2 * time.Second):
		log.Warn().Str("busId", busID).Msg("serial bridge close timed out waiting for I/O loops")
	}
	m.allocator.Release(port)
	log.Info().Str("busId", busID).Msg("serial bridge session closed")
	return nil
}

// Sessions returns a snapshot of every known session. Sorted by bus id
// for stable rendering in the panel and predictable test assertions.
func (m *LinuxManager) Sessions() []Session {
	m.mu.Lock()
	out := make([]Session, 0, len(m.sessions))
	for _, s := range m.sessions {
		s.mu.Lock()
		out = append(out, s.pub)
		s.mu.Unlock()
	}
	m.mu.Unlock()
	sort.Slice(out, func(i, j int) bool { return out[i].BusID < out[j].BusID })
	return out
}

// SessionFor returns the live session for a bus id, or nil if the bus
// id has no session (closed or never opened).
func (m *LinuxManager) SessionFor(busID string) *Session {
	m.mu.Lock()
	sess, ok := m.sessions[busID]
	m.mu.Unlock()
	if !ok {
		return nil
	}
	sess.mu.Lock()
	defer sess.mu.Unlock()
	snap := sess.pub
	return &snap
}

// Reset pulses DTR low on the live session's serial fd. The session
// must already be open — we don't allocate a transient fd here because
// that would race with `usbip-host` rebind logic and surprise an open
// TCP client. Callers should Open() before calling Reset().
//
// Concurrency: we hold the session mutex during the pulse so an in-flight
// RFC 2217 SET-CONTROL from a TCP client doesn't race the manual
// toggle. The pulse is short (50 ms by default), so blocking the IAC
// parser briefly is acceptable.
func (m *LinuxManager) Reset(busID string, pulseMs int) error {
	m.mu.Lock()
	sess, ok := m.sessions[busID]
	m.mu.Unlock()
	if !ok {
		return ErrSessionNotFound
	}
	sess.mu.Lock()
	defer sess.mu.Unlock()
	if sess.pub.State != StateOpen && sess.pub.State != StateOpening {
		return ErrSessionNotFound
	}
	if sess.serialFD == nil {
		return ErrSessionNotFound
	}
	if pulseMs <= 0 {
		pulseMs = 50
	}
	if err := pulseDTR(sess.serialFD, pulseMs); err != nil {
		log.Warn().Err(err).Str("busId", busID).Int("pulseMs", pulseMs).Msg("serial bridge: DTR pulse failed")
		return fmt.Errorf("pulse DTR: %w", err)
	}
	log.Info().Str("busId", busID).Int("pulseMs", pulseMs).Msg("serial bridge: DTR pulsed (manual reset)")
	return nil
}

// OpenBusIDs returns the bus ids of currently-open sessions. Used by
// the heartbeat builder.
func (m *LinuxManager) OpenBusIDs() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]string, 0, len(m.sessions))
	for k, s := range m.sessions {
		s.mu.Lock()
		state := s.pub.State
		s.mu.Unlock()
		if state == StateOpen || state == StateOpening {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

// acceptLoop accepts at most one TCP connection at a time. While a
// client is connected we don't accept a second one — a stale handle
// on the operator's machine could otherwise shadow the real session.
// On client disconnect we go back to accepting, so a panel reload
// reconnects cleanly.
func (m *LinuxManager) acceptLoop(sess *linuxSession) {
	defer close(sess.doneCh)
	for {
		select {
		case <-sess.stopCh:
			return
		default:
		}
		conn, err := sess.listener.Accept()
		if err != nil {
			select {
			case <-sess.stopCh:
				return
			default:
			}
			// Transient accept errors (interrupted syscalls etc.) — loop
			// after a short backoff so a flaky kernel doesn't busy-loop
			// us. A permanent failure (listener closed) hits the stopCh
			// branch above and exits.
			time.Sleep(50 * time.Millisecond)
			continue
		}
		m.handleConn(sess, conn)
		// Mark disconnected; loop and accept the next client.
		sess.mu.Lock()
		sess.pub.Connected = false
		sess.mu.Unlock()
	}
}

// handleConn runs the bidirectional pump for one TCP client. Returns
// when either side EOFs or stopCh fires. Owns the goroutine for the
// duration; spawns one helper for serial→TCP so the IAC parser can
// own the TCP→serial direction.
func (m *LinuxManager) handleConn(sess *linuxSession, conn net.Conn) {
	defer conn.Close()
	sess.mu.Lock()
	sess.pub.Connected = true
	sess.mu.Unlock()

	log.Debug().Str("busId", sess.pub.BusID).Str("remote", conn.RemoteAddr().String()).Msg("serial bridge client connected")

	pumpDone := make(chan struct{})
	// serial → TCP: blind copy. Close the connection on EOF so the
	// TCP → serial side notices and unwinds.
	go func() {
		defer close(pumpDone)
		_, _ = io.Copy(conn, sess.serialFD)
	}()

	// TCP → serial: an IAC parser. We only handle a tiny subset of
	// RFC 2217 (the COM-PORT-OPTION subnegotiations avrdude actually
	// uses); everything else passes through verbatim. The parser is
	// stateful but small — see processIAC for the state machine.
	parser := newIACParser(sess)
	buf := make([]byte, 4096)
	for {
		select {
		case <-sess.stopCh:
			return
		default:
		}
		n, err := conn.Read(buf)
		if n > 0 {
			out, send2217 := parser.Feed(buf[:n])
			if len(out) > 0 {
				if _, werr := sess.serialFD.Write(out); werr != nil {
					log.Warn().Err(werr).Str("busId", sess.pub.BusID).Msg("serial bridge write failed")
					return
				}
			}
			if len(send2217) > 0 {
				if _, werr := conn.Write(send2217); werr != nil {
					log.Warn().Err(werr).Str("busId", sess.pub.BusID).Msg("serial bridge IAC reply failed")
					return
				}
			}
		}
		if err != nil {
			if err != io.EOF {
				log.Debug().Err(err).Str("busId", sess.pub.BusID).Msg("serial bridge client read ended")
			}
			return
		}
	}
}

// resolveDeviceFromBusID maps a USB bus id (e.g. "1-1.3") to the
// /dev/ttyACMx the kernel allocated for its CDC interface. We walk the
// sysfs tree under /sys/bus/usb/devices/<busid>:1.0/tty/ — the cdc_acm
// driver always creates a `tty` directory there listing its allocated
// minor names.
func resolveDeviceFromBusID(busID string) (string, error) {
	if busID == "" {
		return "", fmt.Errorf("empty bus id")
	}
	// Common precondition for both the auto-mode happy path AND
	// "user clicked share via USB/IP earlier in this session": if any
	// interface of the device is currently bound to `usbip-host`,
	// cdc_acm doesn't own it and there's no /dev/ttyACMx for us to
	// open. Release back to the native driver before scanning sysfs
	// for the tty. Idempotent and silent when nothing was bound.
	if err := releaseFromUSBIPHost(busID); err != nil {
		return "", fmt.Errorf("release %s from usbip-host: %w", busID, err)
	}

	if path, ok := scanTTY(busID); ok {
		return path, nil
	}

	// cdc_acm's re-probe after the unbind isn't synchronous — the
	// kernel queues the rebind and processes it in a workqueue. Give
	// it up to ~2s before bailing.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
		if path, ok := scanTTY(busID); ok {
			return path, nil
		}
	}
	return "", fmt.Errorf("no /dev/ttyACMx for bus id %s after waiting for cdc_acm rebind", busID)
}

// scanTTY walks the device's interfaces under /sys/bus/usb/devices
// looking for a `tty/<name>` entry — the marker cdc_acm leaves when
// it claims a CDC interface. We try interface .0 first (the most
// common layout) and fall back to .1, .2, .3 for composite devices
// that put a vendor-specific interface in slot 0 (Arduino Leonardo
// with HID at .0 and CDC at .1, etc.).
func scanTTY(busID string) (string, bool) {
	for i := 0; i <= 3; i++ {
		dir := filepath.Join("/sys/bus/usb/devices", fmt.Sprintf("%s:1.%d", busID, i), "tty")
		entries, err := os.ReadDir(dir)
		if err == nil && len(entries) > 0 {
			return "/dev/" + entries[0].Name(), true
		}
	}
	return "", false
}

// releaseFromUSBIPHost unbinds the device from the `usbip-host` stub
// driver if any of its interfaces are currently held there. After the
// unbind the kernel re-probes and cdc_acm picks up the CDC interface,
// re-creating /dev/ttyACMx within ~tens of milliseconds.
//
// Why this matters: the agent's USB/IP code path (`usbipServer.Export`)
// shells out to `usbip bind` which moves the device from cdc_acm to
// usbip-host. If the operator switches to bridge mode AFTER having
// USB/IP-shared the same device, cdc_acm has nothing to open. Worse,
// the original kernel oops in `stub_rx_loop` we've been chasing
// leaves the usbip-host module in a tainted state where the device
// stays "bound" but unusable. Unbinding clears the kernel's view
// (and the `usbipServer.exported` map self-corrects via its
// `isAlreadyBound` reconciliation pattern).
//
// We try the userspace `usbip unbind` first because it goes through
// the project's own state machine; on failure (binary missing, kernel
// module wedged) we fall back to writing the bus id directly to
// `/sys/bus/usb/drivers/usbip-host/unbind`, which the kernel honours
// regardless of the userspace tool's health.
func releaseFromUSBIPHost(busID string) error {
	if !boundToUSBIPHost(busID) {
		return nil
	}
	log.Info().Str("busId", busID).Msg("serial bridge: releasing device from usbip-host before opening")

	// Userspace path first.
	if err := exec.Command("usbip", "unbind", "-b", busID).Run(); err == nil {
		return nil
	}

	// Sysfs fallback. The kernel exposes
	//   /sys/bus/usb/drivers/usbip-host/unbind
	// as a writable attribute that takes the interface name (e.g.
	// "1-1.3:1.0"). This is the same syscall the userspace tool ends
	// up making, just without the wrapping.
	for i := 0; i <= 3; i++ {
		iface := fmt.Sprintf("%s:1.%d", busID, i)
		if !ifaceBoundToUSBIPHost(iface) {
			continue
		}
		if err := os.WriteFile("/sys/bus/usb/drivers/usbip-host/unbind", []byte(iface), 0); err != nil {
			return fmt.Errorf("write usbip-host/unbind: %w", err)
		}
	}
	return nil
}

// boundToUSBIPHost reports whether ANY interface of the bus id is
// currently bound to usbip-host. Cheap sysfs walk; the agent calls
// this at most once per Open().
func boundToUSBIPHost(busID string) bool {
	for i := 0; i <= 3; i++ {
		if ifaceBoundToUSBIPHost(fmt.Sprintf("%s:1.%d", busID, i)) {
			return true
		}
	}
	return false
}

func ifaceBoundToUSBIPHost(iface string) bool {
	link := filepath.Join("/sys/bus/usb/devices", iface, "driver")
	target, err := os.Readlink(link)
	if err != nil {
		return false
	}
	return filepath.Base(target) == "usbip-host"
}

// isBusyErr identifies the kernel's "device or resource busy" surface
// across the few wordings it ships in. We look for both the errno path
// (EBUSY) and the string substring because os.OpenFile sometimes wraps
// it differently depending on syscall layer version.
func isBusyErr(err error) bool {
	if err == nil {
		return false
	}
	var pe *os.PathError
	if isPathErr(err, &pe) && pe.Err == syscall.EBUSY {
		return true
	}
	return strings.Contains(strings.ToLower(err.Error()), "busy")
}

func isPathErr(err error, target **os.PathError) bool {
	pe, ok := err.(*os.PathError)
	if !ok {
		return false
	}
	*target = pe
	return true
}
