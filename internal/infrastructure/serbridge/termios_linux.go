//go:build linux

package serbridge

import (
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

// configureTermios applies baud rate + data/parity/stop framing to an
// already-open serial fd. We bypass golang.org/x/sys/unix to keep the
// firmware build dependency-free (the project pins to stdlib + chi +
// zerolog + yaml; x/sys would be the first cross-platform fragment).
//
// Implementation note: Linux's `struct termios` carries the speed in
// the c_cflag field (CBAUD bits) for "non-extended" speeds AND in
// dedicated c_ispeed/c_ospeed slots for arbitrary speeds (BOTHER).
// We use BOTHER unconditionally — Arduino's 115200 still works under
// BOTHER, and unusual speeds (Arduino UNO bootloader actually runs at
// 115200 but some fancier programmers want 230400 / 250000) need it.
// That's why we reach for ioctl(TCSETS2) instead of plain TCSETS.
func configureTermios(fd *os.File, baud, dataBits int, parity, stopBits string) error {
	t, err := getTermios2(fd)
	if err != nil {
		return fmt.Errorf("get termios: %w", err)
	}

	// Strip CSIZE bits, set the requested data size.
	t.c_cflag &^= csize
	switch dataBits {
	case 5:
		t.c_cflag |= cs5
	case 6:
		t.c_cflag |= cs6
	case 7:
		t.c_cflag |= cs7
	case 8, 0:
		t.c_cflag |= cs8
	default:
		return fmt.Errorf("invalid data bits %d", dataBits)
	}

	// Parity flags.
	t.c_cflag &^= parenb | parodd
	switch parity {
	case "N", "n", "":
		// no parity
	case "E", "e":
		t.c_cflag |= parenb
	case "O", "o":
		t.c_cflag |= parenb | parodd
	default:
		return fmt.Errorf("invalid parity %q", parity)
	}

	// Stop bits. Linux only supports 1 or 2 (no 1.5).
	t.c_cflag &^= cstopb
	switch stopBits {
	case "1", "":
		// 1 stop bit
	case "2":
		t.c_cflag |= cstopb
	default:
		return fmt.Errorf("invalid stop bits %q", stopBits)
	}

	// Enable receiver, ignore modem control lines (CLOCAL). Without
	// CLOCAL the open() can block waiting for DCD on devices that
	// actually pull it; for CDC-ACM the kernel already pretends DCD,
	// but flipping CLOCAL makes us robust to other USB-serial chips.
	t.c_cflag |= cread | clocal

	// Raw mode: no canonical processing, no echo, no signal generation,
	// no input/output translations. avrdude wants every byte verbatim.
	t.c_lflag &^= icanon | echo | echoe | echok | echonl | isig | iexten
	t.c_iflag &^= brkint | icrnl | inpck | istrip | ixon | ixoff | ixany | inlcr | igncr | iuclc | imaxbel
	t.c_oflag &^= opost | onlcr

	// Inter-character timeout (VTIME) and minimum bytes (VMIN). VMIN=1,
	// VTIME=0 means "block until at least one byte is available", which
	// is what the io.Copy pump wants — the goroutine is dedicated to
	// this fd so blocking is fine and we get to surface kernel errors
	// promptly.
	t.c_cc[cc_vmin] = 1
	t.c_cc[cc_vtime] = 0

	// Speeds: BOTHER on c_cflag tells the kernel to use ispeed/ospeed.
	t.c_cflag &^= cbaud
	t.c_cflag |= bother
	t.c_ispeed = uint32(baud)
	t.c_ospeed = uint32(baud)

	if err := setTermios2(fd, t); err != nil {
		return fmt.Errorf("set termios: %w", err)
	}
	return nil
}

// setBlocking clears the O_NONBLOCK flag we set during open(). Must
// run AFTER the open succeeds — we kept the flag during open to dodge
// the "open hangs forever waiting for DCD" case on non-CLOCAL devices.
func setBlocking(fd *os.File) error {
	flags, _, errno := syscall.Syscall(syscall.SYS_FCNTL, fd.Fd(), syscall.F_GETFL, 0)
	if errno != 0 {
		return errno
	}
	flags &^= syscall.O_NONBLOCK
	_, _, errno = syscall.Syscall(syscall.SYS_FCNTL, fd.Fd(), syscall.F_SETFL, flags)
	if errno != 0 {
		return errno
	}
	return nil
}

// setControlLines applies DTR/RTS state to the serial port via the
// TIOCMSET ioctl. RFC 2217's SET-CONTROL maps to these two modem
// control lines; everything else (RI, DCD, DSR, CTS) is read-only
// from the host's perspective.
func setControlLines(fd *os.File, dtr, rts bool) error {
	var status int
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, fd.Fd(), tiocmget, uintptr(unsafe.Pointer(&status)))
	if errno != 0 {
		return errno
	}
	if dtr {
		status |= tiocmDTR
	} else {
		status &^= tiocmDTR
	}
	if rts {
		status |= tiocmRTS
	} else {
		status &^= tiocmRTS
	}
	_, _, errno = syscall.Syscall(syscall.SYS_IOCTL, fd.Fd(), tiocmset, uintptr(unsafe.Pointer(&status)))
	if errno != 0 {
		return errno
	}
	return nil
}

// pulseDTR drives DTR low for the supplied duration then back high.
// Used by the serial-bridge HTTP "reset" endpoint as a manual fallback
// when the desktop client can't synthesize the DTR toggle (com0com on
// Windows can't easily marshal modem-control IOCTLs across the pair).
func pulseDTR(fd *os.File, ms int) error {
	if err := setControlLines(fd, false, true); err != nil {
		return err
	}
	// 50ms is the conventional optiboot reset pulse; the caller can
	// override but anything below ~10ms risks the bootloader not
	// noticing the edge.
	if ms < 10 {
		ms = 10
	}
	if ms > 5000 {
		ms = 5000
	}
	dur := pulseDuration(ms)
	sleepFor(dur)
	return setControlLines(fd, true, true)
}

// termios2 mirrors the kernel struct used by the TCGETS2 / TCSETS2
// ioctls. The exact layout is per-architecture; we use the AMD64 +
// ARM64 layout (which the Pi 4 runs in 64-bit mode). 32-bit ARMv7
// has a slightly different cc_t array length but we don't ship a
// 32-bit build anymore.
type termios2 struct {
	c_iflag  uint32
	c_oflag  uint32
	c_cflag  uint32
	c_lflag  uint32
	c_line   uint8
	c_cc     [19]uint8
	c_ispeed uint32
	c_ospeed uint32
}

func getTermios2(fd *os.File) (termios2, error) {
	var t termios2
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, fd.Fd(), tcgets2, uintptr(unsafe.Pointer(&t)))
	if errno != 0 {
		return t, errno
	}
	return t, nil
}

func setTermios2(fd *os.File, t termios2) error {
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, fd.Fd(), tcsets2, uintptr(unsafe.Pointer(&t)))
	if errno != 0 {
		return errno
	}
	return nil
}

// Termios constants. These are the asm-generic values used by both
// AMD64 and ARM64 Linux — the Pi 4 build is the only target right now
// and it runs 64-bit. If we ever ship a 32-bit ARMv7 build we'd need
// per-arch builds for these.
const (
	csize    = 0x00000030
	cs5      = 0x00000000
	cs6      = 0x00000010
	cs7      = 0x00000020
	cs8      = 0x00000030
	cstopb   = 0x00000040
	cread    = 0x00000080
	parenb   = 0x00000100
	parodd   = 0x00000200
	clocal   = 0x00000800
	cbaud    = 0x0000100f
	bother   = 0x00001000
	icanon   = 0x00000002
	echo     = 0x00000008
	echoe    = 0x00000010
	echok    = 0x00000020
	echonl   = 0x00000040
	isig     = 0x00000001
	iexten   = 0x00008000
	brkint   = 0x00000002
	icrnl    = 0x00000100
	inpck    = 0x00000010
	istrip   = 0x00000020
	ixon     = 0x00000400
	ixoff    = 0x00001000
	ixany    = 0x00000800
	inlcr    = 0x00000040
	igncr    = 0x00000080
	iuclc    = 0x00000200
	imaxbel  = 0x00002000
	opost    = 0x00000001
	onlcr    = 0x00000004
	cc_vmin  = 6
	cc_vtime = 5

	// ioctl numbers from <asm-generic/ioctls.h>
	tcgets2  uintptr = 0x802c542a
	tcsets2  uintptr = 0x402c542b
	tiocmget uintptr = 0x5415
	tiocmset uintptr = 0x5418

	// modem control bits from <linux/serial.h> + termios.h
	tiocmDTR = 0x002
	tiocmRTS = 0x004
)
