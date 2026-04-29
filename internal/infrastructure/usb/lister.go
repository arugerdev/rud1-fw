// Package usblister enumerates USB devices attached to the host.
package usblister

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/rud1-es/rud1-fw/internal/platform"
)

// Device holds the identifying attributes of a USB device.
//
// DeviceClass and InterfaceClass are the USB class codes read from sysfs
// (`bDeviceClass`, and the first interface's `bInterfaceClass`). They drive
// the auto-mode selector in the export path: CDC-class devices (Arduinos,
// ESP32 dev boards, USB-serial dongles) take the serial-bridge path
// because the kernel `usbip_host` module is unstable when CDC interfaces
// re-enumerate during a DTR-toggle reset, while everything else uses the
// generic USB/IP transport. Empty strings mean sysfs returned no value
// (race during enumeration, or the device was unplugged); callers must
// treat empty as "unknown" rather than "0x00 (per-interface defined)".
type Device struct {
	BusID          string
	VendorID       string
	ProductID      string
	VendorName     string
	ProductName    string
	Serial         string
	DeviceClass    string
	InterfaceClass string
}

// USB class codes we care about for routing decisions. Values are
// hex-encoded lowercase to match sysfs format. The full registry lives at
// https://www.usb.org/defined-class-codes; we only enumerate the two
// classes the auto-mode selector branches on.
const (
	USBClassCommunication = "02" // CDC at the device level (composite CDC+HID etc.)
	USBClassCDCData       = "0a" // CDC-Data at the interface level
)

// IsCDC reports whether the device exposes a CDC-class interface (or is
// CDC at the device level). The serial-bridge path prefers these because
// USB/IP's stub layer races on the re-enumeration that follows a
// DTR-driven Arduino reset — the Pi-side kernel oops in `stub_rx_loop`
// kills the export and the client sees a stranded vhci port.
func (d Device) IsCDC() bool {
	return d.DeviceClass == USBClassCommunication ||
		d.InterfaceClass == USBClassCommunication ||
		d.InterfaceClass == USBClassCDCData
}

// USB busids follow `<bus>-<port>[.<port>]*`: a single port for a device
// plugged straight into a root hub ("1-2"), or dot-joined ports when it
// sits behind one or more hubs ("1-1.4", "2-1.2.3"). The Pi 4's onboard
// VL805 always inserts a `1-1.X` segment for downstream USB-2 ports, so
// the previous `^\d+-\d+$` silently hid every Arduino, hub-attached
// dongle, and most USB-2 peripherals.
var busIDPattern = regexp.MustCompile(`^\d+-\d+(\.\d+)*$`)

// List returns the USB devices currently attached to the host.
// On simulated hardware two fake devices are returned.
func List() ([]Device, error) {
	if platform.SimulateHardware() {
		return simulatedDevices(), nil
	}
	return listLinux()
}

func simulatedDevices() []Device {
	return []Device{
		{
			BusID:          "1-1",
			VendorID:       "0781",
			ProductID:      "5583",
			VendorName:     "SanDisk",
			ProductName:    "Ultra USB 3.0",
			DeviceClass:    "00",
			InterfaceClass: "08", // Mass Storage — generic USB/IP path
		},
		{
			BusID:          "1-2",
			VendorID:       "046d",
			ProductID:      "c52b",
			VendorName:     "Logitech",
			ProductName:    "Unifying Receiver",
			DeviceClass:    "00",
			InterfaceClass: "03", // HID — generic USB/IP path
		},
		{
			// Arduino Uno Rev3 (dog hunter AG / Arduino SRL). CDC at the
			// interface level — the auto-mode selector should prefer the
			// serial bridge for this one to dodge the kernel `usbip_host`
			// race during DTR-toggle reset.
			BusID:          "1-3",
			VendorID:       "2a03",
			ProductID:      "0043",
			VendorName:     "Arduino Srl",
			ProductName:    "Arduino Uno",
			Serial:         "754393239353515191B2",
			DeviceClass:    "02",
			InterfaceClass: "02",
		},
	}
}

// listLinux iterates /sys/bus/usb/devices/ and reads per-device attribute files.
func listLinux() ([]Device, error) {
	root := "/sys/bus/usb/devices"
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, err
	}

	var devices []Device
	for _, entry := range entries {
		name := entry.Name()
		if !busIDPattern.MatchString(name) {
			continue
		}

		dir := filepath.Join(root, name)
		dev := Device{BusID: name}
		dev.VendorID = readSysAttr(dir, "idVendor")
		dev.ProductID = readSysAttr(dir, "idProduct")
		dev.VendorName = readSysAttr(dir, "manufacturer")
		dev.ProductName = readSysAttr(dir, "product")
		dev.Serial = readSysAttr(dir, "serial")
		dev.DeviceClass = readSysAttr(dir, "bDeviceClass")
		// `bInterfaceClass` lives on each USB interface, not the parent
		// device — the parent only carries `bDeviceClass`. We read the
		// first interface (always `<busid>:1.0`) because composite
		// devices (Arduino Leonardo: HID+CDC) still expose the CDC bit
		// there, and devices with a single interface have no other
		// interface to disambiguate. If the first interface dir is
		// missing (race during enumeration, or non-standard device),
		// readSysAttr returns "" and IsCDC falls back to bDeviceClass.
		dev.InterfaceClass = readSysAttr(filepath.Join(dir, name+":1.0"), "bInterfaceClass")

		// Skip entries with no vendor/product — likely hubs or phantom nodes.
		if dev.VendorID == "" && dev.ProductID == "" {
			continue
		}
		devices = append(devices, dev)
	}
	return devices, nil
}

// readSysAttr reads a single-line sysfs attribute file and returns its trimmed content.
// Returns "" on any error.
func readSysAttr(dir, attr string) string {
	data, err := os.ReadFile(filepath.Join(dir, attr))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}
