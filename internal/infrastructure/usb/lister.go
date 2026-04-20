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
type Device struct {
	BusID       string
	VendorID    string
	ProductID   string
	VendorName  string
	ProductName string
	Serial      string
}

var busIDPattern = regexp.MustCompile(`^\d+-\d+$`)

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
			BusID:       "1-1",
			VendorID:    "0781",
			ProductID:   "5583",
			VendorName:  "SanDisk",
			ProductName: "Ultra USB 3.0",
		},
		{
			BusID:       "1-2",
			VendorID:    "046d",
			ProductID:   "c52b",
			VendorName:  "Logitech",
			ProductName: "Unifying Receiver",
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
