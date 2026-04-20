//go:build !linux

package usblister

import "fmt"

// USBIPServer is a stub on non-Linux platforms.
type USBIPServer struct{ port int }

func NewUSBIPServer(port int) *USBIPServer { return &USBIPServer{port: port} }

func (s *USBIPServer) Start() error              { return fmt.Errorf("usbipd not supported on this platform") }
func (s *USBIPServer) Stop()                     {}
func (s *USBIPServer) Export(busId string) error { return fmt.Errorf("usbip not supported on this platform") }
func (s *USBIPServer) Unexport(busId string) error { return fmt.Errorf("usbip not supported on this platform") }
func (s *USBIPServer) ExportedDevices() []string   { return nil }

func ListExportable() ([]string, error) { return nil, nil }
