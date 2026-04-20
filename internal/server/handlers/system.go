package handlers

import (
	"net/http"
	"os/exec"

	"github.com/rs/zerolog/log"

	"github.com/rud1-es/rud1-fw/internal/domain/device"
	domainnet "github.com/rud1-es/rud1-fw/internal/domain/network"
	sysinfo "github.com/rud1-es/rud1-fw/internal/infrastructure/system"
	"github.com/rud1-es/rud1-fw/internal/infrastructure/vpn"
	"github.com/rud1-es/rud1-fw/internal/platform"
)

// SystemHandler serves system-level API endpoints.
type SystemHandler struct {
	version    string
	identity   *device.Identity
	netScanner func() (*domainnet.Status, error)
	vpnPath    string
	vpnIface   string
}

// NewSystemHandler creates a SystemHandler.
func NewSystemHandler(
	version string,
	identity *device.Identity,
	netScanner func() (*domainnet.Status, error),
	vpnConfigPath string,
	vpnIface string,
) *SystemHandler {
	return &SystemHandler{
		version:    version,
		identity:   identity,
		netScanner: netScanner,
		vpnPath:    vpnConfigPath,
		vpnIface:   vpnIface,
	}
}

// systemInfoResponse is the payload returned by GET /api/system/info.
type systemInfoResponse struct {
	Version          string            `json:"version"`
	Platform         string            `json:"platform"`
	Arch             string            `json:"arch"`
	Simulated        bool              `json:"simulated"`
	Hostname         string            `json:"hostname"`
	KernelVersion    string            `json:"kernelVersion,omitempty"`
	RegistrationCode string            `json:"registrationCode"`
	DeviceID         string            `json:"deviceId"`
	SerialNumber     string            `json:"serialNumber,omitempty"`
	Status           device.Status     `json:"status"`
	Metrics          *sysinfo.Metrics  `json:"metrics"`
	VPN              *vpnStatusBody    `json:"vpn"`
	Network          *domainnet.Status `json:"network"`
}

type vpnStatusBody struct {
	Interface string `json:"interface"`
	Connected bool   `json:"connected"`
	Address   string `json:"address"`
	Endpoint  string `json:"endpoint"`
	PublicKey string `json:"publicKey,omitempty"`
	DNS       string `json:"dns,omitempty"`
}

// Info handles GET /api/system/info.
func (h *SystemHandler) Info(w http.ResponseWriter, r *http.Request) {
	metrics, err := sysinfo.Read()
	if err != nil {
		log.Warn().Err(err).Msg("failed to read system metrics")
		metrics = &sysinfo.Metrics{}
	}

	netStatus, err := h.netScanner()
	if err != nil {
		log.Warn().Err(err).Msg("failed to scan network")
	}

	hostname := ""
	if netStatus != nil {
		hostname = netStatus.Hostname
	}

	regCode := ""
	deviceID := ""
	serialNumber := ""
	status := device.StatusProvisioning
	if h.identity != nil {
		regCode = h.identity.RegistrationCode
		deviceID = h.identity.DeviceID
		serialNumber = h.identity.SerialNumber
		// Device is considered online once it has a DeviceID from the cloud.
		if h.identity.DeviceID != "" {
			status = device.StatusOnline
		}
	}

	var vpnBody *vpnStatusBody
	if h.vpnPath != "" {
		if st, err := wireguard.Read(h.vpnPath); err == nil {
			vpnBody = &vpnStatusBody{
				Interface: st.Interface,
				Connected: st.Connected,
				Address:   st.Address,
				Endpoint:  st.Endpoint,
				PublicKey: st.PublicKey,
				DNS:       st.DNS,
			}
		} else {
			vpnBody = &vpnStatusBody{
				Interface: h.vpnIface,
				Connected: wireguard.IsConnected(h.vpnIface),
			}
		}
	}

	writeJSON(w, http.StatusOK, systemInfoResponse{
		Version:          h.version,
		Platform:         platform.OS(),
		Arch:             platform.Arch(),
		Simulated:        platform.SimulateHardware(),
		Hostname:         hostname,
		KernelVersion:    sysinfo.KernelVersion(),
		RegistrationCode: regCode,
		DeviceID:         deviceID,
		SerialNumber:     serialNumber,
		Status:           status,
		Metrics:          metrics,
		VPN:              vpnBody,
		Network:          netStatus,
	})
}

// Reboot handles POST /api/system/reboot.
func (h *SystemHandler) Reboot(w http.ResponseWriter, r *http.Request) {
	if platform.SimulateHardware() {
		log.Info().Msg("reboot requested (simulated — no-op)")
		w.WriteHeader(http.StatusNoContent)
		return
	}

	log.Warn().Msg("system reboot requested via API")
	cmd := exec.CommandContext(r.Context(), "shutdown", "-r", "now")
	if err := cmd.Start(); err != nil {
		log.Error().Err(err).Msg("failed to invoke shutdown")
		writeError(w, http.StatusInternalServerError, "failed to trigger reboot")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
