//go:build with_gvisor && !no_tailscale && (!linux || android)

package outbound

import (
	"fmt"
	"net/netip"
	"runtime"

	"github.com/metacubex/tailscale-wireguard-go/tun"
)

// The tailnet needs a device of its own for a peer to reach a local service, and
// this build only knows how to ask the kernel for one on Linux. Elsewhere the
// node still dials out of the tailnet.
type tailscaleTunDevice struct{}

func openTailscaleOverlayTun() (*tailscaleTunDevice, error) {
	return nil, fmt.Errorf("tailscale: overlay tun is not supported on %s", runtime.GOOS)
}

func (d *tailscaleTunDevice) device() tun.Device { return nil }

func (d *tailscaleTunDevice) takeAddress([]netip.Prefix) error { return nil }

func (d *tailscaleTunDevice) Close() error { return nil }
