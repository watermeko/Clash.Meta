//go:build with_gvisor && !no_tailscale && linux && !android

package outbound

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sync"

	"github.com/metacubex/mihomo/log"
	"github.com/metacubex/tailscale-wireguard-go/tun"
	"github.com/sagernet/netlink"
)

// A tailnet is a network, and a machine on a network is reached at its address:
// without a device carrying that address the node can only dial out, and a peer
// that dials it has nothing to arrive at. This is that device, named so the
// interface is recognisable on the host, kept inside the adapter so any local
// port is reachable and nothing has to be named port by port.
//
// The interface is separate from mihomo's on purpose: the kernel keeps the
// tailnet's route in the main table, where it wins over the proxy tun's default
// route, so tailnet traffic never enters the proxy path.

const (
	tailscaleOverlayTunName = "FlClashTailnet"
	// 1280 is what a tailnet's packets are sized for: WireGuard's overhead over
	// IPv4 leaves no room for a larger datagram.
	tailscaleOverlayTunMTU = 1280
)

// tailscaleTailnetPrefixes is the range a tailnet hands out: the CGNAT block for
// IPv4 and Tailscale's own ULA for IPv6.
var tailscaleTailnetPrefixes = []netip.Prefix{
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("fd7a:115c:a1e0::/48"),
}

// tailscaleTunDevice presents the kernel interface as the device the engine
// writes tailnet packets to and reads them from.
type tailscaleTunDevice struct {
	file   *os.File
	name   string
	mtu    int
	events chan tun.Event
	once   sync.Once
}

func openTailscaleOverlayTun() (*tailscaleTunDevice, error) {
	// A device left behind by a run that ended without closing it would take the
	// name and leave every packet without a way in.
	if stale, err := netlink.LinkByName(tailscaleOverlayTunName); err == nil {
		if err = netlink.LinkDel(stale); err != nil {
			return nil, fmt.Errorf("tailscale: clear stale overlay tun: %w", err)
		}
	}
	tuntap := &netlink.Tuntap{
		LinkAttrs: netlink.LinkAttrs{
			Name: tailscaleOverlayTunName,
			MTU:  tailscaleOverlayTunMTU,
		},
		Mode:       netlink.TUNTAP_MODE_TUN,
		NonPersist: true,
		Queues:     1,
	}
	if err := netlink.LinkAdd(tuntap); err != nil {
		return nil, fmt.Errorf("tailscale: create overlay tun: %w", err)
	}
	if len(tuntap.Fds) == 0 || tuntap.Fds[0] == nil {
		_ = netlink.LinkDel(tuntap)
		return nil, errors.New("tailscale: overlay tun opened no queue")
	}
	events := make(chan tun.Event, 1)
	events <- tun.EventUp
	return &tailscaleTunDevice{
		file:   tuntap.Fds[0],
		name:   tailscaleOverlayTunName,
		mtu:    tailscaleOverlayTunMTU,
		events: events,
	}, nil
}

// takeAddress puts the address the control plane handed out on the interface,
// which is what makes the address local to this machine, and routes the tailnet
// into it so a peer is reached through the device rather than the proxy.
func (d *tailscaleTunDevice) takeAddress(addresses []netip.Prefix) error {
	if len(addresses) == 0 {
		return errors.New("tailscale: the node reported no address")
	}
	link, err := netlink.LinkByName(d.name)
	if err != nil {
		return fmt.Errorf("tailscale: find overlay tun: %w", err)
	}
	for _, prefix := range addresses {
		if !prefix.IsValid() || !prefix.Addr().Is4() {
			continue
		}
		if err = netlink.AddrAdd(link, &netlink.Addr{IPNet: prefixToNet(prefix)}); err != nil {
			return fmt.Errorf("tailscale: address %s on overlay tun: %w", prefix, err)
		}
	}
	if err = netlink.LinkSetUp(link); err != nil {
		return fmt.Errorf("tailscale: bring overlay tun up: %w", err)
	}
	for _, tailnet := range tailscaleTailnetPrefixes {
		route := &netlink.Route{LinkIndex: link.Attrs().Index, Dst: prefixToNet(tailnet.Masked())}
		if err = netlink.RouteReplace(route); err != nil {
			return fmt.Errorf("tailscale: route %s into the overlay tun: %w", tailnet, err)
		}
	}
	log.Infoln("[Tailscale] %s holds %s", d.name, addresses[0])
	return nil
}

func prefixToNet(prefix netip.Prefix) *net.IPNet {
	bits := prefix.Bits()
	if !prefix.Addr().Is4() {
		bits = prefix.Bits()
	}
	addr := prefix.Addr()
	if addr.Is4() {
		return &net.IPNet{IP: net.IP(addr.AsSlice()), Mask: net.CIDRMask(bits, 32)}
	}
	return &net.IPNet{IP: net.IP(addr.AsSlice()), Mask: net.CIDRMask(bits, 128)}
}

// device is the handle the engine keeps.
func (d *tailscaleTunDevice) device() tun.Device { return d }

func (d *tailscaleTunDevice) File() *os.File { return d.file }

func (d *tailscaleTunDevice) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	if len(bufs) == 0 {
		return 0, nil
	}
	n, err := d.file.Read(bufs[0][offset:])
	if err != nil {
		return 0, err
	}
	sizes[0] = n
	return 1, nil
}

func (d *tailscaleTunDevice) Write(bufs [][]byte, offset int) (int, error) {
	for index, packet := range bufs {
		if _, err := d.file.Write(packet[offset:]); err != nil {
			return index, err
		}
	}
	return len(bufs), nil
}

// BatchSize is how many packets one Read may return; the file queue hands over
// one at a time.
func (d *tailscaleTunDevice) BatchSize() int { return 1 }

func (d *tailscaleTunDevice) MTU() (int, error) { return d.mtu, nil }

func (d *tailscaleTunDevice) Name() (string, error) { return d.name, nil }

func (d *tailscaleTunDevice) Events() <-chan tun.Event { return d.events }

func (d *tailscaleTunDevice) Close() error {
	var err error
	d.once.Do(func() {
		if d.events != nil {
			close(d.events)
			d.events = nil
		}
		err = d.file.Close()
		if link, linkErr := netlink.LinkByName(d.name); linkErr == nil {
			_ = netlink.LinkDel(link)
		}
	})
	return err
}
