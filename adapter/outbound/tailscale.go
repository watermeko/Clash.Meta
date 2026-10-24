//go:build with_gvisor && !no_tailscale

package outbound

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/metacubex/mihomo/component/ca"
	"github.com/metacubex/mihomo/component/dialer"
	"github.com/metacubex/mihomo/component/iface/anet"
	"github.com/metacubex/mihomo/component/resolver"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/dns"
	"github.com/metacubex/mihomo/log"
	"github.com/metacubex/mihomo/tunnel"

	ts "github.com/metacubex/tailscale"
	"github.com/metacubex/tailscale/envknob"
	"github.com/metacubex/tailscale/hostinfo"
	"github.com/metacubex/tailscale/ipn"
	"github.com/metacubex/tailscale/ipn/ipnstate"
	"github.com/metacubex/tailscale/net/netmon"
	"github.com/metacubex/tailscale/tailcfg"
	"github.com/metacubex/tailscale/tsnet"
	"github.com/metacubex/tailscale/types/key"
	D "github.com/miekg/dns"
	"github.com/samber/lo"
)

// A host that shows the node needs the states it was not watching for, such as
// the first Running after a login. The adapter is started before the host can
// ask, so the changes come as calls rather than as a watcher of its own.
var TailscaleStatusHook func(status *TailscaleStatus)

type Tailscale struct {
	*Base
	server      *tsnet.Server
	dnsResolver *dns.Resolver
	option      TailscaleOption
	ctx         context.Context
	cancel      context.CancelFunc
	startOnce   sync.Once
	startErr    error

	backendInitOnce sync.Once
	backendInitCh   chan struct{}
	backendInitErr  error

	serverStarted bool

	// The login URL control answered with. It is the only way back to an
	// unfinished login: the watcher sees it once, when control first asks.
	authURLMu sync.Mutex
	authURL   string

	// Set once a browser login was started for this node, which is what makes
	// the signed-in key an interactive one rather than the pre-auth key. It is
	// kept in the state directory because the process outlives no restart, and
	// the pre-auth key in the config would otherwise claim the credit.
	browserLoginMu sync.Mutex
	browserLogin   bool

	unregisterDNSResolver func()
}

type TailscaleOption struct {
	BasicOption
	Name       string `proxy:"name"`
	Hostname   string `proxy:"hostname,omitempty"`
	AuthKey    string `proxy:"auth-key,omitempty"`
	ControlURL string `proxy:"control-url,omitempty"`
	StateDir   string `proxy:"state-dir,omitempty"`
	Ephemeral  bool   `proxy:"ephemeral,omitempty"`
	UDP        bool   `proxy:"udp,omitempty"`

	AcceptRoutes           *bool  `proxy:"accept-routes,omitempty"`
	ExitNode               string `proxy:"exit-node,omitempty"`
	ExitNodeAllowLANAccess *bool  `proxy:"exit-node-allow-lan-access,omitempty"`
}

func init() {
	hostinfo.RegisterHostinfoNewHook(func(hi *tailcfg.Hostinfo) {
		versionDotTxt := strings.TrimSpace(ts.VersionDotTxt)
		hi.IPNVersion = fmt.Sprintf("%s-%s-%s", versionDotTxt, C.MihomoName, C.Version)
	})
	envknob.SetNoLogsNoSupport()
	if runtime.GOOS == "android" { // Android SDK 30 no longer permits Go's net.Interfaces to work (Issue 2293)
		netmon.RegisterInterfaceGetter(func() (nif []netmon.Interface, err error) {
			log.Debugln("[Tailscale] InterfaceGetter: start, IsForceAnet: %v", anet.IsForceAnet())
			ifaces, err := anet.Interfaces()
			if err != nil {
				log.Warnln("[Tailscale] anet.Interfaces failed: %v", err)
				return nil, err
			}
			for _, iff := range ifaces {
				addrs, err := anet.InterfaceAddrsByInterface(&iff)
				if err != nil {
					log.Warnln("[Tailscale] anet.InterfaceAddrsByInterface(%v) failed: %v", iff.Name, err)
					continue
				}
				nif = append(nif, netmon.Interface{
					Interface: &net.Interface{
						Index:        iff.Index,
						MTU:          iff.MTU,
						Name:         iff.Name,
						HardwareAddr: iff.HardwareAddr,
						Flags:        iff.Flags,
					},
					AltAddrs: addrs,
				})
			}

			log.Debugln("[Tailscale] InterfaceGetter: %v", lo.Map(nif, func(item netmon.Interface, index int) string {
				var addrs any
				addrs, err := item.Addrs()
				if err != nil {
					addrs = err
				}
				return fmt.Sprintf("{Name: %s, Addrs: %v, IsUp: %v, IsLoopback: %v}", item.Name, addrs, item.IsUp(), item.IsLoopback())
			}))
			return
		})
	}
}

func NewTailscale(option TailscaleOption) (*Tailscale, error) {
	if _, err := buildTailscaleMaskedPrefs(option); err != nil {
		return nil, err
	}
	if option.StateDir == "" {
		option.StateDir = "tailscale"
	}
	option.StateDir = C.Path.Resolve(option.StateDir)
	if !C.Path.IsSafePath(option.StateDir) {
		return nil, C.Path.ErrNotSafePath(option.StateDir)
	}

	addr := option.ControlURL
	if addr == "" {
		addr = "tailscale"
	}
	ctx, cancel := context.WithCancel(context.Background())
	outbound := &Tailscale{
		Base: NewBase(BaseOption{
			Name:         option.Name,
			Addr:         addr,
			Type:         C.Tailscale,
			ProviderName: option.ProviderName,
			UDP:          option.UDP,
			Interface:    option.Interface,
			RoutingMark:  option.RoutingMark,
			Prefer:       option.IPVersion,
		}),
		option:        option,
		ctx:           ctx,
		cancel:        cancel,
		backendInitCh: make(chan struct{}),
	}
	outbound.dialer = option.NewDialer(outbound.DialOptions())
	outbound.server = &tsnet.Server{
		Dir:        option.StateDir,
		Hostname:   option.Hostname,
		AuthKey:    option.AuthKey,
		ControlURL: option.ControlURL,
		Ephemeral:  option.Ephemeral,
		SystemDialer: func(ctx context.Context, network, address string) (net.Conn, error) {
			log.Debugln("[Tailscale](%s) SystemDialer: start dial %s %s", option.Name, network, address)
			conn, err := outbound.dialer.DialContext(ctx, network, address)
			log.Debugln("[Tailscale](%s) SystemDialer: finish dial %s %s, err: %v", option.Name, network, address, err)
			return conn, err
		},
		SystemPacketListener: func(ctx context.Context, network, address string) (net.PacketConn, error) {
			log.Debugln("[Tailscale](%s) SystemPacketListener: start listen %s %s", option.Name, network, address)
			pc, err := outbound.dialer.ListenPacket(ctx, network, address, netip.AddrPort{})
			log.Debugln("[Tailscale](%s) SystemPacketListener: finish listen %s %s, err: %v", option.Name, network, address, err)
			return pc, err
		},
		ExtraRootCAs: ca.GetCertPool(),
		LookupHook: func(ctx context.Context, host string) ([]netip.Addr, error) {
			log.Debugln("[Tailscale](%s) LookupHook: start lookup %s", option.Name, host)
			ips, err := resolver.LookupIPWithResolver(ctx, host, resolver.ProxyServerHostResolver)
			log.Debugln("[Tailscale](%s) LookupHook: finish lookup %s, ips: %v, err: %v", option.Name, host, ips, err)
			return ips, err
		},
		UserLogf: func(format string, args ...any) {
			log.Infoln("[Tailscale](%s) %s", option.Name, fmt.Sprintf(format, args...))
		},
		Logf: func(format string, args ...any) {
			log.Debugln("[Tailscale](%s) %s", option.Name, fmt.Sprintf(format, args...))
		},
	}
	dnsTransport := tailscaleDNSTransport{tailscale: outbound}
	outbound.dnsResolver = dns.NewResolverFromClient(dnsTransport)
	outbound.unregisterDNSResolver = dns.RegisterTailscaleDnsClient(option.Name, dnsTransport)
	return outbound, nil
}

// StartTailscale starts the backend of the Tailscale outbound named name so a
// host can reach its status without dialing through it first. An outbound of
// another type, or none at all, is not an error here; the caller finds out
// from the status.
func StartTailscale(name string) error {
	outbound, ok := tailscaleByName(name)
	if !ok {
		return nil
	}
	return outbound.start()
}

// TailscaleStatusOf reports what the backend of the outbound named name knows
// now. It reads the status the backend has rather than starting one, so a host
// that asks about a node it has not brought up gets no answer instead of a
// backend of its own. A nil status with a nil error means either no Tailscale
// outbound carries that name or its backend has not been started.
func TailscaleStatusOf(name string) (*TailscaleStatus, error) {
	outbound, ok := tailscaleByName(name)
	if !ok {
		return nil, nil
	}
	return outbound.status()
}

// LoginTailscale asks the node for the URL a browser has to open. A node that
// is already signed in has none, and one that never started has no browser
// login to finish, so both answer with the empty string rather than an error.
//
// Control is what produces the URL, so the call waits for the watcher to see
// it: asking is the only way to get one for a node that lost the first.
func LoginTailscale(name string) (string, error) {
	outbound, ok := tailscaleByName(name)
	if !ok {
		return "", nil
	}
	if err := outbound.start(); err != nil {
		return "", err
	}
	select {
	case <-outbound.backendInitCh:
		if outbound.backendInitErr != nil {
			return "", outbound.backendInitErr
		}
	default:
		return "", nil
	}
	if url := outbound.storedAuthURL(); url != "" {
		outbound.markBrowserLogin()
		return url, nil
	}
	local, err := outbound.server.LocalClient()
	if err != nil {
		return "", err
	}
	status, err := local.Status(context.Background())
	if err != nil {
		return "", err
	}
	if status.AuthURL != "" {
		outbound.setAuthURL(status.AuthURL)
		outbound.markBrowserLogin()
		return status.AuthURL, nil
	}
	// A node that is signed in needs nothing, and asking would log it out.
	if status.BackendState != ipn.NeedsLogin.String() && status.BackendState != ipn.Stopped.String() {
		return "", nil
	}
	ctx, cancel := context.WithTimeout(outbound.ctx, 30*time.Second)
	defer cancel()
	if err := local.StartLoginInteractive(ctx); err != nil {
		return "", err
	}
	outbound.markBrowserLogin()
	// The URL arrives as a notification, so it is waited for rather than read.
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-ticker.C:
			if url := outbound.storedAuthURL(); url != "" {
				return url, nil
			}
			latest, err := local.Status(context.Background())
			if err != nil {
				continue
			}
			if latest.AuthURL != "" {
				outbound.setAuthURL(latest.AuthURL)
				return latest.AuthURL, nil
			}
		}
	}
}

// LogoutTailscale signs the node of the outbound named name out, which drops
// the key it keeps in its state directory so another account can claim it.
func LogoutTailscale(name string) error {
	outbound, ok := tailscaleByName(name)
	if !ok {
		return nil
	}
	local, err := outbound.server.LocalClient()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(outbound.ctx, 30*time.Second)
	defer cancel()
	if err := local.Logout(ctx); err != nil {
		return err
	}
	// The next login decides the method again, so what this one used is not
	// kept.
	outbound.clearBrowserLogin()
	return nil
}

func tailscaleByName(name string) (*Tailscale, bool) {
	proxy := tunnel.AllProxies()[name]
	if proxy == nil {
		return nil, false
	}
	// Adapter() rather than a type assertion on the concrete proxy: this
	// package cannot import the adapter package that builds it. The tunnel
	// wraps every adapter in autoCloseProxyAdapter, so the search unwraps it.
	var adapter any = proxy.Adapter()
	if unwrapper, ok := adapter.(interface{ UnwrapProxyAdapter() any }); ok {
		adapter = unwrapper.UnwrapProxyAdapter()
	}
	tailscale, ok := adapter.(*Tailscale)
	return tailscale, ok
}

func (t *Tailscale) status() (*TailscaleStatus, error) {
	select {
	case <-t.backendInitCh:
		if t.backendInitErr != nil {
			return nil, t.backendInitErr
		}
	default:
		// start() has not run, so there is no backend to report on yet.
		return nil, nil
	}
	ctx, cancel := context.WithTimeout(t.ctx, 30*time.Second)
	defer cancel()
	local, err := t.server.LocalClient()
	if err != nil {
		return nil, err
	}
	self, err := local.Status(ctx)
	if err != nil {
		return nil, err
	}
	authURL := self.AuthURL
	if authURL == "" {
		authURL = t.storedAuthURL()
	}
	status := &TailscaleStatus{
		Name:         t.Name(),
		BackendState: self.BackendState,
		AuthURL:      authURL,
		HaveNodeKey:  self.HaveNodeKey,
		AuthMethod:   t.authMethod(),
		Online:       self.BackendState == ipn.Running.String(),
		MagicDNS:     self.MagicDNSSuffix,
		IPs:          addressesOf(self.TailscaleIPs),
		Health:       self.Health,
	}
	if self.Self != nil {
		status.Hostname = self.Self.HostName
		status.DNSName = self.Self.DNSName
			status.ExitNode = peerStatusOf(self.ExitNodeStatus, self.Peer)
	}
	status.Peers = make([]TailscalePeer, 0, len(self.Peer))
	for _, peer := range self.Peer {
		status.Peers = append(status.Peers, TailscalePeer{
			Hostname:       peer.HostName,
			DNSName:        peer.DNSName,
			OS:             peer.OS,
			IPs:            addressesOf(peer.TailscaleIPs),
			Online:         peer.Online,
			ExitNodeOption: peer.ExitNodeOption,
			ExitNode:       peer.ExitNode,
			Relay:          peer.Relay,
			CurAddr:        peer.CurAddr,
			RxBytes:        peer.RxBytes,
			TxBytes:        peer.TxBytes,
		})
	}
	sort.Slice(status.Peers, func(i, j int) bool {
		return status.Peers[i].Hostname < status.Peers[j].Hostname
	})
	return status, nil
}

// The exit node's status carries its addresses to dial; the peer entry of the
// same node carries what a list shows.
func peerStatusOf(exitNode *ipnstate.ExitNodeStatus, peers map[key.NodePublic]*ipnstate.PeerStatus) *TailscalePeer {
	if exitNode == nil {
		return nil
	}
	for _, peer := range peers {
		if peer.ID == exitNode.ID {
			return &TailscalePeer{
				Hostname:       peer.HostName,
				DNSName:        peer.DNSName,
				OS:             peer.OS,
				IPs:            addressesOf(peer.TailscaleIPs),
				Online:         peer.Online,
				ExitNodeOption: peer.ExitNodeOption,
				ExitNode:       true,
				Relay:          peer.Relay,
				CurAddr:        peer.CurAddr,
				RxBytes:        peer.RxBytes,
				TxBytes:        peer.TxBytes,
			}
		}
	}
	addresses := make([]string, 0, len(exitNode.TailscaleIPs))
	for _, prefix := range exitNode.TailscaleIPs {
		addresses = append(addresses, prefix.Addr().String())
	}
	return &TailscalePeer{IPs: addresses, ExitNode: true}
}

func addressesOf(addresses []netip.Addr) []string {
	result := make([]string, 0, len(addresses))
	for _, address := range addresses {
		result = append(result, address.String())
	}
	return result
}

func (t *Tailscale) start() error {
	t.startOnce.Do(func() {
		// Read before the backend publishes anything, so the first status
		// already names the way this node was signed in.
		t.loadBrowserLogin()
		if err := t.server.Start(); err != nil {
			t.startErr = err
			t.setBackendInitialized(err)
			return
		}
		t.serverStarted = true
		ctx, cancel := context.WithTimeout(t.ctx, 30*time.Second)
		defer cancel()
		if err := t.applyPrefs(ctx); err != nil {
			t.startErr = err
			t.setBackendInitialized(err)
			return
		}
		go t.watchBackendState()
	})
	return t.startErr
}

func (t *Tailscale) ensureStarted(ctx context.Context) error {
	if err := t.start(); err != nil {
		return err
	}
	return t.waitBackendInitialized(ctx)
}

func (t *Tailscale) watchBackendState() {
	lc, err := t.server.LocalClient()
	if err != nil {
		t.setBackendInitialized(err)
		return
	}
	watcher, err := lc.WatchIPNBus(t.ctx, ipn.NotifyInitialState)
	if err != nil {
		t.setBackendInitialized(err)
		return
	}
	defer watcher.Close()

	backendInitialized := false
	exitNodeNeedsStatus := tailscaleExitNodeNeedsStatus(t.option)
	exitNodeApplied := false
	for {
		n, err := watcher.Next()
		if err != nil {
			t.setBackendInitialized(err)
			return
		}
		if n.BrowseToURL != nil && *n.BrowseToURL != "" {
			t.setAuthURL(*n.BrowseToURL)
		}
		if n.State == nil {
			continue
		}

		if *n.State != ipn.NoState && !backendInitialized {
			t.setBackendInitialized(nil)
			backendInitialized = true
		}
		if exitNodeNeedsStatus && *n.State == ipn.Running && !exitNodeApplied {
			exitNodeApplied = true
			if err := t.applyExitNodePrefs(t.ctx); err != nil {
				log.Warnln("[Tailscale](%s) set exit node failed: %v", t.Name(), err)
			}
		}
		// The exit-node prefs are a change of their own, and the status that
		// follows them is the one a page should show.
		if exitNodeNeedsStatus && !exitNodeApplied {
			continue
		}
		t.publishStatus()
	}
}

func (t *Tailscale) publishStatus() {
	if TailscaleStatusHook == nil {
		return
	}
	status, err := t.status()
	if err != nil || status == nil {
		return
	}
	TailscaleStatusHook(status)
}

func (t *Tailscale) setAuthURL(url string) {
	t.authURLMu.Lock()
	t.authURL = url
	t.authURLMu.Unlock()
	t.publishStatus()
}

const tailscaleBrowserLoginMarker = "browser-login"

func (t *Tailscale) markBrowserLogin() {
	t.browserLoginMu.Lock()
	taken := t.browserLogin
	t.browserLogin = true
	t.browserLoginMu.Unlock()
	if taken {
		return
	}
	// A failure here costs the answer to "which way was this signed in", not
	// the login, so it is not worth failing the call over.
	_ = os.WriteFile(t.browserLoginPath(), nil, 0o600)
}

func (t *Tailscale) browserLoginPath() string {
	return filepath.Join(t.option.StateDir, tailscaleBrowserLoginMarker)
}

// A leftover marker is what says a browser login signed this node in; the key
// in the config may well still be there and unused.
func (t *Tailscale) loadBrowserLogin() {
	if _, err := os.Stat(t.browserLoginPath()); err == nil {
		t.browserLoginMu.Lock()
		t.browserLogin = true
		t.browserLoginMu.Unlock()
	}
}

func (t *Tailscale) clearBrowserLogin() {
	t.browserLoginMu.Lock()
	t.browserLogin = false
	t.browserLoginMu.Unlock()
	_ = os.Remove(t.browserLoginPath())
}

// An interactive login wins over a pre-auth key: it only happens when the key
// did not sign the node in, or when there was no key to begin with.
func (t *Tailscale) authMethod() string {
	t.browserLoginMu.Lock()
	browser := t.browserLogin
	t.browserLoginMu.Unlock()
	if browser {
		return "browser"
	}
	if t.option.AuthKey != "" {
		return "auth-key"
	}
	return ""
}

func (t *Tailscale) storedAuthURL() string {
	t.authURLMu.Lock()
	defer t.authURLMu.Unlock()
	return t.authURL
}

func (t *Tailscale) setBackendInitialized(err error) {
	t.backendInitOnce.Do(func() {
		t.backendInitErr = err
		close(t.backendInitCh)
	})
}

func (t *Tailscale) waitBackendInitialized(ctx context.Context) error {
	select {
	case <-t.backendInitCh:
		return t.backendInitErr
	case <-ctx.Done():
		return ctx.Err()
	case <-t.ctx.Done():
		return t.ctx.Err()
	}
}

func (t *Tailscale) applyPrefs(ctx context.Context) error {
	mp, err := buildTailscaleMaskedPrefs(t.option)
	if err != nil {
		return err
	}
	if mp == nil {
		return nil
	}
	lc, err := t.server.LocalClient()
	if err != nil {
		return err
	}
	_, err = lc.EditPrefs(ctx, mp)
	return err
}

func (t *Tailscale) applyExitNodePrefs(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	lc, err := t.server.LocalClient()
	if err != nil {
		return err
	}
	status, err := lc.Status(ctx)
	if err != nil {
		return err
	}
	mp := &ipn.MaskedPrefs{
		ExitNodeIPSet: true,
	}
	if t.option.ExitNodeAllowLANAccess != nil {
		mp.ExitNodeAllowLANAccess = *t.option.ExitNodeAllowLANAccess
		mp.ExitNodeAllowLANAccessSet = true
	}
	if err = mp.SetExitNodeIP(t.option.ExitNode, status); err != nil {
		return err
	}
	_, err = lc.EditPrefs(ctx, mp)
	return err
}

func buildTailscaleMaskedPrefs(option TailscaleOption) (*ipn.MaskedPrefs, error) {
	var mp ipn.MaskedPrefs
	changed := false

	if option.AcceptRoutes != nil {
		mp.RouteAll = *option.AcceptRoutes
		mp.RouteAllSet = true
		changed = true
	}
	if option.ExitNode != "" {
		if autoExitNode, ok := ipn.ParseAutoExitNodeString(option.ExitNode); ok {
			mp.AutoExitNode = autoExitNode
			mp.AutoExitNodeSet = true
			changed = true
		}
	}
	if option.ExitNodeAllowLANAccess != nil && !tailscaleExitNodeNeedsStatus(option) {
		mp.ExitNodeAllowLANAccess = *option.ExitNodeAllowLANAccess
		mp.ExitNodeAllowLANAccessSet = true
		changed = true
	}
	if !changed {
		return nil, nil
	}
	return &mp, nil
}

func tailscaleExitNodeNeedsStatus(option TailscaleOption) bool {
	if option.ExitNode == "" {
		return false
	}
	_, ok := ipn.ParseAutoExitNodeString(option.ExitNode)
	return !ok
}

func (t *Tailscale) DialContext(ctx context.Context, metadata *C.Metadata) (_ C.Conn, err error) {
	if err = t.ensureStarted(ctx); err != nil {
		return nil, err
	}
	netStack, err := t.server.Netstack(ctx)
	if err != nil {
		return nil, err
	}
	v4, v6 := t.server.TailscaleIPs()
	options := t.DialOptions()
	options = append(options, dialer.WithResolver(t.dnsResolver))
	options = append(options, dialer.WithNetDialer(dialer.NetDialerFunc(func(ctx context.Context, network, address string) (net.Conn, error) {
		dst, err := netip.ParseAddrPort(address) // the dialer will resolve the domain to ip
		if err != nil {
			return nil, err
		}
		src := v4
		if dst.Addr().Is6() {
			src = v6
		}
		tcpConn, err := netStack.DialContextTCPWithBind(ctx, src, dst)
		if err != nil {
			return nil, err
		}
		return tcpConn, nil
	})))
	var conn net.Conn
	conn, err = dialer.NewDialer(options...).DialContext(ctx, "tcp", metadata.RemoteAddress())
	if err != nil {
		return nil, err
	}
	if conn == nil {
		return nil, errors.New("conn is nil")
	}
	return NewConn(conn, t), nil
}

func (t *Tailscale) ListenPacketContext(ctx context.Context, metadata *C.Metadata) (_ C.PacketConn, err error) {
	if err = t.ensureStarted(ctx); err != nil {
		return nil, err
	}
	if err = t.ResolveUDP(ctx, metadata); err != nil {
		return nil, err
	}
	v4, v6 := t.server.TailscaleIPs()
	src := v4
	if metadata.DstIP.Is6() {
		src = v6
	}
	pc, err := t.server.ListenPacket("udp", net.JoinHostPort(src.String(), "0"))
	if err != nil {
		return nil, err
	}
	if pc == nil {
		return nil, errors.New("packetConn is nil")
	}
	return NewPacketConn(pc, t), nil
}

func (t *Tailscale) ResolveUDP(ctx context.Context, metadata *C.Metadata) error {
	if metadata.Host != "" {
		ip, err := resolveIPWithResolver(ctx, metadata.Host, t.prefer, t.dnsResolver)
		if err != nil {
			return fmt.Errorf("can't resolve ip: %w", err)
		}
		metadata.DstIP = ip
	}
	return nil
}

type tailscaleDNSTransport struct {
	tailscale *Tailscale
}

func (t tailscaleDNSTransport) Address() string {
	return "tailscale://" + t.tailscale.Name()
}

func (t tailscaleDNSTransport) ResetConnection() {}

func (t tailscaleDNSTransport) ExchangeContext(ctx context.Context, msg *D.Msg) (*D.Msg, error) {
	if len(msg.Question) == 0 {
		return nil, errors.New("should have one question at least")
	}
	if err := t.tailscale.ensureStarted(ctx); err != nil {
		return nil, err
	}
	q := msg.Question[0]
	qtypeName, ok := D.TypeToString[q.Qtype]
	if !ok {
		return nil, fmt.Errorf("unsupported query type: %d", q.Qtype)
	}
	lc, err := t.tailscale.server.LocalClient()
	if err != nil {
		return nil, err
	}
	response, _, err := lc.QueryDNS(ctx, q.Name, qtypeName)
	if err != nil {
		return nil, err
	}
	var responseMsg D.Msg
	if err = responseMsg.Unpack(response); err != nil {
		return nil, err
	}
	responseMsg.Id = msg.Id
	return &responseMsg, nil
}

func (t *Tailscale) ProxyInfo() C.ProxyInfo {
	info := t.Base.ProxyInfo()
	info.DialerProxy = t.option.DialerProxy
	return info
}

func (t *Tailscale) IsL3Protocol(metadata *C.Metadata) bool {
	return true
}

func (t *Tailscale) Close() error {
	t.cancel()
	if t.unregisterDNSResolver != nil {
		t.unregisterDNSResolver()
	}
	t.startOnce.Do(func() {
		t.startErr = errors.New("tailscale outbound closed")
	})
	if t.server != nil && t.serverStarted { // tsnet.Server.Close() must not be called before or concurrently with Start.
		return t.server.Close()
	}
	return nil
}
