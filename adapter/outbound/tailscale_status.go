package outbound

// What a host shows for one Tailscale outbound. Defined apart from the
// adapter so it exists in builds that compile Tailscale out, where the
// adapter reports it is unavailable instead.

type TailscaleStatus struct {
	Name         string `json:"name"`
	BackendState string `json:"backend-state"`
	AuthURL      string `json:"auth-url,omitempty"`
	Hostname     string `json:"hostname,omitempty"`
	DNSName      string `json:"dns-name,omitempty"`
	MagicDNS     string `json:"magic-dns,omitempty"`
	Online       bool   `json:"online"`
	// Whether a state directory holds a node key, which tells a login that
	// expired from one that never happened.
	HaveNodeKey bool `json:"have-node-key"`
	// How the node got its key: "auth-key" when a pre-auth key signed it in,
	// "browser" when the login was finished in a browser, and empty when it
	// has no key to explain. Control treats the two the same once signed in,
	// so the outbound is what remembers which one was used.
	AuthMethod string          `json:"auth-method,omitempty"`
	IPs        []string        `json:"ips"`
	Health     []string        `json:"health"`
	ExitNode   *TailscalePeer  `json:"exit-node,omitempty"`
	Peers      []TailscalePeer `json:"peers"`
}

type TailscalePeer struct {
	Hostname string   `json:"hostname"`
	DNSName  string   `json:"dns-name"`
	OS       string   `json:"os"`
	IPs      []string `json:"ips"`
	Online   bool     `json:"online"`
	// Offered and approved as an exit node, and the one in use.
	ExitNodeOption bool `json:"exit-node-option"`
	ExitNode       bool `json:"exit-node"`
	// The relay when no direct path exists, else the direct address.
	Relay   string `json:"relay"`
	CurAddr string `json:"cur-addr"`
	RxBytes int64  `json:"rx-bytes"`
	TxBytes int64  `json:"tx-bytes"`
}
