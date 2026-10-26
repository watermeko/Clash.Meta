package outbound

// What a host shows for one EasyTier outbound. Defined apart from the adapter
// so it exists in builds that compile EasyTier out, where the adapter reports
// it is unavailable instead.
//
// EasyTier has no control plane and no login: a node joins by holding the same
// network name and secret as its peers, so there is no auth URL, no key state
// and nothing to sign out of. What a host can show is whether the node is up
// and who it has reached.
type EasyTierStatus struct {
	Name string `json:"name"`
	// The instance's own state, mirroring easytier-go's State: "created",
	// "starting", "running", "stopping" or "stopped".
	State string `json:"state"`
	// EasyTier's own instance id, which tells a restarted node from the one
	// that was there before.
	InstanceID  string `json:"instance-id,omitempty"`
	Hostname    string `json:"hostname,omitempty"`
	NetworkName string `json:"network-name,omitempty"`
	// The address this node holds in the overlay, empty until it has joined.
	IPv4 string `json:"ipv4,omitempty"`
	// Whether the node has at least one peer, which is what a joined node has
	// and a node that only started does not.
	Connected bool `json:"connected"`
	// How many peers it reached, and the machines they reported: the overlay's
	// equivalent of a tailnet's machine list.
	Peers []EasyTierPeer `json:"peers"`
	// Why the node is not up, when it is not.
	Error string `json:"error,omitempty"`
}

// One machine in the overlay. EasyTier reports a hostname and an address per
// route and no name for the link in between, so the two are all there is.
type EasyTierPeer struct {
	Hostname string `json:"hostname"`
	IPv4     string `json:"ipv4"`
	// The overlay path length: 1 for a direct peer, more when relayed.
	PathLen int `json:"path-len"`
	// Round trip to the next hop in milliseconds, when the node measured one.
	LatencyMs int64 `json:"latency-ms,omitempty"`
	// The transport the node reached the peer over, when it is direct.
	Tunnel string `json:"tunnel,omitempty"`
}
