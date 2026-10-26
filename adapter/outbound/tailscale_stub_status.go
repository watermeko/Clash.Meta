//go:build !with_gvisor || no_tailscale

package outbound

import "errors"

var errTailscaleUnavailable = errors.New("tailscale support is disabled by \"no_tailscale\" build tag or not include \"with_gvisor\" build tag")

// A build that compiles Tailscale out reports no states, but the host still
// assigns the hook it would report them through: the variable has to exist for
// that assignment to compile.
var TailscaleStatusHook func(status *TailscaleStatus)


// The status of the outbound named by name, for a host that wants to show it
// without dialing through it first. A build without Tailscale answers as if
// no such outbound were configured.
func StartTailscale(name string) error {
	return errTailscaleUnavailable
}

func TailscaleStatusOf(name string) (*TailscaleStatus, error) {
	return nil, nil
}

func LogoutTailscale(name string) error {
	return nil
}

func LoginTailscale(name string) (string, error) {
	return "", nil
}
