//go:build with_gvisor && !no_tailscale

package outbound

import (
	"context"
	"errors"
	"testing"
	"time"
)

// The page shows the way in, and the two ways are exclusive: a browser login
// wins over the key the profile carries, because the key is only a way to sign
// in, not the record of having done it.
func TestTailscaleAuthMethod(t *testing.T) {
	testCases := []struct {
		name       string
		authKey    string
		browser    bool
		haveNode   bool
		wantMethod string
	}{
		{
			name:       "nothing signed in yet",
			wantMethod: "",
		},
		{
			name:       "a key with no node key yet",
			authKey:    "tskey-auth-example",
			wantMethod: "",
		},
		{
			name:       "a node key issued without a key to explain it",
			haveNode:   true,
			wantMethod: "",
		},
		{
			name:       "a key that signed the node in",
			authKey:    "tskey-auth-example",
			haveNode:   true,
			wantMethod: "auth-key",
		},
		{
			name:       "signed in through the browser",
			browser:    true,
			haveNode:   true,
			wantMethod: "browser",
		},
		{
			name:       "the browser wins while its key is still configured",
			authKey:    "tskey-auth-example",
			browser:    true,
			haveNode:   true,
			wantMethod: "browser",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := authMethodOf(tc.browser, tc.authKey, tc.haveNode)
			if got != tc.wantMethod {
				t.Errorf("authMethodOf() = %q, want %q", got, tc.wantMethod)
			}
		})
	}
}

// A login asked for while the backend is still coming up used to read the
// initialization channel without waiting and answer "no URL": the host shows
// that as a device that is already signed in, which is what a fresh install
// saw. Waiting is the fix, and this is the property it has to keep.
func TestTailscaleWaitBackendInitialized(t *testing.T) {
	t.Run("waits for a backend that has not started", func(t *testing.T) {
		tailscale := &Tailscale{
			ctx:           context.Background(),
			backendInitCh: make(chan struct{}),
		}
		done := make(chan error, 1)
		go func() {
			done <- tailscale.waitBackendInitialized(tailscale.ctx)
		}()

		select {
		case err := <-done:
			t.Fatalf("waitBackendInitialized() returned %v before the backend started", err)
		case <-time.After(50 * time.Millisecond):
		}

		tailscale.setBackendInitialized(nil)
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("waitBackendInitialized() = %v, want nil", err)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("waitBackendInitialized() did not return after the backend started")
		}
	})

	t.Run("reports the error the startup ended with", func(t *testing.T) {
		tailscale := &Tailscale{
			ctx:           context.Background(),
			backendInitCh: make(chan struct{}),
		}
		want := errors.New("no backend")
		tailscale.setBackendInitialized(want)

		if err := tailscale.waitBackendInitialized(tailscale.ctx); !errors.Is(err, want) {
			t.Errorf("waitBackendInitialized() = %v, want %v", err, want)
		}
	})

	t.Run("gives up when the caller's context ends", func(t *testing.T) {
		tailscale := &Tailscale{
			ctx:           context.Background(),
			backendInitCh: make(chan struct{}),
		}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		if err := tailscale.waitBackendInitialized(ctx); !errors.Is(err, context.Canceled) {
			t.Errorf("waitBackendInitialized() = %v, want %v", err, context.Canceled)
		}
	})
}
