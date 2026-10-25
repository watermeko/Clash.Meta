package outbound

import "testing"

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
