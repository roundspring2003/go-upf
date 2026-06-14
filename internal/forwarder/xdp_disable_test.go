package forwarder

import "testing"

func TestXDPQoSDisabled(t *testing.T) {
	t.Setenv(disableXDPQoSEnv, "true")
	if !xdpQoSDisabled() {
		t.Fatal("xdpQoSDisabled() = false, want true")
	}

	t.Setenv(disableXDPQoSEnv, "false")
	if xdpQoSDisabled() {
		t.Fatal("xdpQoSDisabled() = true, want false")
	}

	t.Setenv(disableXDPQoSEnv, "invalid")
	if xdpQoSDisabled() {
		t.Fatal("xdpQoSDisabled() = true for invalid value, want false")
	}
}
