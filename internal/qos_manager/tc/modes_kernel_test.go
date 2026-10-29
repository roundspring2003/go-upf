package tc

import (
	"os"
	"os/exec"
	"strings"
	"testing"

	qosconfig "github.com/free5gc/go-upf/internal/qos_manager/config"
	"github.com/free5gc/go-upf/internal/rules"
	"github.com/stretchr/testify/require"
)

// Run only in a freshly unshared network namespace. Refuse the initial network
// namespace even when explicitly enabled, so tests cannot alter lab interfaces.
func TestTCModesNetworkNamespace(t *testing.T) {
	if os.Getenv("FLOWQOS_TC_NETNS_TEST") != "1" {
		t.Skip("requires isolated network namespace")
	}
	self, err := os.Readlink("/proc/self/ns/net")
	require.NoError(t, err)
	initial, err := os.Readlink("/proc/1/ns/net")
	require.NoError(t, err)
	require.NotEqual(t, initial, self, "refusing the host network namespace")
	cmd := exec.Command("ip", "link", "add", "qos-mode-test", "type", "dummy")
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, string(out))
	defer exec.Command("ip", "link", "del", "qos-mode-test").Run()
	for _, mode := range []qosconfig.Mode{qosconfig.PerFlowHTB, qosconfig.SharedHTB, qosconfig.SharedHTBEDT} {
		t.Run(string(mode), func(t *testing.T) {
			e, err := OpenTCEgress([]string{"qos-mode-test"}, qosconfig.Config{Mode: mode})
			require.NoError(t, err)
			defer e.Close()
			p := testPolicy(1, "qos-mode-test")
			p.Rates = []rules.QoSRate{{QERID: 1, MBRBps: 5_000_000, GBRBps: 2_000_000}}
			gbr, err := e.PutQoSPolicy(p)
			require.NoError(t, err)
			be, err := e.PutQoSPolicy(testPolicy(2, "qos-mode-test"))
			require.NoError(t, err)
			require.NotEqual(t, gbr, be)
			be2, err := e.PutQoSPolicy(testPolicy(3, "qos-mode-test"))
			require.NoError(t, err)
			if mode == qosconfig.PerFlowHTB {
				require.NotEqual(t, be, be2)
			} else {
				require.Equal(t, be, be2)
			}
			data, err := exec.Command("tc", "class", "show", "dev", "qos-mode-test").Output()
			require.NoError(t, err)
			classes := strings.Split(strings.TrimSpace(string(data)), "\n")
			expected := 4
			if mode == qosconfig.PerFlowHTB {
				expected += 3
			}
			require.Len(t, classes, expected)
			require.NoError(t, e.DeleteQoSPolicy(2))
			require.NoError(t, e.DeleteQoSPolicy(1))
			require.NoError(t, e.DeleteQoSPolicy(3))
			data, err = exec.Command("tc", "class", "show", "dev", "qos-mode-test").Output()
			require.NoError(t, err)
			classes = strings.Split(strings.TrimSpace(string(data)), "\n")
			require.Len(t, classes, 4, "base hierarchy remains until Close")
		})
	}
}
