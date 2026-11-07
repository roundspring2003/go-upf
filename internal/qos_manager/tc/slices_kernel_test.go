package tc

import (
	"os"
	"os/exec"
	"strings"
	"testing"

	qosconfig "github.com/free5gc/go-upf/internal/qos_manager/config"
	"github.com/stretchr/testify/require"
)

func TestSliceNetworkNamespace(t *testing.T) {
	if os.Getenv("FLOWQOS_TC_NETNS_TEST") != "1" {
		t.Skip("requires isolated network namespace")
	}
	self, err := os.Readlink("/proc/self/ns/net")
	require.NoError(t, err)
	initial, err := os.Readlink("/proc/1/ns/net")
	require.NoError(t, err)
	require.NotEqual(t, initial, self, "refusing host network namespace")
	for _, iface := range []string{"n3", "n6"} {
		out, err := exec.Command("ip", "link", "add", iface, "type", "dummy").CombinedOutput()
		require.NoError(t, err, string(out))
		defer exec.Command("ip", "link", "del", iface).Run()
	}
	for _, mode := range []qosconfig.Mode{qosconfig.HybridHTBEDT, qosconfig.PerFlowHTBEDT} {
		t.Run(string(mode), func(t *testing.T) {
			e, err := OpenTCEgress([]string{"n3", "n6"}, testSliceConfig(mode))
			require.NoError(t, err)
			defer e.Close()
			require.True(t, e.UsesSlices())
			a, b, c := slicePolicy(1, "1-010203", 10_000_000), slicePolicy(2, "1-010203", 0), slicePolicy(3, "1-112233", 0)
			aid, err := e.PutQoSPolicy(a)
			require.NoError(t, err)
			bid, err := e.PutQoSPolicy(b)
			require.NoError(t, err)
			cid, err := e.PutQoSPolicy(c)
			require.NoError(t, err)
			require.NotEqual(t, bid, cid)
			require.NotEqual(t, aid, bid)
			for _, p := range []struct{ id, class uint32 }{{1, aid}, {2, bid}, {3, cid}} {
				var mapped qosMapPolicy
				require.NoError(t, e.objects.Maps["qos_policy"].Lookup(p.id, &mapped))
				require.Equal(t, p.class, mapped.ClassID)
			}
			d := slicePolicy(4, "1-010203", 5_000_000)
			d.Target.Egress = "n3"
			_, err = e.PutQoSPolicy(d)
			require.NoError(t, err)
			data, err := exec.Command("tc", "class", "show", "dev", "n6").Output()
			require.NoError(t, err)
			require.Contains(t, string(data), "class htb e001:10 parent e001:1")
			require.Contains(t, string(data), "class htb e001:11 parent e001:10")
			expected := 9
			if mode.PerFlowClass(false) {
				expected = 11
			}
			require.Len(t, strings.Split(strings.TrimSpace(string(data)), "\n"), expected)
			for id := uint32(1); id <= 4; id++ {
				require.NoError(t, e.DeleteQoSPolicy(id))
			}
			data, err = exec.Command("tc", "class", "show", "dev", "n6").Output()
			require.NoError(t, err)
			require.Len(t, strings.Split(strings.TrimSpace(string(data)), "\n"), 8, "slice hierarchy survives session cleanup")
		})
	}
}
