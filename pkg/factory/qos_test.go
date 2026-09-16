package factory

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestValidateQoSEgress(t *testing.T) {
	lookup := func(name string) (*net.Interface, error) {
		switch name {
		case "n3", "n6", "upfgtp":
			return &net.Interface{Name: name}, nil
		case "lo":
			return &net.Interface{Name: name, Flags: net.FlagLoopback}, nil
		}
		return nil, fmt.Errorf("interface not found")
	}
	for _, q := range []*QoS{nil, {N3Egress: "n3", N6Egress: "n6"}, {N3Egress: "n3", N6Egress: "n3"}} {
		require.NoError(t, validateQoSEgress(q, lookup))
	}
	for _, q := range []*QoS{
		{}, {N3Egress: "n3"}, {N3Egress: "missing", N6Egress: "n6"},
		{N3Egress: "n3", N6Egress: "lo"}, {N3Egress: "upfgtp", N6Egress: "n6"},
	} {
		require.Error(t, validateQoSEgress(q, lookup))
	}
}

func TestReadQoSEgressConfig(t *testing.T) {
	const base = `version: 1.0.3
pfcp:
  addr: 127.0.0.8
  nodeID: 127.0.0.8
  retransTimeout: 1s
gtpu:
  forwarder: gtp5g
dnnList:
  - dnn: internet
    cidr: 10.60.0.0/16
logger:
  level: info
`
	for _, tc := range []struct {
		name, section string
		invalid       bool
	}{
		{name: "omitted"},
		{name: "configured", section: "qos:\n  n3Egress: n3\n  n6Egress: n6\n"},
		{name: "incomplete", section: "qos:\n  n3Egress: n3\n", invalid: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "upfcfg.yaml")
			require.NoError(t, os.WriteFile(path, []byte(base+tc.section), 0o600))
			cfg, err := ReadConfig(path)
			if tc.invalid {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			if tc.name == "configured" {
				require.Equal(t, &QoS{N3Egress: "n3", N6Egress: "n6"}, cfg.QoS)
			} else {
				require.Nil(t, cfg.QoS)
			}
		})
	}
}

func TestProjectQoSConfig(t *testing.T) {
	cfg, err := ReadConfig("../../config/upfcfg.yaml")
	require.NoError(t, err)
	require.NotNil(t, cfg.QoS)
	require.Equal(t, "enp0s8", cfg.QoS.N3Egress)
	require.Equal(t, "enp0s9", cfg.QoS.N6Egress)
}
