package tc

import (
	"encoding/binary"
	"net"
	"os"
	"os/exec"
	"testing"
	"time"

	qosconfig "github.com/free5gc/go-upf/internal/qos_manager/config"
	"github.com/free5gc/go-upf/internal/rules"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// Exercise TCX -> HTB -> FQ -> veth with real packets. SO_MARK stands in for
// gtp5g's PDR mark; no external UE, routes or production interfaces are involved.
func TestEDTWireNetworkNamespace(t *testing.T) {
	if os.Getenv("FLOWQOS_TC_NETNS_TEST") != "1" {
		t.Skip("requires isolated network namespace")
	}
	self, err := os.Readlink("/proc/self/ns/net")
	require.NoError(t, err)
	initial, err := os.Readlink("/proc/1/ns/net")
	require.NoError(t, err)
	require.NotEqual(t, initial, self)
	for _, args := range [][]string{{"link", "add", "qos-wire0", "type", "veth", "peer", "name", "qos-wire1"}, {"link", "set", "qos-wire0", "up"}, {"link", "set", "qos-wire1", "up"}} {
		data, err := exec.Command("ip", args...).CombinedOutput()
		require.NoError(t, err, string(data))
	}
	defer exec.Command("ip", "link", "del", "qos-wire0").Run()
	source, err := net.InterfaceByName("qos-wire0")
	require.NoError(t, err)
	peer, err := net.InterfaceByName("qos-wire1")
	require.NoError(t, err)
	e, err := OpenTCEgress([]string{source.Name}, qosconfig.Config{Mode: qosconfig.SharedHTBEDT, CapacityBps: 10_000_000})
	require.NoError(t, err)
	defer e.Close()
	for id := uint32(1); id <= 2; id++ {
		p := testPolicy(id, source.Name)
		p.Rates = []rules.QoSRate{{QERID: id, MBRBps: 256000}, {QERID: 9, MBRBps: 128000}}
		_, err = e.PutQoSPolicy(p)
		require.NoError(t, err)
	}
	// AF_PACKET protocol is in network byte order.
	protocol := int(binary.NativeEndian.Uint16([]byte{8, 0}))
	sender, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, protocol)
	require.NoError(t, err)
	defer unix.Close(sender)
	receiver, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, protocol)
	require.NoError(t, err)
	defer unix.Close(receiver)
	require.NoError(t, unix.Bind(receiver, &unix.SockaddrLinklayer{Ifindex: peer.Index, Protocol: uint16(protocol)}))
	require.NoError(t, unix.SetsockoptInt(receiver, unix.SOL_SOCKET, unix.SO_TIMESTAMPNS, 1))
	require.NoError(t, unix.SetsockoptTimeval(receiver, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Sec: 3}))
	packet := make([]byte, 128)
	copy(packet[:6], peer.HardwareAddr)
	copy(packet[6:12], source.HardwareAddr)
	packet[12] = 8
	packet[14] = 0x45
	binary.BigEndian.PutUint16(packet[16:], 114)
	packet[22] = 64
	packet[23] = 17
	copy(packet[26:30], []byte{10, 200, 0, 1})
	copy(packet[30:34], []byte{10, 200, 0, 2})
	var checksum uint32
	for n := 14; n < 34; n += 2 {
		checksum += uint32(binary.BigEndian.Uint16(packet[n:]))
	}
	for checksum>>16 != 0 {
		checksum = checksum&0xffff + checksum>>16
	}
	binary.BigEndian.PutUint16(packet[24:], ^uint16(checksum))
	binary.BigEndian.PutUint16(packet[34:], 10001)
	binary.BigEndian.PutUint16(packet[36:], 10002)
	binary.BigEndian.PutUint16(packet[38:], 94)
	copy(packet[42:], []byte("flowqos-edt-wire"))
	address := &unix.SockaddrLinklayer{Ifindex: source.Index, Protocol: uint16(protocol), Halen: 6}
	copy(address.Addr[:], peer.HardwareAddr)
	for n := 0; n < 40; n++ {
		require.NoError(t, unix.SetsockoptInt(sender, unix.SOL_SOCKET, unix.SO_MARK, 1+n%2))
		require.NoError(t, unix.Sendto(sender, packet, 0, address))
	}
	var first, last time.Time
	for n := 0; n < 40; n++ {
		buf, oob := make([]byte, 2048), make([]byte, 128)
		length, control, _, _, err := unix.Recvmsg(receiver, buf, oob, 0)
		require.NoError(t, err)
		require.Equal(t, 128, length)
		messages, err := unix.ParseSocketControlMessage(oob[:control])
		require.NoError(t, err)
		var stamp time.Time
		for _, message := range messages {
			if message.Header.Level == unix.SOL_SOCKET && message.Header.Type == unix.SCM_TIMESTAMPNS {
				stamp = time.Unix(int64(binary.NativeEndian.Uint64(message.Data)), int64(binary.NativeEndian.Uint64(message.Data[8:])))
			}
		}
		require.False(t, stamp.IsZero())
		if n == 0 {
			first = stamp
		}
		last = stamp
	}
	span := last.Sub(first)
	// 40 x 128-byte packets at 128 kbit/s require ~312ms between first and last,
	// even though each individual policy has a looser 256 kbit/s cap.
	require.GreaterOrEqual(t, span, 250*time.Millisecond)
	require.Less(t, span, 2*time.Second)
	t.Logf("40 packets across two policies, shared QER 128 kbit/s: %s", span)
}
