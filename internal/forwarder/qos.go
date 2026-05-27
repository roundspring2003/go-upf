package forwarder

const (
	QoSClassLatencySensitive uint32 = 1
	QoSClassStandard         uint32 = 2
	QoSClassBackground       uint32 = 3

	// Deprecated aliases kept for compatibility with existing tests/configs.
	QoSClassDelayCriticalGBR = QoSClassLatencySensitive
	QoSClassStdGBR           = QoSClassStandard
	QoSClassNonGBR           = QoSClassBackground
)

type QoSULFlowKey struct {
	TEID uint32
	QFI  uint8
	Pad  [3]uint8
}

type QoSDLFlowKey struct {
	UEIPv4     uint32
	RemoteIPv4 uint32
	UEPort     uint16
	RemotePort uint16
	Proto      uint8
	Pad        [3]uint8
}

type QoSFlowInfo struct {
	QFI      uint8
	Pad      [3]uint8
	QoSClass uint32
}

func IsValidQoSClass(qosClass uint32) bool {
	switch qosClass {
	case QoSClassLatencySensitive, QoSClassStandard, QoSClassBackground:
		return true
	default:
		return false
	}
}
