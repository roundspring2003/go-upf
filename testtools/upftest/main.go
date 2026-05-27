package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"
)

const (
	xtQoSProfileIEType       uint16 = 0x8001
	xtQoSProfileEnterpriseID uint16 = 0xfffe
	xtQoSProfileVersion      uint8  = 1

	qosClassLatencySensitive uint32 = 1
	qosClassStandard         uint32 = 2
	qosClassBackground       uint32 = 3
)

type qosFlow struct {
	QERID      uint32
	QFI        uint8
	QoSClass   uint32
	RemotePort uint16
	UEPort     uint16
}

func main() {
	var (
		server         = flag.String("s", "127.0.0.8:8805", "server's addr/port")
		nodeid         = flag.String("n", "127.0.0.1", "client's node id")
		qfi            = flag.Uint("qfi", 9, "legacy single-flow QFI; used only when -qos-flows is empty")
		qosClass       = flag.Uint("qos-class", 3, "legacy single-flow class; used only when -qos-flows is empty (1=latency-sensitive, 2=standard/high-throughput, 3=default/background)")
		qosFlows       = flag.String("qos-flows", "", "comma-separated QFI:class or QERID:QFI:class list, for example 7:1,8:2,9:3")
		ueIP           = flag.String("ue-ip", "60.60.0.6", "UE IPv4 address used by PDRs")
		accessTEID     = flag.Uint("access-teid", 1, "uplink access-side TEID shared by all QFI flows")
		accessIP       = flag.String("access-ip", "172.16.1.1", "IPv4 address in access-side F-TEID")
		dnn            = flag.String("dnn", "internet", "network instance / DNN")
		dlTEID         = flag.Uint("dl-teid", 2, "downlink outer-header TEID")
		dlPeerIP       = flag.String("dl-peer-ip", "172.16.1.3", "downlink outer-header peer IPv4 address")
		dlExact        = flag.Bool("dl-exact", false, "create one downlink PDR with an SDF filter per QoS flow")
		remoteIP       = flag.String("remote-ip", "1.1.1.1", "remote IPv4 address used in generated downlink SDF filters")
		remotePortBase = flag.Uint("remote-port-base", 5000, "first remote UDP source port used in generated downlink SDF filters")
		uePortBase     = flag.Uint("ue-port-base", 6000, "first UE UDP destination port used in generated downlink SDF filters")
		boottime       = time.Now()
		seq            uint32
		err            error
		buf            = make([]byte, 1500)
		waiting        bool
	)
	flag.Parse()

	flows, err := parseQoSFlows(*qosFlows, *qfi, *qosClass, *remotePortBase, *uePortBase)
	if err != nil {
		log.Fatal(err)
	}
	if net.ParseIP(*nodeid) == nil {
		log.Fatalf("invalid node id IP %q", *nodeid)
	}
	if net.ParseIP(*ueIP).To4() == nil {
		log.Fatalf("invalid UE IPv4 %q", *ueIP)
	}
	if net.ParseIP(*accessIP).To4() == nil {
		log.Fatalf("invalid access IPv4 %q", *accessIP)
	}
	if net.ParseIP(*dlPeerIP).To4() == nil {
		log.Fatalf("invalid downlink peer IPv4 %q", *dlPeerIP)
	}
	if *dlExact && net.ParseIP(*remoteIP).To4() == nil {
		log.Fatalf("invalid remote IPv4 %q", *remoteIP)
	}
	if *accessTEID == 0 || *accessTEID > 0xffffffff {
		log.Fatalf("invalid access-teid %d: want 1..4294967295", *accessTEID)
	}
	if *dlTEID == 0 || *dlTEID > 0xffffffff {
		log.Fatalf("invalid dl-teid %d: want 1..4294967295", *dlTEID)
	}

	raddr, err := net.ResolveUDPAddr("udp4", *server)
	if err != nil {
		log.Fatal(err)
	}

	conn, err := net.DialUDP("udp4", nil, raddr)
	if err != nil {
		log.Fatal(err)
	}

	seq += 1
	asreq, err := message.NewAssociationSetupRequest(
		seq,
		ie.NewNodeID(*nodeid, "", ""),
		ie.NewRecoveryTimeStamp(boottime),
	).Marshal()
	if err != nil {
		log.Fatal(err)
	}

	if _, err = conn.Write(asreq); err != nil {
		log.Fatal(err)
	}
	log.Printf("sent PFCP Association Setup Request to: %s", raddr)

	if err = conn.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		log.Fatal(err)
	}

	waiting = true
	for waiting {
		n, addr, err1 := conn.ReadFrom(buf)
		if err1 != nil {
			log.Fatal(err1)
		}

		msg, err1 := message.Parse(buf[:n])
		if err1 != nil {
			log.Printf("ignored undecodable message: %x, error: %s", buf[:n], err1)
			continue
		}

		asres, ok := msg.(*message.AssociationSetupResponse)
		if !ok {
			log.Printf("got unexpected message: %s, from: %s", msg.MessageTypeName(), addr)
			continue
		}

		waiting = false
		if asres.Cause == nil {
			log.Printf("got non accepted response")
			return
		}
		if cause, err1 := asres.Cause.Cause(); cause != ie.CauseRequestAccepted || err1 != nil {
			log.Printf("got non accepted response")
			return
		}
	}

	sessionIEs := []*ie.IE{
		ie.NewNodeID(*nodeid, "", ""),
		ie.NewFSEID(1, net.ParseIP(*nodeid), nil),
		buildAccessPDR(uint32(*accessTEID), *accessIP, *ueIP, flows),
	}
	if *dlExact {
		sessionIEs = append(sessionIEs, buildDLExactPDRs(*dnn, *ueIP, *remoteIP, flows)...)
	} else {
		sessionIEs = append(sessionIEs, buildDLDefaultPDR(*dnn, *ueIP, flows[0].QERID))
	}
	sessionIEs = append(sessionIEs,
		buildAccessFAR(*dnn),
		buildDownlinkFAR(*dnn, uint32(*dlTEID), *dlPeerIP),
	)
	for _, flow := range flows {
		sessionIEs = append(sessionIEs, buildQER(flow))
	}
	sessionIEs = append(sessionIEs, ie.NewPDNType(ie.PDNTypeIPv4))

	seq += 1
	sereq, err := message.NewSessionEstablishmentRequest(
		1,
		0,
		0,
		seq,
		0,
		sessionIEs...,
	).Marshal()
	if err != nil {
		log.Fatal(err)
	}

	if _, err := conn.Write(sereq); err != nil {
		log.Fatal(err)
	}
	log.Printf("sent Session Establishment Request to: %s", raddr)
	for _, flow := range flows {
		log.Printf("configured flow: qer=%d qfi=%d class=%d remote_port=%d ue_port=%d", flow.QERID, flow.QFI, flow.QoSClass, flow.RemotePort, flow.UEPort)
	}

	if err := conn.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		log.Fatal(err)
	}

	waiting = true
	for waiting {
		n, addr, err := conn.ReadFrom(buf)
		if err != nil {
			log.Fatal(err)
		}

		msg, err := message.Parse(buf[:n])
		if err != nil {
			log.Printf("ignored undecodable message: %x, error: %s", buf[:n], err)
			continue
		}

		seres, ok := msg.(*message.SessionEstablishmentResponse)
		if !ok {
			log.Printf("got unexpected message: %s, from: %s", msg.MessageTypeName(), addr)
			continue
		}

		waiting = false
		if seres.Cause == nil {
			log.Printf("got non accepted response")
			return
		}
		if cause, err := seres.Cause.Cause(); cause != ie.CauseRequestAccepted || err != nil {
			log.Printf("got non accepted response")
			return
		}
	}
}

func parseQoSFlows(spec string, legacyQFI, legacyClass, remotePortBase, uePortBase uint) ([]qosFlow, error) {
	if strings.TrimSpace(spec) == "" {
		spec = fmt.Sprintf("%d:%d", legacyQFI, legacyClass)
	}

	parts := strings.Split(spec, ",")
	flows := make([]qosFlow, 0, len(parts))
	seenQERID := make(map[uint32]struct{}, len(parts))
	seenQFI := make(map[uint8]struct{}, len(parts))
	for idx, part := range parts {
		fields := strings.Split(strings.TrimSpace(part), ":")
		var (
			qerID    uint64
			qfi      uint64
			qosClass uint64
			err      error
		)

		switch len(fields) {
		case 2:
			qerID = uint64(idx + 1)
			qfi, err = strconv.ParseUint(fields[0], 10, 8)
			if err != nil {
				return nil, fmt.Errorf("parse QFI in %q: %w", part, err)
			}
			qosClass, err = strconv.ParseUint(fields[1], 10, 32)
			if err != nil {
				return nil, fmt.Errorf("parse QoS class in %q: %w", part, err)
			}
		case 3:
			qerID, err = strconv.ParseUint(fields[0], 10, 32)
			if err != nil {
				return nil, fmt.Errorf("parse QER ID in %q: %w", part, err)
			}
			qfi, err = strconv.ParseUint(fields[1], 10, 8)
			if err != nil {
				return nil, fmt.Errorf("parse QFI in %q: %w", part, err)
			}
			qosClass, err = strconv.ParseUint(fields[2], 10, 32)
			if err != nil {
				return nil, fmt.Errorf("parse QoS class in %q: %w", part, err)
			}
		default:
			return nil, fmt.Errorf("invalid -qos-flows entry %q: want QFI:class or QERID:QFI:class", part)
		}

		if qerID == 0 {
			return nil, fmt.Errorf("invalid QER ID 0 in %q", part)
		}
		if qfi == 0 || qfi > 63 {
			return nil, fmt.Errorf("invalid QFI %d in %q: want 1..63", qfi, part)
		}
		if qosClass != uint64(qosClassLatencySensitive) && qosClass != uint64(qosClassStandard) && qosClass != uint64(qosClassBackground) {
			return nil, fmt.Errorf("invalid QoS class %d in %q: want 1, 2, or 3", qosClass, part)
		}
		if _, ok := seenQERID[uint32(qerID)]; ok {
			return nil, fmt.Errorf("duplicate QER ID %d", qerID)
		}
		if _, ok := seenQFI[uint8(qfi)]; ok {
			return nil, fmt.Errorf("duplicate QFI %d", qfi)
		}
		remotePort, err := portWithOffset(remotePortBase, idx)
		if err != nil {
			return nil, err
		}
		uePort, err := portWithOffset(uePortBase, idx)
		if err != nil {
			return nil, err
		}

		flows = append(flows, qosFlow{
			QERID:      uint32(qerID),
			QFI:        uint8(qfi),
			QoSClass:   uint32(qosClass),
			RemotePort: remotePort,
			UEPort:     uePort,
		})
		seenQERID[uint32(qerID)] = struct{}{}
		seenQFI[uint8(qfi)] = struct{}{}
	}
	return flows, nil
}

func portWithOffset(base uint, idx int) (uint16, error) {
	port := base + uint(idx)
	if port == 0 || port > 65535 {
		return 0, fmt.Errorf("invalid generated UDP port %d: want 1..65535", port)
	}
	return uint16(port), nil
}

func buildAccessPDR(accessTEID uint32, accessIP, ueIP string, flows []qosFlow) *ie.IE {
	pdrIEs := []*ie.IE{
		ie.NewPDRID(1),
		ie.NewPrecedence(255),
		ie.NewPDI(
			ie.NewSourceInterface(ie.SrcInterfaceAccess),
			ie.NewFTEID(1, accessTEID, net.ParseIP(accessIP), nil, 0),
			ie.NewNetworkInstance(""),
			ie.NewUEIPAddress(2, ueIP, "", 0, 0),
		),
		ie.NewOuterHeaderRemoval(0, 0),
		ie.NewFARID(1),
	}
	for _, flow := range flows {
		pdrIEs = append(pdrIEs, ie.NewQERID(flow.QERID))
	}
	return ie.NewCreatePDR(pdrIEs...)
}

func buildDLDefaultPDR(dnn, ueIP string, qerID uint32) *ie.IE {
	return ie.NewCreatePDR(
		ie.NewPDRID(2),
		ie.NewPrecedence(255),
		ie.NewPDI(
			ie.NewSourceInterface(ie.SrcInterfaceCore),
			ie.NewNetworkInstance(dnn),
			ie.NewUEIPAddress(2, ueIP, "", 0, 0),
		),
		ie.NewFARID(2),
		ie.NewQERID(qerID),
	)
}

func buildDLExactPDRs(dnn, ueIP, remoteIP string, flows []qosFlow) []*ie.IE {
	pdrs := make([]*ie.IE, 0, len(flows))
	for idx, flow := range flows {
		flowDescription := fmt.Sprintf(
			"permit out 17 from %s %d to assigned %d",
			remoteIP,
			flow.RemotePort,
			flow.UEPort,
		)
		pdrs = append(pdrs, ie.NewCreatePDR(
			ie.NewPDRID(uint16(100+idx)),
			ie.NewPrecedence(255),
			ie.NewPDI(
				ie.NewSourceInterface(ie.SrcInterfaceCore),
				ie.NewNetworkInstance(dnn),
				ie.NewUEIPAddress(2, ueIP, "", 0, 0),
				ie.NewSDFFilter(flowDescription, "", "", "", uint32(idx+1)),
			),
			ie.NewFARID(2),
			ie.NewQERID(flow.QERID),
		))
	}
	return pdrs
}

func buildAccessFAR(dnn string) *ie.IE {
	return ie.NewCreateFAR(
		ie.NewFARID(1),
		ie.NewApplyAction(2),
		ie.NewForwardingParameters(
			ie.NewDestinationInterface(ie.DstInterfaceSGiLANN6LAN),
			ie.NewNetworkInstance(dnn),
		),
	)
}

func buildDownlinkFAR(dnn string, dlTEID uint32, dlPeerIP string) *ie.IE {
	return ie.NewCreateFAR(
		ie.NewFARID(2),
		ie.NewApplyAction(2),
		ie.NewForwardingParameters(
			ie.NewDestinationInterface(ie.DstInterfaceAccess),
			ie.NewNetworkInstance(dnn),
			ie.NewOuterHeaderCreation(
				256,
				dlTEID,
				dlPeerIP,
				"",
				0,
				0,
				0,
			),
		),
	)
}

func buildQER(flow qosFlow) *ie.IE {
	return ie.NewCreateQER(
		ie.NewQERID(flow.QERID),
		ie.NewGateStatus(ie.GateStatusOpen, ie.GateStatusOpen),
		ie.NewMBR(2000000, 1000000),
		ie.NewQFI(flow.QFI),
		newXTQoSProfileIE(flow.QoSClass),
	)
}

func newXTQoSProfileIE(qosClass uint32) *ie.IE {
	return ie.NewVendorSpecificIE(
		xtQoSProfileIEType,
		xtQoSProfileEnterpriseID,
		[]byte{xtQoSProfileVersion, byte(qosClass)},
	)
}
