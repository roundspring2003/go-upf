package pfcp

import (
	"encoding/binary"
	"fmt"
	"net"
	"sort"

	"github.com/wmnsk/go-pfcp/ie"

	"github.com/free5gc/go-upf/internal/forwarder"
)

const (
	xtQoSProfileIEType       uint16 = 0x8001
	xtQoSProfileEnterpriseID uint16 = 0xfffe
	xtQoSProfileVersion      uint8  = 1
	xtQoSProfilePayloadLen          = 2
)

type pdrQoSFields struct {
	pdrid            uint16
	teids            map[uint32]struct{}
	ueIPv4s          map[uint32]struct{}
	dlExactFlowKeys  map[forwarder.QoSDLFlowKey]struct{}
	dlDefaultUEIPv4s map[uint32]struct{}
	qerids           map[uint32]struct{}
	hasTEIDs         bool
	hasUEIPv4s       bool
	hasDLFlowKeys    bool
	hasQERIDs        bool
}

func collectPDRQoSFields(ies []*ie.IE) pdrQoSFields {
	fields := pdrQoSFields{
		teids:            make(map[uint32]struct{}),
		ueIPv4s:          make(map[uint32]struct{}),
		dlExactFlowKeys:  make(map[forwarder.QoSDLFlowKey]struct{}),
		dlDefaultUEIPv4s: make(map[uint32]struct{}),
		qerids:           make(map[uint32]struct{}),
	}

	for _, i := range ies {
		switch i.Type {
		case ie.PDRID:
			if id, err := i.PDRID(); err == nil {
				fields.pdrid = id
			}
		case ie.PDI:
			fields.hasTEIDs = true
			for teid := range collectTEIDsFromPDI(i) {
				fields.teids[teid] = struct{}{}
			}

			fields.hasUEIPv4s = true
			ueIPv4s := collectUEIPv4sFromPDI(i)
			for ueIPv4 := range ueIPv4s {
				fields.ueIPv4s[ueIPv4] = struct{}{}
			}

			fields.hasDLFlowKeys = true
			dlFields := collectDLQoSFieldsFromPDI(i, ueIPv4s)
			for key := range dlFields.exactFlowKeys {
				fields.dlExactFlowKeys[key] = struct{}{}
			}
			for ueIPv4 := range dlFields.defaultUEIPv4s {
				fields.dlDefaultUEIPv4s[ueIPv4] = struct{}{}
			}
		case ie.QERID:
			fields.hasQERIDs = true
			if qerid, err := i.QERID(); err == nil {
				fields.qerids[qerid] = struct{}{}
			}
		}
	}

	return fields
}

func collectTEIDsFromPDI(pdi *ie.IE) map[uint32]struct{} {
	teids := make(map[uint32]struct{})

	ies, err := pdi.PDI()
	if err != nil {
		return teids
	}

	for _, i := range ies {
		switch i.Type {
		case ie.FTEID, ie.RedundantTransmissionParameters:
			fteid, err := i.FTEID()
			if err == nil && fteid.TEID != 0 {
				teids[fteid.TEID] = struct{}{}
			}
		}
	}

	return teids
}

func collectUEIPv4sFromPDI(pdi *ie.IE) map[uint32]struct{} {
	ueIPv4s := make(map[uint32]struct{})

	ies, err := pdi.PDI()
	if err != nil {
		return ueIPv4s
	}

	for _, i := range ies {
		if i.Type != ie.UEIPAddress {
			continue
		}
		fields, err := i.UEIPAddress()
		if err != nil {
			continue
		}
		ueIPv4 := fields.IPv4Address.To4()
		if ueIPv4 == nil {
			continue
		}
		ueIPv4s[binary.BigEndian.Uint32(ueIPv4)] = struct{}{}
	}

	return ueIPv4s
}

type dlQoSFields struct {
	exactFlowKeys  map[forwarder.QoSDLFlowKey]struct{}
	defaultUEIPv4s map[uint32]struct{}
}

func collectDLQoSFieldsFromPDI(pdi *ie.IE, ueIPv4s map[uint32]struct{}) dlQoSFields {
	fields := dlQoSFields{
		exactFlowKeys:  make(map[forwarder.QoSDLFlowKey]struct{}),
		defaultUEIPv4s: make(map[uint32]struct{}),
	}

	ies, err := pdi.PDI()
	if err != nil {
		return fields
	}

	if !isDownlinkPDI(ies) {
		return fields
	}

	hasSDF := false
	for _, i := range ies {
		if i.Type != ie.SDFFilter {
			continue
		}
		hasSDF = true
		sdf, err := i.SDFFilter()
		if err != nil || !sdf.HasFD() {
			continue
		}
		for key := range dlExactFlowKeysFromFlowDesc(sdf.FlowDescription, ueIPv4s) {
			fields.exactFlowKeys[key] = struct{}{}
		}
	}

	if !hasSDF {
		for ueIPv4 := range ueIPv4s {
			fields.defaultUEIPv4s[ueIPv4] = struct{}{}
		}
	}

	return fields
}

func isDownlinkPDI(ies []*ie.IE) bool {
	for _, i := range ies {
		if i.Type != ie.SourceInterface {
			continue
		}
		srcIf, err := i.SourceInterface()
		if err != nil {
			return false
		}
		return srcIf != ie.SrcInterfaceAccess
	}
	return false
}

func dlExactFlowKeysFromFlowDesc(flowDescription string, ueIPv4s map[uint32]struct{}) map[forwarder.QoSDLFlowKey]struct{} {
	keys := make(map[forwarder.QoSDLFlowKey]struct{})

	fd, err := forwarder.ParseFlowDesc(flowDescription)
	if err != nil || fd.Action != "permit" {
		return keys
	}
	if fd.Proto == 0xff {
		return keys
	}

	remoteIPv4, ok := exactIPv4(fd.Src)
	if !ok {
		return keys
	}
	ueIPv4Choices, ok := ueIPv4ChoicesFromDst(fd.Dst, ueIPv4s)
	if !ok {
		return keys
	}

	requirePorts := fd.Proto == 6 || fd.Proto == 17
	remotePorts, ok := exactPortChoices(fd.SrcPorts, requirePorts)
	if !ok {
		return keys
	}
	uePorts, ok := exactPortChoices(fd.DstPorts, requirePorts)
	if !ok {
		return keys
	}

	for _, ueIPv4 := range ueIPv4Choices {
		for _, remotePort := range remotePorts {
			for _, uePort := range uePorts {
				keys[forwarder.QoSDLFlowKey{
					UEIPv4:     ueIPv4,
					RemoteIPv4: remoteIPv4,
					UEPort:     uePort,
					RemotePort: remotePort,
					Proto:      fd.Proto,
				}] = struct{}{}
			}
		}
	}

	return keys
}

func ueIPv4ChoicesFromDst(ipnet *net.IPNet, ueIPv4s map[uint32]struct{}) ([]uint32, bool) {
	if isWildcardIPNet(ipnet) {
		if len(ueIPv4s) == 0 {
			return nil, false
		}
		choices := make([]uint32, 0, len(ueIPv4s))
		for ueIPv4 := range ueIPv4s {
			choices = append(choices, ueIPv4)
		}
		sort.Slice(choices, func(i, j int) bool { return choices[i] < choices[j] })
		return choices, true
	}
	ip, ok := exactIPv4(ipnet)
	if !ok {
		return nil, false
	}
	return []uint32{ip}, true
}

func isWildcardIPNet(ipnet *net.IPNet) bool {
	if ipnet == nil {
		return false
	}
	ones, _ := ipnet.Mask.Size()
	return ones == 0
}

func exactIPv4(ipnet *net.IPNet) (uint32, bool) {
	if ipnet == nil {
		return 0, false
	}
	ones, bits := ipnet.Mask.Size()
	if bits != 32 || ones != 32 {
		return 0, false
	}
	ip := ipnet.IP.To4()
	if ip == nil {
		return 0, false
	}
	return binary.BigEndian.Uint32(ip), true
}

func exactPortChoices(ports [][]uint16, required bool) ([]uint16, bool) {
	if len(ports) == 0 {
		if required {
			return nil, false
		}
		return []uint16{0}, true
	}
	choices := make([]uint16, 0, len(ports))
	for _, port := range ports {
		switch len(port) {
		case 1:
			choices = append(choices, port[0])
		case 2:
			if port[0] != port[1] {
				return nil, false
			}
			choices = append(choices, port[0])
		default:
			return nil, false
		}
	}
	return choices, true
}

func qerInfoFromCreateQER(req *ie.IE) (uint32, *QERInfo, error) {
	id, err := req.QERID()
	if err != nil {
		return 0, nil, err
	}

	ies, err := req.CreateQER()
	if err != nil {
		return 0, nil, err
	}

	qfi, err := qfiFromQERIEs(ies)
	if err != nil {
		return 0, nil, err
	}
	qosClass, err := classifyQERQoSClass(ies)
	if err != nil {
		return 0, nil, err
	}

	return id, &QERInfo{QFI: qfi, QoSClass: qosClass}, nil
}

func qerInfoFromUpdateQER(req *ie.IE, current *QERInfo) (*QERInfo, error) {
	if current == nil {
		return nil, fmt.Errorf("missing current QER state")
	}

	ies, err := req.UpdateQER()
	if err != nil {
		return nil, err
	}

	updated := *current
	qfi, hasQFI, err := optionalQFIFromQERIEs(ies)
	if err != nil {
		return nil, err
	}
	if hasQFI {
		updated.QFI = qfi
	}

	qosClass, hasQoSClass, err := optionalQERQoSClass(ies)
	if err != nil {
		return nil, err
	}
	if hasQoSClass {
		updated.QoSClass = qosClass
	}

	return &updated, nil
}

func qfiFromQERIEs(ies []*ie.IE) (uint8, error) {
	qfi, ok, err := optionalQFIFromQERIEs(ies)
	if err != nil {
		return 0, err
	}
	if !ok {
		return 0, fmt.Errorf("missing QFI IE in QER")
	}
	return qfi, nil
}

func optionalQFIFromQERIEs(ies []*ie.IE) (uint8, bool, error) {
	for _, i := range ies {
		if i.Type != ie.QFI {
			continue
		}
		qfi, err := i.QFI()
		if err != nil {
			return 0, false, err
		}
		if qfi == 0 || qfi > 63 {
			return 0, false, fmt.Errorf("QFI=%d is invalid", qfi)
		}
		return qfi, true, nil
	}
	return 0, false, nil
}

func classifyQERQoSClass(ies []*ie.IE) (uint32, error) {
	qosClass, ok, err := optionalQERQoSClass(ies)
	if err != nil {
		return 0, err
	}
	if ok {
		return qosClass, nil
	}
	return forwarder.QoSClassStandard, nil
}

func optionalQERQoSClass(ies []*ie.IE) (uint32, bool, error) {
	for _, i := range ies {
		if i.Type != xtQoSProfileIEType || i.EnterpriseID != xtQoSProfileEnterpriseID {
			continue
		}
		if len(i.Payload) != xtQoSProfilePayloadLen {
			return 0, false, fmt.Errorf("XT QoS Profile IE length=%d, want %d", len(i.Payload), xtQoSProfilePayloadLen)
		}
		if i.Payload[0] != xtQoSProfileVersion {
			return 0, false, fmt.Errorf("XT QoS Profile IE version=%d, want %d", i.Payload[0], xtQoSProfileVersion)
		}

		qosClass := uint32(i.Payload[1])
		if !isValidQoSClass(qosClass) {
			return 0, false, fmt.Errorf("XT QoS Profile IE qosClass=%d is invalid", qosClass)
		}

		return qosClass, true, nil
	}

	return 0, false, nil
}

func isValidQoSClass(qosClass uint32) bool {
	return forwarder.IsValidQoSClass(qosClass)
}

func (s *Sess) qosFlowsForPDR(pdrInfo *PDRInfo) []forwarder.QoSFlowInfo {
	if pdrInfo == nil || len(pdrInfo.RelatedQERIDs) == 0 {
		return nil
	}

	qerids := make([]uint32, 0, len(pdrInfo.RelatedQERIDs))
	for qerid := range pdrInfo.RelatedQERIDs {
		qerids = append(qerids, qerid)
	}
	sort.Slice(qerids, func(i, j int) bool { return qerids[i] < qerids[j] })

	flows := make([]forwarder.QoSFlowInfo, 0, len(qerids))
	seenQFI := make(map[uint8]struct{}, len(qerids))
	for _, qerid := range qerids {
		qerInfo, ok := s.QERIDs[qerid]
		if !ok || qerInfo == nil || !isValidQoSClass(qerInfo.QoSClass) || qerInfo.QFI == 0 || qerInfo.QFI > 63 {
			s.log.Warnf("skip QoS flow: qer=%d is not ready or has invalid QFI/QoS class", qerid)
			continue
		}
		if _, exists := seenQFI[qerInfo.QFI]; exists {
			s.log.Warnf("skip QoS flow: duplicate QFI=%d on qer=%d", qerInfo.QFI, qerid)
			continue
		}
		flows = append(flows, forwarder.QoSFlowInfo{
			QFI:      qerInfo.QFI,
			QoSClass: qerInfo.QoSClass,
		})
		seenQFI[qerInfo.QFI] = struct{}{}
	}
	return flows
}

func (s *Sess) updatePDRQoSMap(pdrid uint16, pdrInfo *PDRInfo) {
	if pdrInfo == nil {
		return
	}

	flowInfos := s.qosFlowsForPDR(pdrInfo)
	if len(flowInfos) == 0 {
		s.deletePDRQoSMap(pdrInfo)
		s.log.Warnf("skip QoS map update: pdr=%d has no ready QER with SMF-assigned QFI/QoS class", pdrid)
		return
	}

	newULKeys := make(map[forwarder.QoSULFlowKey]struct{})
	for teid := range pdrInfo.TEIDs {
		for _, flowInfo := range flowInfos {
			key := forwarder.QoSULFlowKey{TEID: teid, QFI: flowInfo.QFI}
			if err := s.rnode.driver.UpdateULFlowQoS(key, flowInfo); err != nil {
				s.log.Warnf("update UL flow QoS map failed: pdr=%d key=%+v info=%+v err=%+v", pdrid, key, flowInfo, err)
			}
			newULKeys[key] = struct{}{}
		}
	}
	deleteStaleULFlowQoSMap(s, pdrInfo.WrittenULFlowKeys, newULKeys)
	pdrInfo.WrittenULFlowKeys = newULKeys

	newDLExactKeys := make(map[forwarder.QoSDLFlowKey]struct{})
	newDLDefaultUEIPv4s := make(map[uint32]struct{})
	if len(flowInfos) == 1 {
		flowInfo := flowInfos[0]
		for key := range pdrInfo.DLExactFlowKeys {
			if err := s.rnode.driver.UpdateDLExactFlowQoS(key, flowInfo); err != nil {
				s.log.Warnf("update DL exact QoS map failed: pdr=%d key=%+v info=%+v err=%+v", pdrid, key, flowInfo, err)
			}
			newDLExactKeys[key] = struct{}{}
		}
		for ueIPv4 := range pdrInfo.DLDefaultUEIPv4s {
			if err := s.rnode.driver.UpdateDLDefaultQoS(ueIPv4, flowInfo); err != nil {
				s.log.Warnf("update DL default QoS map failed: pdr=%d ueIPv4=%d info=%+v err=%+v", pdrid, ueIPv4, flowInfo, err)
			}
			newDLDefaultUEIPv4s[ueIPv4] = struct{}{}
		}
	} else if len(pdrInfo.DLExactFlowKeys) > 0 || len(pdrInfo.DLDefaultUEIPv4s) > 0 {
		s.log.Warnf(
			"skip DL QoS map update: pdr=%d references %d QERs; use one DL PDR/SDF filter per QFI",
			pdrid,
			len(flowInfos),
		)
	}

	deleteStaleDLExactFlowQoSMap(s, pdrInfo.WrittenDLExactFlowKeys, newDLExactKeys)
	deleteStaleDLDefaultQoSMap(s, pdrInfo.WrittenDLDefaultUEIPv4s, newDLDefaultUEIPv4s)
	pdrInfo.WrittenDLExactFlowKeys = newDLExactKeys
	pdrInfo.WrittenDLDefaultUEIPv4s = newDLDefaultUEIPv4s
}

func (s *Sess) deletePDRQoSMap(pdrInfo *PDRInfo) {
	if pdrInfo == nil {
		return
	}
	deleteStaleULFlowQoSMap(s, pdrInfo.WrittenULFlowKeys, nil)
	deleteStaleDLExactFlowQoSMap(s, pdrInfo.WrittenDLExactFlowKeys, nil)
	deleteStaleDLDefaultQoSMap(s, pdrInfo.WrittenDLDefaultUEIPv4s, nil)
	pdrInfo.WrittenULFlowKeys = nil
	pdrInfo.WrittenDLExactFlowKeys = nil
	pdrInfo.WrittenDLDefaultUEIPv4s = nil
}

func deleteStaleULFlowQoSMap(s *Sess, oldKeys, newKeys map[forwarder.QoSULFlowKey]struct{}) {
	for key := range oldKeys {
		if _, ok := newKeys[key]; ok {
			continue
		}
		if err := s.rnode.driver.DeleteULFlowQoS(key); err != nil {
			s.log.Warnf("delete stale UL flow QoS map failed: key=%+v err=%+v", key, err)
		}
	}
}

func deleteStaleDLExactFlowQoSMap(s *Sess, oldKeys, newKeys map[forwarder.QoSDLFlowKey]struct{}) {
	for key := range oldKeys {
		if _, ok := newKeys[key]; ok {
			continue
		}
		if err := s.rnode.driver.DeleteDLExactFlowQoS(key); err != nil {
			s.log.Warnf("delete stale DL exact QoS map failed: key=%+v err=%+v", key, err)
		}
	}
}

func deleteStaleDLDefaultQoSMap(s *Sess, oldKeys, newKeys map[uint32]struct{}) {
	for ueIPv4 := range oldKeys {
		if _, ok := newKeys[ueIPv4]; ok {
			continue
		}
		if err := s.rnode.driver.DeleteDLDefaultQoS(ueIPv4); err != nil {
			s.log.Warnf("delete stale DL default QoS map failed: ueIPv4=%d err=%+v", ueIPv4, err)
		}
	}
}

func (s *Sess) refreshPDRQoSForQER(qerid uint32) {
	for pdrid, pdrInfo := range s.PDRIDs {
		if _, ok := pdrInfo.RelatedQERIDs[qerid]; ok {
			s.updatePDRQoSMap(pdrid, pdrInfo)
		}
	}
}
