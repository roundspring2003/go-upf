package pfcp

import (
	"encoding/binary"
	"net"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/wmnsk/go-pfcp/ie"

	"github.com/free5gc/go-upf/internal/forwarder"
	logger_util "github.com/free5gc/util/logger"
)

type qosCaptureDriver struct {
	forwarder.Empty
	ulUpdates        map[forwarder.QoSULFlowKey]forwarder.QoSFlowInfo
	ulDeletes        []forwarder.QoSULFlowKey
	dlExactUpdates   map[forwarder.QoSDLFlowKey]forwarder.QoSFlowInfo
	dlExactDeletes   []forwarder.QoSDLFlowKey
	dlDefaultUpdates map[uint32]forwarder.QoSFlowInfo
	dlDefaultDeletes []uint32
}

func newQoSCaptureDriver() *qosCaptureDriver {
	return &qosCaptureDriver{
		ulUpdates:        make(map[forwarder.QoSULFlowKey]forwarder.QoSFlowInfo),
		dlExactUpdates:   make(map[forwarder.QoSDLFlowKey]forwarder.QoSFlowInfo),
		dlDefaultUpdates: make(map[uint32]forwarder.QoSFlowInfo),
	}
}

func (d *qosCaptureDriver) UpdateULFlowQoS(key forwarder.QoSULFlowKey, info forwarder.QoSFlowInfo) error {
	d.ulUpdates[key] = info
	return nil
}

func (d *qosCaptureDriver) DeleteULFlowQoS(key forwarder.QoSULFlowKey) error {
	d.ulDeletes = append(d.ulDeletes, key)
	delete(d.ulUpdates, key)
	return nil
}

func (d *qosCaptureDriver) UpdateDLExactFlowQoS(key forwarder.QoSDLFlowKey, info forwarder.QoSFlowInfo) error {
	d.dlExactUpdates[key] = info
	return nil
}

func (d *qosCaptureDriver) DeleteDLExactFlowQoS(key forwarder.QoSDLFlowKey) error {
	d.dlExactDeletes = append(d.dlExactDeletes, key)
	delete(d.dlExactUpdates, key)
	return nil
}

func (d *qosCaptureDriver) UpdateDLDefaultQoS(ueIPv4 uint32, info forwarder.QoSFlowInfo) error {
	d.dlDefaultUpdates[ueIPv4] = info
	return nil
}

func (d *qosCaptureDriver) DeleteDLDefaultQoS(ueIPv4 uint32) error {
	d.dlDefaultDeletes = append(d.dlDefaultDeletes, ueIPv4)
	delete(d.dlDefaultUpdates, ueIPv4)
	return nil
}

func newQoSTestSess(driver *qosCaptureDriver) *Sess {
	rnode := NewRemoteNode(
		"smf1",
		nil,
		&LocalNode{},
		driver,
		logrus.WithField(logger_util.FieldControlPlaneNodeID, "smf1"),
	)
	return rnode.NewSess(10)
}

func newXTQoSProfileIE(qosClass uint32) *ie.IE {
	return ie.NewVendorSpecificIE(
		xtQoSProfileIEType,
		xtQoSProfileEnterpriseID,
		[]byte{xtQoSProfileVersion, byte(qosClass)},
	)
}

func TestQERQoSClassRequiresQFIAndSMFProfile(t *testing.T) {
	ies := []*ie.IE{
		ie.NewQFI(7),
		ie.NewGBR(1000, 1000),
		ie.NewMBR(2000, 2000),
		newXTQoSProfileIE(forwarder.QoSClassLatencySensitive),
	}

	qfi, err := qfiFromQERIEs(ies)
	assert.NoError(t, err)
	assert.Equal(t, uint8(7), qfi)

	qosClass, err := classifyQERQoSClass(ies)
	assert.NoError(t, err)
	assert.Equal(t, forwarder.QoSClassLatencySensitive, qosClass)

	_, err = qfiFromQERIEs([]*ie.IE{newXTQoSProfileIE(forwarder.QoSClassStandard)})
	assert.Error(t, err)

	_, err = classifyQERQoSClass([]*ie.IE{ie.NewQFI(7)})
	assert.Error(t, err)

	_, err = classifyQERQoSClass([]*ie.IE{newXTQoSProfileIE(99)})
	assert.Error(t, err)
}

func TestSessFlattensULPDRQERToTEIDQFIQoSMap(t *testing.T) {
	driver := newQoSCaptureDriver()
	sess := newQoSTestSess(driver)

	err := sess.CreateQER(ie.NewCreateQER(
		ie.NewQERID(2),
		ie.NewQFI(7),
		ie.NewGBR(1000, 1000),
		ie.NewMBR(2000, 2000),
		newXTQoSProfileIE(forwarder.QoSClassLatencySensitive),
	))
	assert.NoError(t, err)

	err = sess.CreatePDR(ie.NewCreatePDR(
		ie.NewPDRID(1),
		ie.NewPDI(
			ie.NewSourceInterface(ie.SrcInterfaceAccess),
			ie.NewFTEID(1, 100, net.IPv4(172, 16, 1, 1), nil, 0),
			ie.NewUEIPAddress(2, "60.60.0.6", "", 0, 0),
		),
		ie.NewQERID(2),
	))
	assert.NoError(t, err)

	key := forwarder.QoSULFlowKey{TEID: 100, QFI: 7}
	assert.Equal(t, forwarder.QoSFlowInfo{QFI: 7, QoSClass: forwarder.QoSClassLatencySensitive}, driver.ulUpdates[key])
	assert.Empty(t, driver.dlExactUpdates)
	assert.Empty(t, driver.dlDefaultUpdates)
}

func TestSessFlattensMultiQERULPDRToTEIDQFIQoSMap(t *testing.T) {
	driver := newQoSCaptureDriver()
	sess := newQoSTestSess(driver)

	assert.NoError(t, sess.CreateQER(ie.NewCreateQER(
		ie.NewQERID(1),
		ie.NewQFI(7),
		newXTQoSProfileIE(forwarder.QoSClassLatencySensitive),
	)))
	assert.NoError(t, sess.CreateQER(ie.NewCreateQER(
		ie.NewQERID(2),
		ie.NewQFI(8),
		newXTQoSProfileIE(forwarder.QoSClassStandard),
	)))
	assert.NoError(t, sess.CreateQER(ie.NewCreateQER(
		ie.NewQERID(3),
		ie.NewQFI(9),
		newXTQoSProfileIE(forwarder.QoSClassBackground),
	)))

	err := sess.CreatePDR(ie.NewCreatePDR(
		ie.NewPDRID(1),
		ie.NewPDI(
			ie.NewSourceInterface(ie.SrcInterfaceAccess),
			ie.NewFTEID(1, 100, net.IPv4(172, 16, 1, 1), nil, 0),
			ie.NewUEIPAddress(2, "60.60.0.6", "", 0, 0),
		),
		ie.NewQERID(1),
		ie.NewQERID(2),
		ie.NewQERID(3),
	))
	assert.NoError(t, err)

	assert.Equal(t, forwarder.QoSFlowInfo{QFI: 7, QoSClass: forwarder.QoSClassLatencySensitive}, driver.ulUpdates[forwarder.QoSULFlowKey{TEID: 100, QFI: 7}])
	assert.Equal(t, forwarder.QoSFlowInfo{QFI: 8, QoSClass: forwarder.QoSClassStandard}, driver.ulUpdates[forwarder.QoSULFlowKey{TEID: 100, QFI: 8}])
	assert.Equal(t, forwarder.QoSFlowInfo{QFI: 9, QoSClass: forwarder.QoSClassBackground}, driver.ulUpdates[forwarder.QoSULFlowKey{TEID: 100, QFI: 9}])
	assert.Empty(t, driver.dlExactUpdates)
	assert.Empty(t, driver.dlDefaultUpdates)
}

func TestSessFlattensDLPDRSDFToExactFlowQoSMap(t *testing.T) {
	driver := newQoSCaptureDriver()
	sess := newQoSTestSess(driver)

	assert.NoError(t, sess.CreateQER(ie.NewCreateQER(
		ie.NewQERID(3),
		ie.NewQFI(8),
		ie.NewMBR(200000, 200000),
		newXTQoSProfileIE(forwarder.QoSClassStandard),
	)))
	assert.NoError(t, sess.CreatePDR(ie.NewCreatePDR(
		ie.NewPDRID(1),
		ie.NewPDI(
			ie.NewSourceInterface(ie.SrcInterfaceCore),
			ie.NewUEIPAddress(2, "60.60.0.6", "", 0, 0),
			ie.NewSDFFilter("permit out 17 from 1.1.1.1 5555 to assigned 443", "", "", "", 1),
		),
		ie.NewQERID(3),
	)))

	ueIP := binary.BigEndian.Uint32(net.ParseIP("60.60.0.6").To4())
	remoteIP := binary.BigEndian.Uint32(net.ParseIP("1.1.1.1").To4())
	key := forwarder.QoSDLFlowKey{
		UEIPv4:     ueIP,
		RemoteIPv4: remoteIP,
		UEPort:     443,
		RemotePort: 5555,
		Proto:      17,
	}
	assert.Equal(t, forwarder.QoSFlowInfo{QFI: 8, QoSClass: forwarder.QoSClassStandard}, driver.dlExactUpdates[key])
	assert.Empty(t, driver.dlDefaultUpdates)
	assert.Empty(t, driver.ulUpdates)
}

func TestSessFlattensDefaultDLPDRToUEQoSMap(t *testing.T) {
	driver := newQoSCaptureDriver()
	sess := newQoSTestSess(driver)

	assert.NoError(t, sess.CreateQER(ie.NewCreateQER(
		ie.NewQERID(9),
		ie.NewQFI(9),
		newXTQoSProfileIE(forwarder.QoSClassBackground),
	)))
	assert.NoError(t, sess.CreatePDR(ie.NewCreatePDR(
		ie.NewPDRID(2),
		ie.NewPDI(
			ie.NewSourceInterface(ie.SrcInterfaceCore),
			ie.NewUEIPAddress(2, "60.60.0.6", "", 0, 0),
		),
		ie.NewQERID(9),
	)))

	ueIP := binary.BigEndian.Uint32(net.ParseIP("60.60.0.6").To4())
	assert.Equal(t, forwarder.QoSFlowInfo{QFI: 9, QoSClass: forwarder.QoSClassBackground}, driver.dlDefaultUpdates[ueIP])
	assert.Empty(t, driver.dlExactUpdates)
	assert.Empty(t, driver.ulUpdates)
}

func TestSessRefreshesQoSMapWhenQERArrivesAfterPDR(t *testing.T) {
	driver := newQoSCaptureDriver()
	sess := newQoSTestSess(driver)

	assert.NoError(t, sess.CreatePDR(ie.NewCreatePDR(
		ie.NewPDRID(4),
		ie.NewPDI(
			ie.NewSourceInterface(ie.SrcInterfaceCore),
			ie.NewUEIPAddress(2, "60.60.0.6", "", 0, 0),
		),
		ie.NewQERID(9),
	)))
	assert.Empty(t, driver.dlDefaultUpdates)

	assert.NoError(t, sess.CreateQER(ie.NewCreateQER(
		ie.NewQERID(9),
		ie.NewQFI(9),
		newXTQoSProfileIE(forwarder.QoSClassBackground),
	)))

	ueIP := binary.BigEndian.Uint32(net.ParseIP("60.60.0.6").To4())
	assert.Equal(t, forwarder.QoSFlowInfo{QFI: 9, QoSClass: forwarder.QoSClassBackground}, driver.dlDefaultUpdates[ueIP])
}

func TestSessUpdatesAndDeletesFlowQoSMap(t *testing.T) {
	driver := newQoSCaptureDriver()
	sess := newQoSTestSess(driver)

	assert.NoError(t, sess.CreateQER(ie.NewCreateQER(
		ie.NewQERID(3),
		ie.NewQFI(8),
		newXTQoSProfileIE(forwarder.QoSClassStandard),
	)))
	assert.NoError(t, sess.CreatePDR(ie.NewCreatePDR(
		ie.NewPDRID(1),
		ie.NewPDI(
			ie.NewSourceInterface(ie.SrcInterfaceAccess),
			ie.NewFTEID(1, 100, net.IPv4(172, 16, 1, 1), nil, 0),
		),
		ie.NewQERID(3),
	)))
	oldKey := forwarder.QoSULFlowKey{TEID: 100, QFI: 8}
	assert.Equal(t, forwarder.QoSFlowInfo{QFI: 8, QoSClass: forwarder.QoSClassStandard}, driver.ulUpdates[oldKey])

	_, err := sess.UpdatePDR(ie.NewUpdatePDR(
		ie.NewPDRID(1),
		ie.NewPDI(
			ie.NewSourceInterface(ie.SrcInterfaceAccess),
			ie.NewFTEID(1, 200, net.IPv4(172, 16, 1, 1), nil, 0),
		),
		ie.NewQERID(3),
	))
	assert.NoError(t, err)
	newKey := forwarder.QoSULFlowKey{TEID: 200, QFI: 8}
	assert.NotContains(t, driver.ulUpdates, oldKey)
	assert.Contains(t, driver.ulDeletes, oldKey)
	assert.Equal(t, forwarder.QoSFlowInfo{QFI: 8, QoSClass: forwarder.QoSClassStandard}, driver.ulUpdates[newKey])

	_, err = sess.RemovePDR(ie.NewRemovePDR(ie.NewPDRID(1)))
	assert.NoError(t, err)
	assert.NotContains(t, driver.ulUpdates, newKey)
	assert.Contains(t, driver.ulDeletes, newKey)
}
