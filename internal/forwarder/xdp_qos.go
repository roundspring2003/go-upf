package forwarder

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/cilium/ebpf"

	"github.com/free5gc/go-upf/pkg/factory"
)

const (
	defaultXDPBPFPinDir = "/sys/fs/bpf/xdp/globals"
	defaultTCBPFPinDir  = "/sys/fs/bpf/tc/globals"
	fallbackBPFPinDir   = "/sys/fs/bpf"
	ulFlowQoSMapName    = "ul_flow_qos_map"
	dlExactQoSMapName   = "dl_exact_qos_map"
	dlDefaultQoSMapName = "dl_default_qos_map"
	qosCPUMapName       = "qos_cpu_map"
	qosCPUPoolMapName   = "qos_cpu_pool_map"
	qosCPUMapQueueSize  = uint32(2048)
	qosCPUMapMaxEntries = 256
	qosMapPinDirEnv     = "GO_UPF_EBPF_PIN_PATH"
)

type qosCPUPool struct {
	StartCPU uint32
	CPUCount uint32
}

type qosCPUMapValue struct {
	QueueSize uint32
	ProgramFD int32
}

type xdpQoSMaps struct {
	mu              sync.Mutex
	ulFlowQoS       *ebpf.Map
	dlExactQoS      *ebpf.Map
	dlDefaultQoS    *ebpf.Map
	qosCPU          *ebpf.Map
	qosCPUPool      *ebpf.Map
	qosPools        map[uint32]qosCPUPool
	cpuMapsPrepared bool
}

func newXDPQoSMaps(policy *factory.XDPCPUPolicy) (*xdpQoSMaps, error) {
	if policy == nil {
		return nil, errors.New("xdpCpuPolicy is required")
	}

	totalCPU, err := onlineCPUCount()
	if err != nil {
		return nil, err
	}
	pools, err := buildQoSCPUPools(totalCPU, policy.ReservedPrefixCount)
	if err != nil {
		return nil, err
	}

	return &xdpQoSMaps{
		qosPools: pools,
	}, nil
}

func onlineCPUCount() (int, error) {
	data, err := os.ReadFile("/sys/devices/system/cpu/online")
	if err != nil {
		return 0, fmt.Errorf("read online CPU list: %w", err)
	}

	count := 0
	for _, part := range strings.Split(strings.TrimSpace(string(data)), ",") {
		bounds := strings.Split(part, "-")
		switch len(bounds) {
		case 1:
			if _, err := strconv.Atoi(bounds[0]); err != nil {
				return 0, fmt.Errorf("parse online CPU list %q: %w", string(data), err)
			}
			count++
		case 2:
			start, err := strconv.Atoi(bounds[0])
			if err != nil {
				return 0, fmt.Errorf("parse online CPU list %q: %w", string(data), err)
			}
			end, err := strconv.Atoi(bounds[1])
			if err != nil || end < start {
				return 0, fmt.Errorf("invalid online CPU range %q", part)
			}
			count += end - start + 1
		default:
			return 0, fmt.Errorf("invalid online CPU range %q", part)
		}
	}
	if count == 0 {
		return 0, errors.New("online CPU list is empty")
	}
	return count, nil
}

func (m *xdpQoSMaps) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	var err error
	if m.ulFlowQoS != nil {
		err = errors.Join(err, m.ulFlowQoS.Close())
		m.ulFlowQoS = nil
	}
	if m.dlExactQoS != nil {
		err = errors.Join(err, m.dlExactQoS.Close())
		m.dlExactQoS = nil
	}
	if m.dlDefaultQoS != nil {
		err = errors.Join(err, m.dlDefaultQoS.Close())
		m.dlDefaultQoS = nil
	}
	if m.qosCPU != nil {
		err = errors.Join(err, m.qosCPU.Close())
		m.qosCPU = nil
	}
	if m.qosCPUPool != nil {
		err = errors.Join(err, m.qosCPUPool.Close())
		m.qosCPUPool = nil
	}
	return err
}

func (m *xdpQoSMaps) UpdateULFlowQoS(key QoSULFlowKey, info QoSFlowInfo) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if err := m.ensureOpenLocked(); err != nil {
		return err
	}
	if !IsValidQoSClass(info.QoSClass) {
		return fmt.Errorf("invalid QoS class %d", info.QoSClass)
	}
	if err := m.prepareCPUMapsLocked(); err != nil {
		return err
	}

	if err := m.ulFlowQoS.Update(key, info, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("update %s[%+v]=%+v: %w", ulFlowQoSMapName, key, info, err)
	}
	return nil
}

func (m *xdpQoSMaps) UpdateDLExactFlowQoS(key QoSDLFlowKey, info QoSFlowInfo) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if err := m.ensureOpenLocked(); err != nil {
		return err
	}
	if !IsValidQoSClass(info.QoSClass) {
		return fmt.Errorf("invalid QoS class %d", info.QoSClass)
	}
	if err := m.prepareCPUMapsLocked(); err != nil {
		return err
	}

	if err := m.dlExactQoS.Update(key, info, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("update %s[%+v]=%+v: %w", dlExactQoSMapName, key, info, err)
	}
	return nil
}

func (m *xdpQoSMaps) UpdateDLDefaultQoS(ueIPv4 uint32, info QoSFlowInfo) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if err := m.ensureOpenLocked(); err != nil {
		return err
	}
	if !IsValidQoSClass(info.QoSClass) {
		return fmt.Errorf("invalid QoS class %d", info.QoSClass)
	}
	if err := m.prepareCPUMapsLocked(); err != nil {
		return err
	}

	if err := m.dlDefaultQoS.Update(ueIPv4, info, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("update %s[%d]=%+v: %w", dlDefaultQoSMapName, ueIPv4, info, err)
	}
	return nil
}

func (m *xdpQoSMaps) DeleteULFlowQoS(key QoSULFlowKey) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if err := m.ensureOpenLocked(); err != nil {
		return err
	}
	if err := m.ulFlowQoS.Delete(key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return fmt.Errorf("delete %s[%+v]: %w", ulFlowQoSMapName, key, err)
	}
	return nil
}

func (m *xdpQoSMaps) DeleteDLExactFlowQoS(key QoSDLFlowKey) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if err := m.ensureOpenLocked(); err != nil {
		return err
	}
	if err := m.dlExactQoS.Delete(key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return fmt.Errorf("delete %s[%+v]: %w", dlExactQoSMapName, key, err)
	}
	return nil
}

func (m *xdpQoSMaps) DeleteDLDefaultQoS(ueIPv4 uint32) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if err := m.ensureOpenLocked(); err != nil {
		return err
	}
	if err := m.dlDefaultQoS.Delete(ueIPv4); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return fmt.Errorf("delete %s[%d]: %w", dlDefaultQoSMapName, ueIPv4, err)
	}
	return nil
}

func (m *xdpQoSMaps) ensureOpenLocked() error {
	if m.ulFlowQoS != nil && m.dlExactQoS != nil && m.dlDefaultQoS != nil && m.qosCPU != nil && m.qosCPUPool != nil {
		return nil
	}

	var errs error
	for _, pinDir := range qosMapPinDirs() {
		ulFlowQoS, err := ebpf.LoadPinnedMap(filepath.Join(pinDir, ulFlowQoSMapName), nil)
		if err != nil {
			errs = errors.Join(errs, err)
			continue
		}

		dlExactQoS, err := ebpf.LoadPinnedMap(filepath.Join(pinDir, dlExactQoSMapName), nil)
		if err != nil {
			_ = ulFlowQoS.Close()
			errs = errors.Join(errs, err)
			continue
		}

		dlDefaultQoS, err := ebpf.LoadPinnedMap(filepath.Join(pinDir, dlDefaultQoSMapName), nil)
		if err != nil {
			_ = ulFlowQoS.Close()
			_ = dlExactQoS.Close()
			errs = errors.Join(errs, err)
			continue
		}

		qosCPU, err := ebpf.LoadPinnedMap(filepath.Join(pinDir, qosCPUMapName), nil)
		if err != nil {
			_ = ulFlowQoS.Close()
			_ = dlExactQoS.Close()
			_ = dlDefaultQoS.Close()
			errs = errors.Join(errs, err)
			continue
		}

		qosCPUPool, err := ebpf.LoadPinnedMap(filepath.Join(pinDir, qosCPUPoolMapName), nil)
		if err != nil {
			_ = ulFlowQoS.Close()
			_ = dlExactQoS.Close()
			_ = dlDefaultQoS.Close()
			_ = qosCPU.Close()
			errs = errors.Join(errs, err)
			continue
		}

		m.ulFlowQoS = ulFlowQoS
		m.dlExactQoS = dlExactQoS
		m.dlDefaultQoS = dlDefaultQoS
		m.qosCPU = qosCPU
		m.qosCPUPool = qosCPUPool
		return nil
	}

	return fmt.Errorf("open pinned XDP QoS maps: %w", errs)
}

func (m *xdpQoSMaps) prepareCPUMapsLocked() error {
	if m.cpuMapsPrepared {
		return nil
	}

	spec, err := LoadXdpSmoke()
	if err != nil {
		return fmt.Errorf("load XDP collection spec: %w", err)
	}
	programSpec := spec.Programs["xdp_cpumap_pass"]
	if programSpec == nil {
		return errors.New("xdp_cpumap_pass program is missing")
	}
	passProgram, err := ebpf.NewProgram(programSpec)
	if err != nil {
		return fmt.Errorf("load xdp_cpumap_pass: %w", err)
	}
	defer passProgram.Close()

	for qosClass, pool := range m.qosPools {
		if err := m.qosCPUPool.Update(qosClass, pool, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("update %s[%d]=%+v: %w", qosCPUPoolMapName, qosClass, pool, err)
		}

		for cpu := pool.StartCPU; cpu < pool.StartCPU+pool.CPUCount; cpu++ {
			value := qosCPUMapValue{QueueSize: qosCPUMapQueueSize, ProgramFD: int32(passProgram.FD())}
			if err := m.qosCPU.Update(cpu, value, ebpf.UpdateAny); err != nil {
				return fmt.Errorf("update %s[%d] queue and program: %w", qosCPUMapName, cpu, err)
			}
		}
	}

	m.cpuMapsPrepared = true
	return nil
}

func qosMapPinDirs() []string {
	if pinDir := os.Getenv(qosMapPinDirEnv); pinDir != "" {
		return []string{pinDir}
	}
	return []string{defaultXDPBPFPinDir, defaultTCBPFPinDir, fallbackBPFPinDir}
}

func (g *Gtp5g) UpdateULFlowQoS(key QoSULFlowKey, info QoSFlowInfo) error {
	if g.qosMaps == nil {
		return nil
	}
	return g.qosMaps.UpdateULFlowQoS(key, info)
}

func (g *Gtp5g) DeleteULFlowQoS(key QoSULFlowKey) error {
	if g.qosMaps == nil {
		return nil
	}
	return g.qosMaps.DeleteULFlowQoS(key)
}

func (g *Gtp5g) UpdateDLExactFlowQoS(key QoSDLFlowKey, info QoSFlowInfo) error {
	if g.qosMaps == nil {
		return nil
	}
	return g.qosMaps.UpdateDLExactFlowQoS(key, info)
}

func (g *Gtp5g) DeleteDLExactFlowQoS(key QoSDLFlowKey) error {
	if g.qosMaps == nil {
		return nil
	}
	return g.qosMaps.DeleteDLExactFlowQoS(key)
}

func (g *Gtp5g) UpdateDLDefaultQoS(ueIPv4 uint32, info QoSFlowInfo) error {
	if g.qosMaps == nil {
		return nil
	}
	return g.qosMaps.UpdateDLDefaultQoS(ueIPv4, info)
}

func (g *Gtp5g) DeleteDLDefaultQoS(ueIPv4 uint32) error {
	if g.qosMaps == nil {
		return nil
	}
	return g.qosMaps.DeleteDLDefaultQoS(ueIPv4)
}

func buildQoSCPUPools(totalCPU int, reservedPrefixCount uint32) (map[uint32]qosCPUPool, error) {
	if reservedPrefixCount == 0 {
		return nil, errors.New("xdpCpuPolicy.reservedPrefixCount must be greater than 0")
	}
	if totalCPU <= 0 {
		return nil, fmt.Errorf("invalid CPU count: %d", totalCPU)
	}
	if totalCPU > qosCPUMapMaxEntries {
		return nil, fmt.Errorf("CPU count %d exceeds qos_cpu_map capacity %d", totalCPU, qosCPUMapMaxEntries)
	}
	if reservedPrefixCount >= uint32(totalCPU) {
		return nil, fmt.Errorf("reservedPrefixCount %d leaves no data-plane CPU out of %d", reservedPrefixCount, totalCPU)
	}

	usable := uint32(totalCPU) - reservedPrefixCount
	if usable < 4 {
		return nil, fmt.Errorf("xdpCpuPolicy needs at least 4 data-plane CPUs after reservation; got %d", usable)
	}

	unit := usable / 4
	remainder := usable % 4
	backgroundCount := unit
	latencySensitiveCount := unit
	standardCount := unit * 2

	for _, qosClass := range []uint32{QoSClassStandard, QoSClassBackground, QoSClassLatencySensitive} {
		if remainder == 0 {
			break
		}
		switch qosClass {
		case QoSClassBackground:
			backgroundCount++
		case QoSClassLatencySensitive:
			latencySensitiveCount++
		case QoSClassStandard:
			standardCount++
		}
		remainder--
	}

	start := reservedPrefixCount
	pools := map[uint32]qosCPUPool{
		QoSClassBackground: {
			StartCPU: start,
			CPUCount: backgroundCount,
		},
	}
	start += backgroundCount
	pools[QoSClassLatencySensitive] = qosCPUPool{
		StartCPU: start,
		CPUCount: latencySensitiveCount,
	}
	start += latencySensitiveCount
	pools[QoSClassStandard] = qosCPUPool{
		StartCPU: start,
		CPUCount: standardCount,
	}

	return pools, nil
}
