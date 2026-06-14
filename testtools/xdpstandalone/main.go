package main

import (
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
)

const (
	defaultPinDir = "/sys/fs/bpf/xdp/globals"
	etherTypeIPv4 = 0x0800
	gtpuPort      = 2152
	cpuQueueSize  = 2048
)

var statNames = []string{
	"rx",
	"pass",
	"ul_hit",
	"dl_exact_hit",
	"dl_default_hit",
	"qos_miss",
	"cpu_select_fail",
	"redirect",
}

type ulFlowKey struct {
	TEID uint32
	QFI  uint8
	Pad  [3]uint8
}

type flowInfo struct {
	QFI      uint8
	Pad      [3]uint8
	QoSClass uint32
}

type cpuPool struct {
	StartCPU uint32
	CPUCount uint32
}

type cpuMapValue struct {
	QueueSize uint32
	ProgramFD int32
}

type flowSpec struct {
	TEID     uint32
	QFI      uint8
	QoSClass uint32
}

func main() {
	log.SetFlags(0)
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	var err error
	switch os.Args[1] {
	case "init":
		err = runInit(os.Args[2:])
	case "send":
		err = runSend(os.Args[2:])
	case "stats":
		err = runStats(os.Args[2:])
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		log.Fatal(err)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `Usage:
  xdpstandalone init  [--pin-dir DIR] [--object FILE] [--reserved-prefix N] [--flows TEID:QFI:CLASS,...]
  xdpstandalone send  --interface IFACE [--src-ip IP] [--dst-ip IP] [--dst-mac MAC]
                      [--ue-ip IP] [--remote-ip IP] [--flows TEID:QFI:CLASS,...]
                      [--count N | --duration D]
  xdpstandalone stats [--pin-dir DIR]`)
}

func runInit(args []string) error {
	totalCPU, err := onlineCPUCount()
	if err != nil {
		return err
	}
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	pinDir := fs.String("pin-dir", defaultPinDir, "directory containing pinned QoS maps")
	objectPath := fs.String("object", "", "eBPF object containing xdp_cpumap_pass")
	reserved := fs.Int("reserved-prefix", totalCPU-4, "number of leading CPUs reserved for OS/control plane")
	flowsText := fs.String("flows", "1:7:1,1:8:2,1:9:3", "comma-separated TEID:QFI:CLASS entries")
	if err := fs.Parse(args); err != nil {
		return err
	}

	flows, err := parseFlows(*flowsText)
	if err != nil {
		return err
	}
	pools, err := buildPools(totalCPU, *reserved)
	if err != nil {
		return err
	}

	ulMap, err := loadMap(*pinDir, "ul_flow_qos_map")
	if err != nil {
		return err
	}
	defer ulMap.Close()
	cpuMap, err := loadMap(*pinDir, "qos_cpu_map")
	if err != nil {
		return err
	}
	defer cpuMap.Close()
	poolMap, err := loadMap(*pinDir, "qos_cpu_pool_map")
	if err != nil {
		return err
	}
	defer poolMap.Close()
	if *objectPath == "" {
		return errors.New("--object is required")
	}
	spec, err := ebpf.LoadCollectionSpec(*objectPath)
	if err != nil {
		return fmt.Errorf("load eBPF object: %w", err)
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

	for class, pool := range pools {
		if err := poolMap.Update(class, pool, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("update qos_cpu_pool_map class %d: %w", class, err)
		}
		for cpu := pool.StartCPU; cpu < pool.StartCPU+pool.CPUCount; cpu++ {
			value := cpuMapValue{QueueSize: cpuQueueSize, ProgramFD: int32(passProgram.FD())}
			if err := cpuMap.Update(cpu, value, ebpf.UpdateAny); err != nil {
				return fmt.Errorf("update qos_cpu_map CPU %d: %w", cpu, err)
			}
		}
	}

	for _, flow := range flows {
		key := ulFlowKey{TEID: flow.TEID, QFI: flow.QFI}
		value := flowInfo{QFI: flow.QFI, QoSClass: flow.QoSClass}
		if err := ulMap.Update(key, value, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("update UL flow TEID=%d QFI=%d: %w", flow.TEID, flow.QFI, err)
		}
	}

	fmt.Printf("Initialized %d UL flows in %s\n", len(flows), *pinDir)
	for _, class := range []uint32{3, 1, 2} {
		pool := pools[class]
		fmt.Printf("  class %d: CPU %s\n", class, cpuRange(pool))
	}
	return nil
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

func runSend(args []string) error {
	fs := flag.NewFlagSet("send", flag.ContinueOnError)
	ifaceName := fs.String("interface", "", "Ethernet interface used to inject packets")
	srcIPText := fs.String("src-ip", "10.200.0.2", "outer IPv4 source address")
	dstIPText := fs.String("dst-ip", "10.200.0.1", "outer IPv4 destination address")
	dstMACText := fs.String("dst-mac", "ff:ff:ff:ff:ff:ff", "destination Ethernet MAC address")
	ueIPText := fs.String("ue-ip", "10.60.0.1", "inner UE IPv4 source address")
	remoteIPText := fs.String("remote-ip", "1.1.1.1", "inner remote IPv4 destination address")
	flowsText := fs.String("flows", "1:7:1,1:8:2,1:9:3", "comma-separated TEID:QFI:CLASS entries")
	count := fs.Int("count", 10000, "packets sent for each flow")
	duration := fs.Duration("duration", 0, "send continuously for this duration instead of using --count")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *ifaceName == "" {
		return errors.New("--interface is required")
	}
	if *duration < 0 {
		return errors.New("--duration must not be negative")
	}
	if *duration == 0 && *count <= 0 {
		return errors.New("--count must be greater than zero")
	}
	flows, err := parseFlows(*flowsText)
	if err != nil {
		return err
	}
	srcIP, err := parseIPv4(*srcIPText, "src-ip")
	if err != nil {
		return err
	}
	dstIP, err := parseIPv4(*dstIPText, "dst-ip")
	if err != nil {
		return err
	}
	ueIP, err := parseIPv4(*ueIPText, "ue-ip")
	if err != nil {
		return err
	}
	remoteIP, err := parseIPv4(*remoteIPText, "remote-ip")
	if err != nil {
		return err
	}
	dstMAC, err := net.ParseMAC(*dstMACText)
	if err != nil || len(dstMAC) != 6 {
		return fmt.Errorf("invalid --dst-mac %q", *dstMACText)
	}
	iface, err := net.InterfaceByName(*ifaceName)
	if err != nil {
		return err
	}
	if len(iface.HardwareAddr) != 6 {
		return fmt.Errorf("%s does not have a 6-byte Ethernet address", *ifaceName)
	}

	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(etherTypeIPv4)))
	if err != nil {
		return fmt.Errorf("open AF_PACKET socket: %w", err)
	}
	defer syscall.Close(fd)
	addr := &syscall.SockaddrLinklayer{
		Protocol: htons(etherTypeIPv4),
		Ifindex:  iface.Index,
		Halen:    6,
	}
	copy(addr.Addr[:], dstMAC)

	frames := make([][]byte, len(flows))
	for idx, flow := range flows {
		frames[idx] = buildULFrame(iface.HardwareAddr, dstMAC, srcIP, dstIP, ueIP, remoteIP, flow, uint16(30000)+uint16(flow.QFI), idx)
	}

	start := time.Now()
	sent := make([]uint64, len(flows))
	if *duration > 0 {
		deadline := start.Add(*duration)
		for time.Now().Before(deadline) {
			for idx, flow := range flows {
				if err := syscall.Sendto(fd, frames[idx], 0, addr); err != nil {
					return fmt.Errorf("send QFI %d: %w", flow.QFI, err)
				}
				sent[idx]++
			}
		}
	} else {
		for idx, flow := range flows {
			for i := 0; i < *count; i++ {
				if err := syscall.Sendto(fd, frames[idx], 0, addr); err != nil {
					return fmt.Errorf("send QFI %d: %w", flow.QFI, err)
				}
				sent[idx]++
			}
		}
	}

	elapsed := time.Since(start)
	var total uint64
	for idx, flow := range flows {
		total += sent[idx]
		fmt.Printf("Sent %d packets: TEID=%d QFI=%d class=%d\n", sent[idx], flow.TEID, flow.QFI, flow.QoSClass)
	}
	if elapsed > 0 {
		fmt.Printf("Completed in %s (%.0f packets/s)\n", elapsed.Round(time.Millisecond), float64(total)/elapsed.Seconds())
	} else {
		fmt.Printf("Completed in %s\n", elapsed)
	}
	return nil
}

func runStats(args []string) error {
	fs := flag.NewFlagSet("stats", flag.ContinueOnError)
	pinDir := fs.String("pin-dir", defaultPinDir, "directory containing pinned maps")
	if err := fs.Parse(args); err != nil {
		return err
	}
	stats, err := loadMap(*pinDir, "xdp_stats_map")
	if err != nil {
		return err
	}
	defer stats.Close()

	for idx, name := range statNames {
		key := uint32(idx)
		var value uint64
		if err := stats.Lookup(key, &value); err != nil {
			return fmt.Errorf("lookup xdp_stats_map[%d]: %w", idx, err)
		}
		fmt.Printf("%-16s %d\n", name, value)
	}
	return nil
}

func parseIPv4(value, name string) (net.IP, error) {
	ip := net.ParseIP(strings.TrimSpace(value)).To4()
	if ip == nil {
		return nil, fmt.Errorf("invalid --%s %q", name, value)
	}
	return ip, nil
}

func parseFlows(value string) ([]flowSpec, error) {
	var flows []flowSpec
	for _, item := range strings.Split(value, ",") {
		parts := strings.Split(strings.TrimSpace(item), ":")
		if len(parts) != 3 {
			return nil, fmt.Errorf("invalid flow %q: expected TEID:QFI:CLASS", item)
		}
		teid, err := parseUint(parts[0], 32)
		if err != nil || teid == 0 {
			return nil, fmt.Errorf("invalid TEID in flow %q", item)
		}
		qfi, err := parseUint(parts[1], 8)
		if err != nil || qfi == 0 || qfi > 63 {
			return nil, fmt.Errorf("invalid QFI in flow %q", item)
		}
		class, err := parseUint(parts[2], 32)
		if err != nil || class < 1 || class > 3 {
			return nil, fmt.Errorf("invalid QoS class in flow %q", item)
		}
		flows = append(flows, flowSpec{
			TEID:     uint32(teid),
			QFI:      uint8(qfi),
			QoSClass: uint32(class),
		})
	}
	if len(flows) == 0 {
		return nil, errors.New("at least one flow is required")
	}
	return flows, nil
}

func parseUint(value string, bits int) (uint64, error) {
	return strconv.ParseUint(strings.TrimSpace(value), 0, bits)
}

func buildPools(totalCPU, reserved int) (map[uint32]cpuPool, error) {
	if reserved <= 0 || reserved >= totalCPU {
		return nil, fmt.Errorf("reserved-prefix must be between 1 and %d", totalCPU-1)
	}
	usable := totalCPU - reserved
	if usable < 4 {
		return nil, fmt.Errorf("at least four data-plane CPUs are required; got %d", usable)
	}

	unit := usable / 4
	remainder := usable % 4
	background := unit
	latency := unit
	standard := unit * 2
	for _, class := range []uint32{2, 3, 1} {
		if remainder == 0 {
			break
		}
		switch class {
		case 1:
			latency++
		case 2:
			standard++
		case 3:
			background++
		}
		remainder--
	}

	start := reserved
	pools := map[uint32]cpuPool{
		3: {StartCPU: uint32(start), CPUCount: uint32(background)},
	}
	start += background
	pools[1] = cpuPool{StartCPU: uint32(start), CPUCount: uint32(latency)}
	start += latency
	pools[2] = cpuPool{StartCPU: uint32(start), CPUCount: uint32(standard)}
	return pools, nil
}

func loadMap(pinDir, name string) (*ebpf.Map, error) {
	path := filepath.Join(pinDir, name)
	m, err := ebpf.LoadPinnedMap(path, nil)
	if err != nil {
		return nil, fmt.Errorf("load %s: %w", path, err)
	}
	return m, nil
}

func cpuRange(pool cpuPool) string {
	if pool.CPUCount == 1 {
		return strconv.FormatUint(uint64(pool.StartCPU), 10)
	}
	return fmt.Sprintf("%d-%d", pool.StartCPU, pool.StartCPU+pool.CPUCount-1)
}

func buildULFrame(srcMAC, dstMAC net.HardwareAddr, srcIP, dstIP, ueIP, remoteIP net.IP, flow flowSpec, sourcePort uint16, variant int) []byte {
	payload := []byte("standalone-xdp-qos")
	innerLength := 20 + 8 + len(payload)
	gtpLength := 4 + 4 + innerLength
	udpLength := 8 + 8 + gtpLength
	ipLength := 20 + udpLength
	frame := make([]byte, 14+ipLength)

	copy(frame[0:6], dstMAC)
	copy(frame[6:12], srcMAC)
	binary.BigEndian.PutUint16(frame[12:14], etherTypeIPv4)

	ip := frame[14:34]
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], uint16(ipLength))
	ip[8] = 64
	ip[9] = syscall.IPPROTO_UDP
	copy(ip[12:16], srcIP)
	copy(ip[16:20], dstIP)
	binary.BigEndian.PutUint16(ip[10:12], checksum(ip))

	udp := frame[34:42]
	binary.BigEndian.PutUint16(udp[0:2], sourcePort)
	binary.BigEndian.PutUint16(udp[2:4], gtpuPort)
	binary.BigEndian.PutUint16(udp[4:6], uint16(udpLength))

	gtp := frame[42:]
	gtp[0] = 0x34
	gtp[1] = 0xff
	binary.BigEndian.PutUint16(gtp[2:4], uint16(gtpLength))
	binary.BigEndian.PutUint32(gtp[4:8], flow.TEID)
	gtp[11] = 0x85
	gtp[12] = 1
	gtp[14] = flow.QFI & 0x3f

	innerIP := gtp[16:36]
	innerIP[0] = 0x45
	binary.BigEndian.PutUint16(innerIP[2:4], uint16(innerLength))
	innerIP[8] = 64
	innerIP[9] = syscall.IPPROTO_UDP
	copy(innerIP[12:16], ueIP)
	copy(innerIP[16:20], remoteIP)
	binary.BigEndian.PutUint16(innerIP[10:12], checksum(innerIP))

	innerUDP := gtp[36:44]
	binary.BigEndian.PutUint16(innerUDP[0:2], uint16(6000)+uint16(flow.QFI))
	binary.BigEndian.PutUint16(innerUDP[2:4], uint16(5000)+uint16(flow.QFI)+uint16(variant))
	binary.BigEndian.PutUint16(innerUDP[4:6], uint16(8+len(payload)))
	copy(gtp[44:], payload)
	return frame
}

func checksum(data []byte) uint16 {
	var sum uint32
	for len(data) >= 2 {
		sum += uint32(binary.BigEndian.Uint16(data[:2]))
		data = data[2:]
	}
	if len(data) == 1 {
		sum += uint32(data[0]) << 8
	}
	for sum > 0xffff {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func htons(value uint16) uint16 {
	return value<<8 | value>>8
}
