package main

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"math"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	etherTypeIPv4 = 0x0800
	gtpuPort      = 2152
	probeMagic    = "XTPROBE1"
	probeSize     = 32
)

type flowSpec struct {
	TEID     uint32
	QFI      uint8
	QoSClass uint32
}

type flowResult struct {
	QFI      uint8   `json:"qfi"`
	QoSClass uint32  `json:"qos_class"`
	Sent     uint64  `json:"sent"`
	Received uint64  `json:"received"`
	Loss     uint64  `json:"loss"`
	LossPct  float64 `json:"loss_percent"`
	MinUS    float64 `json:"min_us"`
	MeanUS   float64 `json:"mean_us"`
	P50US    float64 `json:"p50_us"`
	P95US    float64 `json:"p95_us"`
	P99US    float64 `json:"p99_us"`
	MaxUS    float64 `json:"max_us"`
}

type probeResult struct {
	StartedAt string       `json:"started_at"`
	Duration  float64      `json:"duration_seconds"`
	TargetPPS uint64       `json:"target_pps"`
	Sent      uint64       `json:"sent"`
	Received  uint64       `json:"received"`
	Loss      uint64       `json:"loss"`
	LossPct   float64      `json:"loss_percent"`
	RatePPS   float64      `json:"actual_send_pps"`
	MinUS     float64      `json:"min_us"`
	MeanUS    float64      `json:"mean_us"`
	P50US     float64      `json:"p50_us"`
	P95US     float64      `json:"p95_us"`
	P99US     float64      `json:"p99_us"`
	MaxUS     float64      `json:"max_us"`
	Flows     []flowResult `json:"flows"`
}

type receiveState struct {
	mu        sync.Mutex
	seen      map[uint64]struct{}
	latencies [][]int64
}

func main() {
	log.SetFlags(0)
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "echo":
		err = runEcho(os.Args[2:])
	case "probe":
		err = runProbe(os.Args[2:])
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
  gtpuprobe echo  [--listen IP:PORT]
  gtpuprobe probe --interface IFACE --src-ip IP --dst-ip IP --dst-mac MAC
                  [--ue-ip IP] [--remote-ip IP] [--echo-port PORT]
                  [--flows TEID:QFI:CLASS,...] [--dl-teid N]
                  [--pps N] [--duration D] [--grace D] [--json-out FILE]`)
}

func runEcho(args []string) error {
	fs := flag.NewFlagSet("echo", flag.ContinueOnError)
	listen := fs.String("listen", "192.168.113.21:9000", "UDP echo listen address")
	if err := fs.Parse(args); err != nil {
		return err
	}
	conn, err := net.ListenPacket("udp4", *listen)
	if err != nil {
		return fmt.Errorf("listen UDP echo: %w", err)
	}
	defer conn.Close()
	fmt.Printf("UDP echo listening on %s\n", *listen)
	buf := make([]byte, 2048)
	for {
		n, addr, err := conn.ReadFrom(buf)
		if err != nil {
			return err
		}
		if _, err := conn.WriteTo(buf[:n], addr); err != nil {
			return err
		}
	}
}

func runProbe(args []string) error {
	fs := flag.NewFlagSet("probe", flag.ContinueOnError)
	ifaceName := fs.String("interface", "", "physical Ethernet interface")
	srcIPText := fs.String("src-ip", "192.168.113.20", "outer IPv4 source")
	dstIPText := fs.String("dst-ip", "192.168.113.21", "outer IPv4 destination")
	dstMACText := fs.String("dst-mac", "", "UPF Ethernet MAC")
	ueIPText := fs.String("ue-ip", "10.60.0.1", "inner UE IPv4 source")
	remoteIPText := fs.String("remote-ip", "192.168.113.21", "inner echo-server IPv4 destination")
	flowsText := fs.String("flows", "1:7:1,1:8:2,1:8:2,1:9:3", "TEID:QFI:CLASS entries")
	dlTEID := fs.Uint("dl-teid", 2, "expected downlink TEID")
	echoPort := fs.Uint("echo-port", 9000, "inner UDP echo destination port")
	pps := fs.Uint64("pps", 10000, "total offered packet rate across all flows")
	duration := fs.Duration("duration", 30*time.Second, "send duration")
	grace := fs.Duration("grace", 2*time.Second, "receive grace period after sending")
	jsonOut := fs.String("json-out", "", "write JSON summary to this file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *ifaceName == "" || *dstMACText == "" {
		return errors.New("--interface and --dst-mac are required")
	}
	if *pps == 0 || *duration <= 0 || *echoPort == 0 || *echoPort > 65535 || *dlTEID == 0 {
		return errors.New("pps, duration, echo-port, and dl-teid must be positive")
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
		return fmt.Errorf("%s has no Ethernet MAC", *ifaceName)
	}

	sendFD, err := packetSocket(iface.Index, false)
	if err != nil {
		return err
	}
	defer syscall.Close(sendFD)
	recvFD, err := packetSocket(iface.Index, true)
	if err != nil {
		return err
	}
	defer syscall.Close(recvFD)
	addr := &syscall.SockaddrLinklayer{Protocol: htons(etherTypeIPv4), Ifindex: iface.Index, Halen: 6}
	copy(addr.Addr[:], dstMAC)

	frames := make([][]byte, len(flows))
	payloadOffsets := make([]int, len(flows))
	for idx, flow := range flows {
		frames[idx], payloadOffsets[idx] = buildULFrame(iface.HardwareAddr, dstMAC, srcIP, dstIP, ueIP, remoteIP, uint16(*echoPort), flow, uint16(30000+idx))
	}
	state := &receiveState{seen: make(map[uint64]struct{}), latencies: make([][]int64, len(flows))}
	receiveUntil := time.Now().Add(*duration + *grace + time.Second)
	done := make(chan struct{})
	go receiveLoop(recvFD, dstIP, uint32(*dlTEID), receiveUntil, state, done)

	started := time.Now()
	deadline := started.Add(*duration)
	interval := time.Second / time.Duration(*pps)
	next := started
	sent := make([]uint64, len(flows))
	var seq uint64
	for time.Now().Before(deadline) {
		idx := int(seq % uint64(len(flows)))
		now := time.Now()
		writeProbePayload(frames[idx][payloadOffsets[idx]:], seq, now.UnixNano(), uint32(idx))
		if err := syscall.Sendto(sendFD, frames[idx], 0, addr); err != nil {
			return fmt.Errorf("send sequence %d: %w", seq, err)
		}
		sent[idx]++
		seq++
		next = next.Add(interval)
		waitUntil(next)
	}
	elapsed := time.Since(started)
	time.Sleep(*grace)
	syscall.Close(recvFD)
	<-done

	result := summarize(started, elapsed, *pps, flows, sent, state)
	printResult(result)
	if *jsonOut != "" {
		data, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			return err
		}
		if err := os.WriteFile(*jsonOut, append(data, '\n'), 0o644); err != nil {
			return err
		}
	}
	return nil
}

func packetSocket(ifindex int, nonblock bool) (int, error) {
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(etherTypeIPv4)))
	if err != nil {
		return -1, fmt.Errorf("open AF_PACKET socket: %w", err)
	}
	if err := syscall.Bind(fd, &syscall.SockaddrLinklayer{Protocol: htons(etherTypeIPv4), Ifindex: ifindex}); err != nil {
		syscall.Close(fd)
		return -1, fmt.Errorf("bind AF_PACKET socket: %w", err)
	}
	if nonblock {
		if err := syscall.SetNonblock(fd, true); err != nil {
			syscall.Close(fd)
			return -1, err
		}
	}
	return fd, nil
}

func receiveLoop(fd int, upfIP net.IP, dlTEID uint32, deadline time.Time, state *receiveState, done chan<- struct{}) {
	defer close(done)
	buf := make([]byte, 4096)
	for time.Now().Before(deadline) {
		n, _, err := syscall.Recvfrom(fd, buf, 0)
		if err != nil {
			if errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.EWOULDBLOCK) {
				time.Sleep(50 * time.Microsecond)
				continue
			}
			return
		}
		seq, sentNS, flowIdx, ok := parseDownlinkProbe(buf[:n], upfIP, dlTEID)
		if !ok || int(flowIdx) >= len(state.latencies) {
			continue
		}
		latency := time.Now().UnixNano() - sentNS
		if latency < 0 {
			continue
		}
		state.mu.Lock()
		if _, duplicate := state.seen[seq]; !duplicate {
			state.seen[seq] = struct{}{}
			state.latencies[flowIdx] = append(state.latencies[flowIdx], latency)
		}
		state.mu.Unlock()
	}
}

func parseDownlinkProbe(frame []byte, upfIP net.IP, dlTEID uint32) (uint64, int64, uint32, bool) {
	if len(frame) < 14+20+8+8 || binary.BigEndian.Uint16(frame[12:14]) != etherTypeIPv4 {
		return 0, 0, 0, false
	}
	outer := 14
	ihl := int(frame[outer]&0x0f) * 4
	if ihl < 20 || len(frame) < outer+ihl+8 || frame[outer+9] != syscall.IPPROTO_UDP || !net.IP(frame[outer+12:outer+16]).Equal(upfIP) {
		return 0, 0, 0, false
	}
	udp := outer + ihl
	if binary.BigEndian.Uint16(frame[udp:udp+2]) != gtpuPort && binary.BigEndian.Uint16(frame[udp+2:udp+4]) != gtpuPort {
		return 0, 0, 0, false
	}
	gtp := udp + 8
	if len(frame) < gtp+8 || frame[gtp+1] != 0xff || binary.BigEndian.Uint32(frame[gtp+4:gtp+8]) != dlTEID {
		return 0, 0, 0, false
	}
	inner := gtpPayloadOffset(frame, gtp)
	if inner < 0 || len(frame) < inner+20 {
		return 0, 0, 0, false
	}
	innerIHL := int(frame[inner]&0x0f) * 4
	if innerIHL < 20 || len(frame) < inner+innerIHL+8 || frame[inner+9] != syscall.IPPROTO_UDP {
		return 0, 0, 0, false
	}
	payload := inner + innerIHL + 8
	if len(frame) < payload+probeSize || string(frame[payload:payload+8]) != probeMagic {
		return 0, 0, 0, false
	}
	return binary.BigEndian.Uint64(frame[payload+8 : payload+16]), int64(binary.BigEndian.Uint64(frame[payload+16 : payload+24])), binary.BigEndian.Uint32(frame[payload+24 : payload+28]), true
}

func gtpPayloadOffset(frame []byte, gtp int) int {
	flags := frame[gtp]
	cursor := gtp + 8
	if flags&0x07 == 0 {
		return cursor
	}
	if len(frame) < cursor+4 {
		return -1
	}
	nextExt := frame[cursor+3]
	cursor += 4
	if flags&0x04 == 0 {
		return cursor
	}
	for nextExt != 0 {
		if len(frame) <= cursor {
			return -1
		}
		length := int(frame[cursor]) * 4
		if length < 4 || len(frame) < cursor+length {
			return -1
		}
		nextExt = frame[cursor+length-1]
		cursor += length
	}
	return cursor
}

func buildULFrame(srcMAC, dstMAC net.HardwareAddr, srcIP, dstIP, ueIP, remoteIP net.IP, echoPort uint16, flow flowSpec, sourcePort uint16) ([]byte, int) {
	innerLength := 20 + 8 + probeSize
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
	ip[8], ip[9] = 64, syscall.IPPROTO_UDP
	copy(ip[12:16], srcIP)
	copy(ip[16:20], dstIP)
	binary.BigEndian.PutUint16(ip[10:12], checksum(ip))
	udp := frame[34:42]
	binary.BigEndian.PutUint16(udp[0:2], sourcePort)
	binary.BigEndian.PutUint16(udp[2:4], gtpuPort)
	binary.BigEndian.PutUint16(udp[4:6], uint16(udpLength))
	gtp := frame[42:]
	gtp[0], gtp[1] = 0x34, 0xff
	binary.BigEndian.PutUint16(gtp[2:4], uint16(gtpLength))
	binary.BigEndian.PutUint32(gtp[4:8], flow.TEID)
	gtp[11], gtp[12], gtp[14] = 0x85, 1, flow.QFI&0x3f
	innerIP := gtp[16:36]
	innerIP[0] = 0x45
	binary.BigEndian.PutUint16(innerIP[2:4], uint16(innerLength))
	innerIP[8], innerIP[9] = 64, syscall.IPPROTO_UDP
	copy(innerIP[12:16], ueIP)
	copy(innerIP[16:20], remoteIP)
	binary.BigEndian.PutUint16(innerIP[10:12], checksum(innerIP))
	innerUDP := gtp[36:44]
	binary.BigEndian.PutUint16(innerUDP[0:2], uint16(6000)+uint16(flow.QFI)+sourcePort%16)
	binary.BigEndian.PutUint16(innerUDP[2:4], echoPort)
	binary.BigEndian.PutUint16(innerUDP[4:6], uint16(8+probeSize))
	return frame, 42 + 44
}

func writeProbePayload(payload []byte, seq uint64, sentNS int64, flowIdx uint32) {
	copy(payload[:8], probeMagic)
	binary.BigEndian.PutUint64(payload[8:16], seq)
	binary.BigEndian.PutUint64(payload[16:24], uint64(sentNS))
	binary.BigEndian.PutUint32(payload[24:28], flowIdx)
}

func waitUntil(target time.Time) {
	for {
		remaining := time.Until(target)
		if remaining <= 0 {
			return
		}
		if remaining > 200*time.Microsecond {
			time.Sleep(remaining - 100*time.Microsecond)
		} else {
			time.Sleep(10 * time.Microsecond)
		}
	}
}

func summarize(started time.Time, elapsed time.Duration, targetPPS uint64, flows []flowSpec, sent []uint64, state *receiveState) probeResult {
	state.mu.Lock()
	defer state.mu.Unlock()
	result := probeResult{StartedAt: started.Format(time.RFC3339Nano), Duration: elapsed.Seconds(), TargetPPS: targetPPS, Flows: make([]flowResult, len(flows))}
	var all []int64
	for idx, flow := range flows {
		lat := append([]int64(nil), state.latencies[idx]...)
		stats := latencyStats(lat)
		received := uint64(len(lat))
		loss := saturatingSub(sent[idx], received)
		result.Flows[idx] = flowResult{QFI: flow.QFI, QoSClass: flow.QoSClass, Sent: sent[idx], Received: received, Loss: loss, LossPct: percent(loss, sent[idx]), MinUS: stats[0], MeanUS: stats[1], P50US: stats[2], P95US: stats[3], P99US: stats[4], MaxUS: stats[5]}
		result.Sent += sent[idx]
		result.Received += received
		all = append(all, lat...)
	}
	result.Loss = saturatingSub(result.Sent, result.Received)
	result.LossPct = percent(result.Loss, result.Sent)
	result.RatePPS = float64(result.Sent) / elapsed.Seconds()
	stats := latencyStats(all)
	result.MinUS, result.MeanUS, result.P50US, result.P95US, result.P99US, result.MaxUS = stats[0], stats[1], stats[2], stats[3], stats[4], stats[5]
	return result
}

func latencyStats(values []int64) [6]float64 {
	if len(values) == 0 {
		return [6]float64{}
	}
	sort.Slice(values, func(i, j int) bool { return values[i] < values[j] })
	var sum float64
	for _, value := range values {
		sum += float64(value)
	}
	return [6]float64{float64(values[0]) / 1e3, sum / float64(len(values)) / 1e3, percentile(values, 0.50), percentile(values, 0.95), percentile(values, 0.99), float64(values[len(values)-1]) / 1e3}
}

func percentile(values []int64, q float64) float64 {
	idx := int(math.Ceil(q*float64(len(values)))) - 1
	if idx < 0 {
		idx = 0
	}
	return float64(values[idx]) / 1e3
}

func printResult(r probeResult) {
	fmt.Printf("sent=%d received=%d loss=%d loss=%.4f%% actual_pps=%.1f\n", r.Sent, r.Received, r.Loss, r.LossPct, r.RatePPS)
	fmt.Printf("rtt_us min=%.1f mean=%.1f p50=%.1f p95=%.1f p99=%.1f max=%.1f\n", r.MinUS, r.MeanUS, r.P50US, r.P95US, r.P99US, r.MaxUS)
	for _, flow := range r.Flows {
		fmt.Printf("qfi=%d class=%d sent=%d received=%d loss=%.4f%% p50_us=%.1f p95_us=%.1f p99_us=%.1f\n", flow.QFI, flow.QoSClass, flow.Sent, flow.Received, flow.LossPct, flow.P50US, flow.P95US, flow.P99US)
	}
}

func saturatingSub(a, b uint64) uint64 {
	if b >= a {
		return 0
	}
	return a - b
}

func percent(value, total uint64) float64 {
	if total == 0 {
		return 0
	}
	return float64(value) * 100 / float64(total)
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
		teid, err := strconv.ParseUint(parts[0], 0, 32)
		if err != nil || teid == 0 {
			return nil, fmt.Errorf("invalid TEID in %q", item)
		}
		qfi, err := strconv.ParseUint(parts[1], 0, 8)
		if err != nil || qfi == 0 || qfi > 63 {
			return nil, fmt.Errorf("invalid QFI in %q", item)
		}
		class, err := strconv.ParseUint(parts[2], 0, 32)
		if err != nil || class < 1 || class > 3 {
			return nil, fmt.Errorf("invalid class in %q", item)
		}
		flows = append(flows, flowSpec{TEID: uint32(teid), QFI: uint8(qfi), QoSClass: uint32(class)})
	}
	return flows, nil
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

func htons(value uint16) uint16 { return value<<8 | value>>8 }
