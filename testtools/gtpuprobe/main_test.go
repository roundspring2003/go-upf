package main

import (
	"encoding/binary"
	"net"
	"testing"
)

func TestProbePayloadRoundTrip(t *testing.T) {
	payload := make([]byte, probeSize)
	writeProbePayload(payload, 42, 123456789, 2)
	frame := buildTestDownlink(payload, 2)
	seq, sentNS, flow, ok := parseDownlinkProbe(frame, net.ParseIP("192.168.113.21").To4(), 2)
	if !ok || seq != 42 || sentNS != 123456789 || flow != 2 {
		t.Fatalf("parsed=(%d,%d,%d,%t)", seq, sentNS, flow, ok)
	}
}

func TestLatencyStats(t *testing.T) {
	stats := latencyStats([]int64{1000, 2000, 3000, 4000, 100000})
	if stats[2] != 3 || stats[3] != 100 || stats[4] != 100 {
		t.Fatalf("p50/p95/p99 = %.1f/%.1f/%.1f us", stats[2], stats[3], stats[4])
	}
}

func buildTestDownlink(payload []byte, teid uint32) []byte {
	innerLength := 20 + 8 + len(payload)
	outerLength := 20 + 8 + 8 + innerLength
	frame := make([]byte, 14+outerLength)
	binary.BigEndian.PutUint16(frame[12:14], etherTypeIPv4)
	outer := frame[14:34]
	outer[0], outer[8], outer[9] = 0x45, 64, 17
	binary.BigEndian.PutUint16(outer[2:4], uint16(outerLength))
	copy(outer[12:16], net.ParseIP("192.168.113.21").To4())
	copy(outer[16:20], net.ParseIP("192.168.113.20").To4())
	udp := frame[34:42]
	binary.BigEndian.PutUint16(udp[0:2], gtpuPort)
	binary.BigEndian.PutUint16(udp[2:4], gtpuPort)
	gtp := frame[42:50]
	gtp[0], gtp[1] = 0x30, 0xff
	binary.BigEndian.PutUint32(gtp[4:8], teid)
	inner := frame[50:70]
	inner[0], inner[8], inner[9] = 0x45, 64, 17
	binary.BigEndian.PutUint16(inner[2:4], uint16(innerLength))
	copy(inner[12:16], net.ParseIP("192.168.113.21").To4())
	copy(inner[16:20], net.ParseIP("10.60.0.1").To4())
	innerUDP := frame[70:78]
	binary.BigEndian.PutUint16(innerUDP[0:2], 9000)
	binary.BigEndian.PutUint16(innerUDP[2:4], 6007)
	copy(frame[78:], payload)
	return frame
}
