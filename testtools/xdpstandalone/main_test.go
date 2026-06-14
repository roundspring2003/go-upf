package main

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
)

func TestBuildPoolsFourDataPlaneCPUs(t *testing.T) {
	pools, err := buildPools(20, 16)
	if err != nil {
		t.Fatal(err)
	}

	assertPool(t, pools[3], 16, 1)
	assertPool(t, pools[1], 17, 1)
	assertPool(t, pools[2], 18, 2)
}

func TestOnlineCPUCount(t *testing.T) {
	count, err := onlineCPUCount()
	if err != nil {
		t.Fatal(err)
	}
	if count < 1 {
		t.Fatalf("online CPU count = %d", count)
	}
}

func TestBuildULFrameMatchesXDPParserLayout(t *testing.T) {
	flow := flowSpec{TEID: 0x10203040, QFI: 7, QoSClass: 1}
	srcMAC := net.HardwareAddr{0, 1, 2, 3, 4, 5}
	dstMAC := net.HardwareAddr{6, 7, 8, 9, 10, 11}
	srcIP := net.ParseIP("192.168.113.20").To4()
	dstIP := net.ParseIP("192.168.113.21").To4()
	frame := buildULFrame(srcMAC, dstMAC, srcIP, dstIP, net.ParseIP("10.60.0.1").To4(), net.ParseIP("1.1.1.1").To4(), flow, 30007, 0)

	if got := net.HardwareAddr(frame[0:6]); !bytes.Equal(got, dstMAC) {
		t.Fatalf("destination MAC = %s", got)
	}
	if got := net.IP(frame[26:30]); !got.Equal(srcIP) {
		t.Fatalf("outer source IP = %s", got)
	}
	if got := net.IP(frame[30:34]); !got.Equal(dstIP) {
		t.Fatalf("outer destination IP = %s", got)
	}
	if got := binary.BigEndian.Uint16(frame[12:14]); got != etherTypeIPv4 {
		t.Fatalf("EtherType = %#x", got)
	}
	if got := frame[23]; got != 17 {
		t.Fatalf("IP protocol = %d", got)
	}
	if got := binary.BigEndian.Uint16(frame[36:38]); got != gtpuPort {
		t.Fatalf("UDP destination = %d", got)
	}
	if got := frame[42]; got != 0x34 {
		t.Fatalf("GTP flags = %#x", got)
	}
	if got := frame[43]; got != 0xff {
		t.Fatalf("GTP message type = %#x", got)
	}
	if got := binary.BigEndian.Uint32(frame[46:50]); got != flow.TEID {
		t.Fatalf("TEID = %#x", got)
	}
	if got := frame[53]; got != 0x85 {
		t.Fatalf("next extension type = %#x", got)
	}
	if got := frame[56] & 0x3f; got != flow.QFI {
		t.Fatalf("QFI = %d", got)
	}
}

func TestBuildULFrameVariantChangesInnerFlow(t *testing.T) {
	flow := flowSpec{TEID: 1, QFI: 8, QoSClass: 2}
	srcMAC := net.HardwareAddr{0, 1, 2, 3, 4, 5}
	dstMAC := net.HardwareAddr{6, 7, 8, 9, 10, 11}
	srcIP := net.ParseIP("192.168.113.20").To4()
	dstIP := net.ParseIP("192.168.113.21").To4()
	ueIP := net.ParseIP("10.60.0.1").To4()
	remoteIP := net.ParseIP("1.1.1.1").To4()
	first := buildULFrame(srcMAC, dstMAC, srcIP, dstIP, ueIP, remoteIP, flow, 30008, 0)
	second := buildULFrame(srcMAC, dstMAC, srcIP, dstIP, ueIP, remoteIP, flow, 30008, 1)

	firstPort := binary.BigEndian.Uint16(first[80:82])
	secondPort := binary.BigEndian.Uint16(second[80:82])
	if secondPort != firstPort+1 {
		t.Fatalf("inner destination ports = %d and %d", firstPort, secondPort)
	}
}

func assertPool(t *testing.T, got cpuPool, start, count uint32) {
	t.Helper()
	if got.StartCPU != start || got.CPUCount != count {
		t.Fatalf("pool = %+v, want start=%d count=%d", got, start, count)
	}
}
