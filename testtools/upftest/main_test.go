package main

import "testing"

func TestParseQoSFlows(t *testing.T) {
	flows, err := parseQoSFlows("7:1,8:2,9:3", 1, 1, 5000, 6000)
	if err != nil {
		t.Fatalf("parseQoSFlows() error = %v", err)
	}
	if len(flows) != 3 {
		t.Fatalf("len(flows) = %d, want 3", len(flows))
	}
	wantQFI := []uint8{7, 8, 9}
	wantClass := []uint32{qosClassLatencySensitive, qosClassStandard, qosClassBackground}
	for idx, flow := range flows {
		if flow.QERID != uint32(idx+1) {
			t.Errorf("flows[%d].QERID = %d, want %d", idx, flow.QERID, idx+1)
		}
		if flow.QFI != wantQFI[idx] {
			t.Errorf("flows[%d].QFI = %d, want %d", idx, flow.QFI, wantQFI[idx])
		}
		if flow.QoSClass != wantClass[idx] {
			t.Errorf("flows[%d].QoSClass = %d, want %d", idx, flow.QoSClass, wantClass[idx])
		}
		if flow.RemotePort != uint16(5000+idx) {
			t.Errorf("flows[%d].RemotePort = %d, want %d", idx, flow.RemotePort, 5000+idx)
		}
		if flow.UEPort != uint16(6000+idx) {
			t.Errorf("flows[%d].UEPort = %d, want %d", idx, flow.UEPort, 6000+idx)
		}
	}
}

func TestParseQoSFlowsRejectsDuplicateQFI(t *testing.T) {
	_, err := parseQoSFlows("7:1,7:2", 1, 1, 5000, 6000)
	if err == nil {
		t.Fatal("parseQoSFlows() error = nil, want duplicate QFI error")
	}
}
