package tc

import (
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
)

// Stable Linux UAPI __sk_buff offsets, not kernel struct sk_buff offsets.
// Constructing the small program here avoids requiring clang at build time.
const (
	skbLen      = 0
	skbMark     = 8
	skbPriority = 32
	skbIfindex  = 40
)

func qosEgressSpec() *ebpf.CollectionSpec {
	return &ebpf.CollectionSpec{
		Maps: map[string]*ebpf.MapSpec{
			"qos_policy": {Name: "qos_policy", Type: ebpf.Hash, KeySize: 4, ValueSize: 8, MaxEntries: 65536},
			"qos_stats":  {Name: "qos_stats", Type: ebpf.PerCPUHash, KeySize: 4, ValueSize: 16, MaxEntries: 65536},
		},
		Programs: map[string]*ebpf.ProgramSpec{
			"qos_egress": {Name: "qos_egress", Type: ebpf.SchedCLS, AttachType: ebpf.AttachTCXEgress, License: "GPL",
				Instructions: asm.Instructions{
					asm.Mov.Reg(asm.R6, asm.R1),
					asm.LoadMem(asm.R2, asm.R6, skbMark, asm.Word),
					asm.And.Imm(asm.R2, 0xffffff),
					asm.JEq.Imm(asm.R2, 0, "done"),
					asm.StoreMem(asm.RFP, -4, asm.R2, asm.Word),
					asm.LoadMapPtr(asm.R1, 0).WithReference("qos_policy"),
					asm.Mov.Reg(asm.R2, asm.RFP),
					asm.Add.Imm(asm.R2, -4),
					asm.FnMapLookupElem.Call(),
					asm.JEq.Imm(asm.R0, 0, "done"),
					asm.LoadMem(asm.R2, asm.R0, 0, asm.Word),
					asm.LoadMem(asm.R3, asm.R6, skbIfindex, asm.Word),
					asm.JNE.Reg(asm.R2, asm.R3, "done"),
					asm.LoadMem(asm.R2, asm.R0, 4, asm.Word),
					asm.JEq.Imm(asm.R2, 0, "count"),
					asm.StoreMem(asm.R6, skbPriority, asm.R2, asm.Word),
					asm.LoadMapPtr(asm.R1, 0).WithReference("qos_stats").WithSymbol("count"),
					asm.Mov.Reg(asm.R2, asm.RFP),
					asm.Add.Imm(asm.R2, -4),
					asm.FnMapLookupElem.Call(),
					asm.JEq.Imm(asm.R0, 0, "done"),
					asm.LoadMem(asm.R2, asm.R0, 0, asm.DWord),
					asm.Add.Imm(asm.R2, 1),
					asm.StoreMem(asm.R0, 0, asm.R2, asm.DWord),
					asm.LoadMem(asm.R2, asm.R0, 8, asm.DWord),
					asm.LoadMem(asm.R3, asm.R6, skbLen, asm.Word),
					asm.Add.Reg(asm.R2, asm.R3),
					asm.StoreMem(asm.R0, 8, asm.R2, asm.DWord),
					// TCX_NEXT: allow subsequent classifiers; never drop or alter the mark.
					asm.Mov.Imm(asm.R0, -1).WithSymbol("done"),
					asm.Return(),
				}},
		},
	}
}
