package tc

import (
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
)

// Offsets are the stable __sk_buff UAPI, not struct sk_buff offsets.
const skbTstamp = 152
const skbTstampType = 180

func addEDT(spec *ebpf.CollectionSpec, horizonMS uint32) {
	u32 := &btf.Int{Name: "__u32", Size: 4}
	u64 := &btf.Int{Name: "__u64", Size: 8}
	lock := &btf.Struct{Name: "bpf_spin_lock", Size: 4, Members: []btf.Member{{Name: "val", Type: u32}}}
	runtime := &btf.Struct{Name: "qos_runtime_value", Size: 8 + 8*maxSessionRates, Members: []btf.Member{
		{Name: "lock", Type: lock}, {Name: "pad", Type: u32, Offset: 32},
		{Name: "next", Type: &btf.Array{Index: u32, Type: u64, Nelems: maxSessionRates}, Offset: 64},
	}}
	spec.Maps["qos_runtime"] = &ebpf.MapSpec{Name: "qos_runtime", Type: ebpf.Hash, KeySize: 16, ValueSize: 8 + 8*maxSessionRates, MaxEntries: 65536, Flags: 1, Key: &btf.Array{Index: u32, Type: u64, Nelems: 2}, Value: runtime}
	spec.Maps["qos_rate_policy"] = &ebpf.MapSpec{Name: "qos_rate_policy", Type: ebpf.Hash, KeySize: 4, ValueSize: 16 + 16*MaxPolicyRates, MaxEntries: 65536}
	// Reasons: missing config/runtime, horizon, unsupported timestamp protocol.
	spec.Maps["qos_drops"] = &ebpf.MapSpec{Name: "qos_drops", Type: ebpf.PerCPUHash, KeySize: 4, ValueSize: 24, MaxEntries: 65536}
	ins := spec.Programs["qos_egress"].Instructions
	// Insert before the existing normal return; all accepted packets have already
	// been classified and counted. Unmarked/missing-policy traffic goes straight
	// to the HTB fallback, while classified EDT policies fail closed on state loss.
	index := 0
	for i, in := range ins {
		if in.Symbol() == "done" {
			index = i
			break
		}
	}
	// A missing observation counter must never bypass rate enforcement.
	for n := index - 1; n >= 0; n-- {
		if ins[n].Reference() == "done" {
			ins[n] = asm.JEq.Imm(asm.R0, 0, "edt_start")
			break
		}
	}
	// Redirect only the successful stats path into EDT. Earlier "done" branches
	// retain the original fallback behavior.
	prefix := append(asm.Instructions{}, ins[:index]...)
	prefix = append(prefix, edtInstructions(horizonMS)...)
	spec.Programs["qos_egress"].Instructions = append(prefix, ins[index:]...)
}

// EDT uses a session/direction lock so all applicable QER clocks are reserved
// atomically across CPUs and PDRs. Sequential independent reservations would
// allow a later constraint to bunch packets beyond another QER's cap.
// This implements upper bounds, not a proof of per-flow GBR service.
func edtInstructions(horizonMS uint32) asm.Instructions {
	i := asm.Instructions{
		asm.LoadMapPtr(asm.R1, 0).WithReference("qos_rate_policy").WithSymbol("edt_start"),
		asm.Mov.Reg(asm.R2, asm.RFP), asm.Add.Imm(asm.R2, -4), asm.FnMapLookupElem.Call(),
		asm.JEq.Imm(asm.R0, 0, "edt_missing"), asm.Mov.Reg(asm.R8, asm.R0),
		asm.LoadMem(asm.R1, asm.R8, 16, asm.DWord), asm.JEq.Imm(asm.R1, 0, "done"),
		// Also bound the byte/time product for unusually large GSO skbs.
		asm.LoadMem(asm.R1, asm.R6, skbLen, asm.Word), asm.JGT.Imm(asm.R1, 1<<20, "edt_horizon"),
		asm.LoadMapPtr(asm.R1, 0).WithReference("qos_runtime"), asm.Mov.Reg(asm.R2, asm.R8), asm.FnMapLookupElem.Call(),
		asm.JEq.Imm(asm.R0, 0, "edt_missing"), asm.Mov.Reg(asm.R7, asm.R0),
		asm.FnKtimeGetNs.Call(), asm.Mov.Reg(asm.R9, asm.R0),
		asm.LoadImm(asm.R1, int64(horizonMS)*1_000_000, asm.DWord), asm.Add.Reg(asm.R1, asm.R0), asm.StoreMem(asm.RFP, -24, asm.R1, asm.DWord),
		// Honor an existing monotonic EDT, never interpret a receive timestamp as EDT.
		asm.LoadMem(asm.R1, asm.R6, skbTstampType, asm.Byte), asm.JNE.Imm(asm.R1, 1, "edt_lock"),
		asm.LoadMem(asm.R1, asm.R6, skbTstamp, asm.DWord), asm.JLE.Reg(asm.R1, asm.R9, "edt_lock"), asm.Mov.Reg(asm.R9, asm.R1),
		asm.Mov.Reg(asm.R1, asm.R7).WithSymbol("edt_lock"), asm.FnSpinLock.Call(),
	}
	for n := 0; n < MaxPolicyRates; n++ {
		next := fmt.Sprintf("edt_max_%d", n)
		off := int16(16 + 16*n)
		i = append(i,
			asm.LoadMem(asm.R1, asm.R8, off, asm.DWord), asm.JEq.Imm(asm.R1, 0, next),
			asm.LoadMem(asm.R2, asm.R8, off+8, asm.Word), asm.JGE.Imm(asm.R2, maxSessionRates, "edt_unlock_missing"),
			asm.LSh.Imm(asm.R2, 3), asm.Add.Reg(asm.R2, asm.R7), asm.LoadMem(asm.R3, asm.R2, 8, asm.DWord),
			asm.JLE.Reg(asm.R3, asm.R9, next), asm.Mov.Reg(asm.R9, asm.R3), asm.Mov.Reg(asm.R9, asm.R9).WithSymbol(next))
	}
	i = append(i, asm.LoadMem(asm.R1, asm.RFP, -24, asm.DWord), asm.JGT.Reg(asm.R9, asm.R1, "edt_unlock_horizon"))
	for n := 0; n < MaxPolicyRates; n++ {
		next := fmt.Sprintf("edt_set_%d", n)
		off := int16(16 + 16*n)
		i = append(i,
			asm.LoadMem(asm.R1, asm.R8, off, asm.DWord), asm.JEq.Imm(asm.R1, 0, next),
			asm.LoadMem(asm.R2, asm.R8, off+8, asm.Word), asm.JGE.Imm(asm.R2, maxSessionRates, "edt_unlock_missing"),
			asm.LSh.Imm(asm.R2, 3), asm.Add.Reg(asm.R2, asm.R7),
			// Conservative egress skb-byte accounting, including encapsulation. Round
			// serialization time up; the byte bound above keeps the product within u64.
			asm.LoadMem(asm.R3, asm.R6, skbLen, asm.Word), asm.LoadImm(asm.R4, 8_000_000_000, asm.DWord), asm.Mul.Reg(asm.R3, asm.R4),
			asm.Add.Reg(asm.R3, asm.R1), asm.Sub.Imm(asm.R3, 1), asm.Div.Reg(asm.R3, asm.R1), asm.Add.Reg(asm.R3, asm.R9),
			asm.StoreMem(asm.R2, 8, asm.R3, asm.DWord), asm.Mov.Reg(asm.R9, asm.R9).WithSymbol(next))
	}
	i = append(i,
		asm.Mov.Reg(asm.R1, asm.R7), asm.FnSpinUnlock.Call(),
		asm.Mov.Reg(asm.R1, asm.R6), asm.Mov.Reg(asm.R2, asm.R9), asm.Mov.Imm(asm.R3, 1), asm.FnSkbSetTstamp.Call(),
		asm.JNE.Imm(asm.R0, 0, "edt_tstamp"), asm.Ja.Label("done"),
		asm.Mov.Reg(asm.R1, asm.R7).WithSymbol("edt_unlock_missing"), asm.FnSpinUnlock.Call(), asm.Ja.Label("edt_missing"),
		asm.Mov.Reg(asm.R1, asm.R7).WithSymbol("edt_unlock_horizon"), asm.FnSpinUnlock.Call(),
		asm.Mov.Imm(asm.R9, 8).WithSymbol("edt_horizon"), asm.Ja.Label("edt_drop"),
		asm.Mov.Imm(asm.R9, 16).WithSymbol("edt_tstamp"), asm.Ja.Label("edt_drop"),
		asm.Mov.Imm(asm.R9, 0).WithSymbol("edt_missing"),
		asm.LoadMapPtr(asm.R1, 0).WithReference("qos_drops").WithSymbol("edt_drop"), asm.Mov.Reg(asm.R2, asm.RFP), asm.Add.Imm(asm.R2, -4), asm.FnMapLookupElem.Call(),
		asm.JEq.Imm(asm.R0, 0, "edt_drop_return"), asm.Add.Reg(asm.R0, asm.R9), asm.LoadMem(asm.R1, asm.R0, 0, asm.DWord), asm.Add.Imm(asm.R1, 1), asm.StoreMem(asm.R0, 0, asm.R1, asm.DWord),
		asm.Mov.Imm(asm.R0, 2).WithSymbol("edt_drop_return"), asm.Return(),
	)
	return i
}
