// qos-experiment prepares fixed startup budgets for a three-mode comparison.
// It writes configurations only; the lab restarts UPF and establishes fresh
// PFCP sessions with the matching SMF policy before sending traffic each round.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	qosconfig "github.com/free5gc/go-upf/internal/qos_manager/config"
	"github.com/free5gc/go-upf/pkg/factory"
	"gopkg.in/yaml.v2"
)

type flow struct {
	Session  string `json:"session"`
	QFI      uint8  `json:"qfi"`
	GBRULBps uint64 `json:"gbrULBps"`
	GBRDLBps uint64 `json:"gbrDLBps"`
}

type scenario struct {
	CapacityBps uint64 `json:"capacityBps"`
	FallbackBps uint64 `json:"fallbackBps"`
	Flows       []flow `json:"flows"`
}

type roundPlan struct {
	Scenario    scenario              `json:"scenario"`
	UniqueFlows int                   `json:"uniqueFlows"`
	N3Egress    string                `json:"n3Egress"`
	N6Egress    string                `json:"n6Egress"`
	Uplink      qosconfig.ClassBudget `json:"uplink"`
	Downlink    qosconfig.ClassBudget `json:"downlink"`
}

func calculate(s scenario) (roundPlan, error) {
	plan := roundPlan{Scenario: s}
	if s.CapacityBps < 1000 || s.CapacityBps > 1_000_000_000_000 ||
		s.FallbackBps == 0 || s.FallbackBps >= s.CapacityBps {
		return plan, fmt.Errorf("specify capacityBps (1000..1000000000000) and a positive fallbackBps smaller than capacity")
	}
	if len(s.Flows) == 0 {
		return plan, fmt.Errorf("specify the round's QoS flows")
	}
	type flowKey struct {
		session string
		qfi     uint8
	}
	seen := make(map[flowKey]flow)
	available := s.CapacityBps - s.FallbackBps
	for _, f := range s.Flows {
		if f.Session == "" || f.QFI == 0 || f.QFI > 63 {
			return plan, fmt.Errorf("each flow needs a session label and QFI in 1..63")
		}
		key := flowKey{f.Session, f.QFI}
		if previous, ok := seen[key]; ok {
			if previous != f {
				return plan, fmt.Errorf("conflicting GBR values for session %q QFI %d", f.Session, f.QFI)
			}
			continue // Multiple PDRs must not reserve the same QoS flow twice.
		}
		// Check before adding, including integer overflow and room for BE.
		if f.GBRULBps >= available-plan.Uplink.GBRBps || f.GBRDLBps >= available-plan.Downlink.GBRBps {
			return plan, fmt.Errorf("GBR sum plus fallback must leave a positive BE budget in both directions")
		}
		seen[key] = f
		plan.Uplink.GBRBps += f.GBRULBps
		plan.Downlink.GBRBps += f.GBRDLBps
	}
	plan.UniqueFlows = len(seen)
	plan.Uplink.FallbackBps, plan.Downlink.FallbackBps = s.FallbackBps, s.FallbackBps
	plan.Uplink.BEBps = available - plan.Uplink.GBRBps
	plan.Downlink.BEBps = available - plan.Downlink.GBRBps
	return plan, nil
}

func prepare(base []byte, s scenario) (map[string][]byte, roundPlan, error) {
	plan, err := calculate(s)
	if err != nil {
		return nil, plan, err
	}
	var document map[interface{}]interface{}
	if err := yaml.UnmarshalStrict(base, &document); err != nil {
		return nil, plan, err
	}
	qos, ok := document["qos"].(map[interface{}]interface{})
	if !ok {
		return nil, plan, fmt.Errorf("base UPF configuration must contain qos.n3Egress and qos.n6Egress")
	}
	qosBytes, err := yaml.Marshal(qos)
	if err != nil {
		return nil, plan, err
	}
	var deployment factory.QoS
	if err := yaml.UnmarshalStrict(qosBytes, &deployment); err != nil {
		return nil, plan, err
	}
	plan.N3Egress, plan.N6Egress = deployment.N3Egress, deployment.N6Egress
	if plan.N3Egress == "" || plan.N6Egress == "" || plan.N3Egress == plan.N6Egress {
		return nil, plan, fmt.Errorf("this experiment requires distinct N3 and N6 egress interfaces for directional budgets")
	}
	cfg := qosconfig.Config{
		CapacityBps: s.CapacityBps,
		HorizonMS:   deployment.HorizonMS,
		EgressBudgets: map[string]qosconfig.ClassBudget{
			plan.N6Egress: plan.Uplink,
			plan.N3Egress: plan.Downlink,
		},
	}
	cfg, err = cfg.Normalize()
	if err != nil {
		return nil, plan, err
	}
	// Explicit per-egress budgets replace the legacy common service budgets.
	delete(qos, "gbrBps")
	delete(qos, "beBps")
	delete(qos, "fallbackBps")
	qos["capacityBps"] = cfg.CapacityBps
	qos["horizonMs"] = cfg.HorizonMS
	qos["egressBudgets"] = cfg.EgressBudgets
	files := make(map[string][]byte)
	for _, mode := range []qosconfig.Mode{qosconfig.PerFlowHTB, qosconfig.SharedHTB, qosconfig.SharedHTBEDT} {
		qos["mode"] = mode
		data, err := yaml.Marshal(document)
		if err != nil {
			return nil, plan, err
		}
		files[string(mode)+".yaml"] = data
	}
	data, err := json.MarshalIndent(plan, "", "  ")
	if err != nil {
		return nil, plan, err
	}
	files["round.json"] = append(data, '\n')
	return files, plan, nil
}

func run() error {
	basePath := flag.String("base", "config/upfcfg.yaml", "base UPF configuration")
	flowsPath := flag.String("flows", "", "round's flow scenario JSON (see testtools/qos-experiment/flows.example.json)")
	outDir := flag.String("out", "", "new output directory; existing directories are never overwritten")
	flag.Parse()
	if *flowsPath == "" || *outDir == "" || flag.NArg() != 0 {
		return fmt.Errorf("usage: go run ./testtools/qos-experiment -base config/upfcfg.yaml -flows SCENARIO.json -out NEW_DIRECTORY")
	}
	input, err := os.ReadFile(*flowsPath)
	if err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(input))
	decoder.DisallowUnknownFields()
	var s scenario
	if err := decoder.Decode(&s); err != nil {
		return err
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return fmt.Errorf("scenario must contain exactly one JSON object")
	}
	base, err := os.ReadFile(*basePath)
	if err != nil {
		return err
	}
	files, plan, err := prepare(base, s)
	if err != nil {
		return err
	}
	if err := os.Mkdir(*outDir, 0o755); err != nil {
		return err
	}
	for name, data := range files {
		if err := os.WriteFile(filepath.Join(*outDir, name), data, 0o600); err != nil {
			return err
		}
	}
	fmt.Printf("Prepared %d distinct QoS flows, capacity %d bit/s per direction\n", plan.UniqueFlows, s.CapacityBps)
	fmt.Printf("UL (%s): GBR=%d BE=%d fallback=%d bit/s\n", plan.N6Egress, plan.Uplink.GBRBps, plan.Uplink.BEBps, plan.Uplink.FallbackBps)
	fmt.Printf("DL (%s): GBR=%d BE=%d fallback=%d bit/s\n", plan.N3Egress, plan.Downlink.GBRBps, plan.Downlink.BEBps, plan.Downlink.FallbackBps)
	fmt.Printf("Three configurations and round.json written to %s\n", *outDir)
	fmt.Println("Before EACH mode: stop the previous run and refresh its UPF/TC/BPF/session state, start UPF with that mode's configuration, establish matching SMF rules, verify them, then send traffic.")
	return nil
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
