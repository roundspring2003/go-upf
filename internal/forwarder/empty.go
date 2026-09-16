package forwarder

import (
	"github.com/free5gc/go-gtp5gnl"
	"github.com/free5gc/go-upf/internal/report"
	"github.com/khirono/go-nl"
)

type Empty struct{}

func (Empty) Close() {
}

func (Empty) QueryURR(uint64, uint32) ([]report.USAReport, error) {
	return nil, nil
}

func (Empty) HandleReport(report.Handler) {
}

// Plan-based methods for two-phase commit

func (Empty) executeModificationPlan(plan *modificationPlan) (*executionResult, error) {
	return newSuccessfulExecutionResult(plan), nil
}

func (Empty) executeEstablishmentPlan(plan *modificationPlan) (*executionResult, error) {
	return newSuccessfulExecutionResult(plan), nil
}

func (Empty) updateFlowQoS(gtp5gnl.OID, nl.Attr) error { return nil }
