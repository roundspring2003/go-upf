package rules

// QoS policies contain only derived binding/marking data. PFCP Session and
// RuleState remain the owners of PDR/QER configurations and their update semantics.
type Direction string

const (
	Unknown  Direction = "unknown"
	Uplink   Direction = "UL"
	Downlink Direction = "DL"
)

type PDRKey struct {
	SEID  uint64
	PDRID uint16
}

// Target is explicitly supplied by deployment policy, never inferred from QFI.
// Egress may be known before Slice/ClassID; MissingTarget then remains on Policy.
type Target struct {
	Egress  string
	Slice   string
	ClassID uint32
}

type Diagnostic struct {
	Code   string
	PDR    PDRKey
	QERID  *uint32
	Detail string
}

const (
	UnsupportedPath = "UnsupportedPath"
	MissingTarget   = "MissingTarget"
)

type Policy struct {
	Key         PDRKey
	ID          uint32 // manager-local packet policy ID; unrelated to QFI or QER ID
	Direction   Direction
	Target      *Target
	QFI         *uint8
	QFISources  map[uint32]uint8 // QER ID to QFI
	Rates       []QoSRate        // Directional QER constraints, collected with QFI in one traversal.
	Diagnostics []Diagnostic
}

// QoSRate keeps the QER identity: different PDRs referencing this QER must
// share its rate budget within the session and direction.
type QoSRate struct {
	QERID  uint32
	MBRBps uint64
	GBRBps uint64
}

func (p Policy) GBR() uint64 {
	var rate uint64
	for _, r := range p.Rates {
		if r.GBRBps > rate {
			rate = r.GBRBps
		}
	}
	return rate
}

func (p Policy) MBR() uint64 {
	var rate uint64
	for _, r := range p.Rates {
		if r.MBRBps != 0 && (rate == 0 || r.MBRBps < rate) {
			rate = r.MBRBps
		}
	}
	return rate
}
