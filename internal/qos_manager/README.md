# qos_manager

The manager uses existing PFCP RuleChangeSet and RuleState data to update
PDR policies. It stores only current policies and a local packet ID counter.
There is no Constraint graph, copied QER database, reverse reference table,
Plan/Commit/Abort API, retained snapshot or QoS rollback mechanism.

## Data

`internal/rules/qos.go` defines Policy with its PDR key, packet PolicyID,
direction, target, QER IDs, QFI summary/sources and diagnostics. QER IDs are
retained for the derived binding; complete MBR/GBR/Gate configurations remain
in the existing Session/RuleState and follow the existing forwarder path.

RuleView reuses `PDR`, `QER` and `RangePDR` from RuleState. It must contain the
complete validated result of the same request. The manager does not parse PFCP,
merge patches or revalidate references. A missing lookup reports a violated view
contract. Direction comes only from PDR Source Interface; target mapping is
explicit. QFI sources are all retained, with AmbiguousQFI when values conflict.

## Updating policies

```go
manager := qosmanager.NewManager()
// After existing validation and successful datapath application:
changed, err := manager.Apply(changes, validatedState, resolver)
policies := manager.Policies(changes.SEID)
```

- CreatePDR / UpdatePDR: look up the complete PDR by ID and build its policy.
  Editing one PDR does not refresh other users of its old/new QERs.
- RemovePDR: remove that policy. Original QERs remain owned by PFCP.
- UpdateQER containing QFI: scan the current PDR.QERIDs to refresh affected QFI
  summaries. Mixed PDR/QER changes use the final view; created policies are not
  also reported as updated.
- MBR/GBR/Gate-only UpdateQER: no policy work. These fields are not stored in a
  policy. Existing QER forwarding still handles them; a future rate backend
  must consume those original QER changes even when policy Changes is empty.
- Empty/FAR/URR requests: no policy work or rule scan.

Apply changes current memory in one call, without an external commit stage.
It finishes reads and capacity checks before editing the policy map, so a local
error does not leave half an update. This does not provide external rollback or
atomicity with the forwarder/BPF backend.

Use the existing PFCP event loop as the single owner and serialize all access.
Deliver successful requests from initial creation onward. Empty changes do not
bootstrap existing sessions. Live enablement, restart synchronization and target
remapping outside PFCP updates require explicit lifecycle work in a later step.

Policy/Policies return copies of policy slices/pointers for safe inspection;
these copies are not stored as history. Original QER configurations are never
copied into the manager. IDs occupy 1..0x00ffffff, remain stable for live PDRs,
and are not reused after removal. Exhaustion returns ErrIDExhausted.

RemoveSession deletes policies only after every session PDR is confirmed gone.
For partial cleanup, Apply only confirmed RemovePDRs with the remaining view.

## Future backend

Rate state can be keyed by (LocalSEID, QERID, Direction). PDRs referencing the
same key must use the same state across CPUs and applicable egress interfaces.
No extra Constraint ID or per-PDR copy of the shared budget is required here.
Resource creation/update/cleanup will be implemented with that backend, using
existing QER changes and references. EDT state and map layouts are not yet built.

Steps 1–4 are implemented. Production PFCP wiring calls Apply after successful
rule execution/publication and follows confirmed cleanup removals. The manager
is created at UPF startup without a mode switch. Update logs use the existing
logger at debug level. See [PFCP integration](../../docs/qos_pfcp.md) for details.
No binding, TC/BPF operation or packet pacing runs from this package.
The PFCP caller now sends policy bindings through the existing session datapath;
see [binding integration](../../docs/qos_binding.md). Egress BPF will own classid.
Deployment `qos.n3Egress` / `qos.n6Egress` settings now feed the target resolver.
The target retains a known egress while MissingTarget remains until slice/class
configuration is supplied. See [egress configuration](../../docs/qos_egress.md).
Existing forwarder rollback code is outside this change and remains unchanged.

## Verification

```sh
go test -race ./internal/rules ./internal/qos_manager ./internal/pfcp
go vet ./internal/rules ./internal/qos_manager ./internal/pfcp
go build ./...
```

Tests exercise local PDR edits, QFI propagation, rate/gate no-ops for policies,
mixed changes, reference cleanup, session isolation, all QER IDs, diagnostics,
ID limits and safe inspection. The PFCP test uses the actual request parser,
merged RuleState and existing dangling-reference validation. These tests do not
establish datapath rate enforcement or GBR guarantees.
