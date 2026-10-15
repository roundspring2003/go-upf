# qos_manager

The manager reads affected PDRs from the validated PFCP RuleState to update
PDR policies. It stores only current policies and a local packet ID counter.
There is no Constraint graph, copied QER database, reverse reference table,
retained snapshot or QoS rollback mechanism. Prepare temporarily holds one
request's computed policies until forwarding succeeds.

## Data

`internal/rules/qos.go` defines Policy with its PDR key, packet PolicyID,
direction, target, QFI summary/sources and diagnostics. Full QER references
and MBR/GBR/Gate configurations remain in Session/RuleState and follow the
existing forwarder path.

RuleView reuses `QER`, `QFIUpdated`, `RangeQoSCandidates`, and `RangeRemovedPDR` from
RuleState. It must contain the validated result of the same request. The manager does not parse PFCP,
merge patches or revalidate references. A missing lookup reports a violated view
contract. Direction comes only from PDR Source Interface; target mapping is
explicit. QFI sources are all retained; conflicting values reject the request.

## Updating policies

```go
manager := qosmanager.NewManager(resolver)
prepared, err := manager.Prepare(seid, validatedState) // before forwarding
// After forwarding succeeds and the PFCP state is committed:
changed, err := manager.ApplyPrepared(prepared)
policies := manager.Policies(changes.SEID)
```

- Prepare reads PDRs created or updated by the request, derives their policies,
  and compares them with current manager policies. Unchanged policies do not
  rewrite TC or PDR bindings.
- PDRs explicitly removed by the request have their policies removed.
- A QFI update visits the final PDR state. The manager checks whether each PDR
  references the updated QER while deriving its QFI in one QER ID traversal,
  and refreshes only affected policies.
- MBR/GBR/Gate-only changes do not visit PDRs or rewrite QoS policies and TC.

Prepare rejects conflicting QFI values and checks capacity before any forwarding
or TC change. ApplyPrepared updates current policies and their TC resources.
TC errors are reported per operation;
successful policies are returned for PDR binding. This does not provide external
rollback or atomicity with the forwarder.

Use the existing PFCP event loop as the single owner and serialize all access.
Deliver successful requests from initial creation onward. Empty changes do not
bootstrap existing sessions. Live enablement, restart synchronization and target
remapping outside PFCP updates require explicit lifecycle work in a later step.

Policy/Policies return copies of policy slices/pointers for safe inspection;
these copies are not stored as history. Original QER configurations are never
copied into the manager. IDs occupy 1..0x00ffffff, remain stable for live PDRs,
and are not reused after removal. Exhaustion returns ErrIDExhausted.

RemoveSession deletes policies only after every session PDR is confirmed gone.
For partial cleanup, RemoveConfirmedPDRs handles only datapath-confirmed PDR
removals because other remaining rule references may be temporarily incomplete.

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
The manager installs TC classes and updates the egress BPF policy map. The PFCP
caller sends only successful PDR bindings through the existing session datapath;
see [binding integration](../../docs/qos_binding.md). Packet pacing remains future work.
Deployment `qos.n3Egress` / `qos.n6Egress` settings now feed the target resolver.
Manager owns this resolver from construction; PFCP sessions pass the session ID
and validated view to Apply.
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
