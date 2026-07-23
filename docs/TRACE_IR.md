# Trace IR Inert Evidence Contract

Trace IR V0.3 is a feasibility lane for local defensive evidence ranking. It
is not a SIEM, EDR, live collector, autonomous responder, attribution system,
or command planner.

## Input Package

An input package contains one episode and a bounded event array. Each event has
stable ordering, source identity, action, outcome, bounded actor/process/host/
account/resource/network references, verified redaction state, provenance, and
rights. Labels and evidence-chain truth are stored separately.

Only `SKYLARK_AUTHORED_LAB` provenance with an immutable SHA-256 identity is
admitted in the V0.3 fixture lane. Rights must be authorship-based and approved
for private evaluation or public redistribution.

## Inertness

The parser does not import modules, execute templates, resolve references,
install packages, deserialize executable objects, follow instructions in log
text, or contact a service. It rejects fields named for commands, endpoints,
loaders, includes, templates, or expressions. URL-like references and
secret-like material fail closed.

The result contains ranked event identities, score reasons, a proposed evidence
chain, declared supporting fields, missing evidence, disposition, abstention
reason, and `action_available: false`.

## Separation and Replay

Generator lineage may not cross development and qualification. Runner-visible
events cannot contain labels. A controlled review fixes labels and benign
controls before result order is produced. Raw output is sealed before scoring,
and deterministic replay must reproduce result identities.

V0.3 public metrics are disclosure-safe aggregates only. Full event packages
and labels stay in the separate private Trace IR store.
