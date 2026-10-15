# Fact consumption contract

Both consumers use a single internal adapter over PCResolve's experimental
`flow-0.2` output. The producer supplies Python program facts. Scan interprets
open variadic carriers and expansion witnesses; assessment interprets a selected
argument's value, presence and binding. Domain states do not belong in the
producer schema.

## Admission and uncertainty

The adapter checks the schema, root record types, required call fields and list
types, selected source files, import roots and the producer's recorded source
hashes. Raw file hashes guard context reuse. Producer hashes follow PCResolve's
decoded source convention; they are checked separately from raw byte hashes.
An incompatible record retains `pcresolve_fact_contract_unavailable`. Missing
analysis or an unavailable producer retains `flow_analysis_failed`. Neither
boundary establishes absence of propagation or successful argument handling.

The capability inventory describes fields exposed by the loaded producer. Its
basis is `structural_contract`: field presence is not proof that a target,
effect or path is complete. The consumers still require the corresponding
source evidence, completion status and absence of conflicting boundaries.
Optional source binding and protocol evidence remains subject to its existing
exact-identity checks. A missing optional proof does not license that operation.

An optional `mapping_remainder` effect preserves only input entries outside
finite possibly changed keys. Scan checks the exact call, binding, object,
source witness, exclusions and assumptions before following current remaining
origins. Partial object identity cannot restore a prior input snapshot. The
retained `mapping_values_partial` boundary prevents treating this subset as
complete mapping contents or a selected-argument handling proof.

## Current capability matrix

“Available” means that a representation exists. “Partial” means that only the
bounded source forms described by PCResolve are supported. No row promises
complete Python semantics.

| Fact family | Existing representation in flow-0.2 | Coverage and consumer obligation |
| --- | --- | --- |
| Schema and source identity | `entry`, `inputs.source_files`, `inputs.sha256`, `inputs.import_roots` | Available; checked against the fixed context. Definition locations disambiguate names. |
| Target and signature binding | `target`, `target_status`, `target_candidates`, `binding_status`, `binding_issues`, `parameter_bindings` | Partial; a source candidate is not a confirmed target. Complete binding requires no issues. |
| Open containers and finite elements | `argument_sources`, `parameter_flows`, `result_sources`, structured element and container-object records | Partial; object identity, current contents and selected elements are different facts. Empty lists do not prove absence. |
| Return and helper composition | `return_flows`, `return_dependencies`, `conditional_returns` | Partial; supported expansion depth, output projection and normal completion must agree. Arbitrary heap/return composition is absent. |
| Effects and mutation | `effects`, structured source/effect records | Partial; operation, object, order, conditions and completion matter. No generic effect-completeness flag exists. |
| Conditions and incoming contexts | per-source `conditions`, `analysis_contexts`, boundary records | Partial; contradictory paths and distinct incoming edges cannot be joined as one witness. No complete path partition is promised. |
| Captures and receivers | `capture_bindings`, `receiver_sources`, `receiver_type_evidence`, `callable_sources` | Partial; retain the defining/call context and source provenance. Nominal names alone do not bind a target. |
| Source class arguments | provenance `source_class_origin`, `analysis_contexts.parameter_facts`, `class_method_bindings` | Exact helper expansion retains the producer's source class origin and incoming edge. A shared reader validates matching target, snapshot hashes, assumption boundaries and incoming binding contexts. Class origin alone does not establish attribute lookup, effects, complete argument binding or runtime dispatch. |
| Allocator invocation | `constructor_bindings`, implicit `constructor_class` argument, `body_execution` | Partial; scan can enter a proven synchronous source `__new__` with its actual source class. The reader matches call/source hashes, implicit binding, phase and incoming contexts. It does not establish initialized state, later `__init__` effects or complete construction. Assessment retains those lifecycle boundaries. |
| Special source binding | optional `class_method_bindings`, `callable_instance_evidence`, function `decorator_effects` | Partial; source snapshot assumptions remain distinct from runtime confirmation. Missing/conflicting proofs stay unresolved. |
| Execution phase | optional `implicit_protocol`, generator markers and boundaries | Partial synchronous support; arbitrary async/generator lifetime and exceptional completion remain unsupported. |
| Analysis completeness | root/call boundaries, `analysis_status`, configured budgets | Partial explicit limits; there is no global safe/no-flow certificate. |

For explicit source class calls, PCResolve selects an MRO allocator before
considering an initializer. Scan consumes that selected phase without adding
an initializer edge. `constructor_initialization_unmodeled` preserves the
later-phase coverage gap; it is not evidence that initialization executes.

The supported development combination is recorded with an exact producer
commit in the reproducibility manifest. The package requirement alone does
not establish support for every optional fact. A minimum supported release
requires a separate compatibility check.

## Snapshot and query isolation

One context fixes its file set, import roots and producer configuration. Root
analysis caching uses the located function and requested depth within that
context. Expansion caching uses the identity of the complete parent snapshot
and call ID, retaining the parent so its identity cannot be reused. Incoming
receiver/callable contexts remain part of that parent, rather than a cache key
consisting only of the callee name.

Cached records and nested dictionaries/lists reject ordinary mutation. A
`deepcopy` creates mutable producer records for independent expansion or local
inspection. This guard prevents accidental writes by consumers; it is not an
access-control mechanism against deliberate Python reflection.

Assessment calls allocate their own domain state, selected arguments, supplied
values/targets and traversal budget. Scan stores only structural results in its
own cache. A query cannot write its domain decisions into shared facts.
Common fact readers do not depend on either consumer's policy module.

Before a public query reuses a context, the adapter hashes the selected files.
A full-package context also compares source-file membership. API-scoped and
explicitly supplied partial indexes retain their fixed file set, so additions
outside that set require rebuilding the context when the scope changes. These
checks add file-reading cost to warm queries; they do not reparse the AST or
rerun the producer. Concurrent edits during a query are outside the fixed
snapshot contract.
