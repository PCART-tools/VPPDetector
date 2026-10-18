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

Assessment consumes exact `container_clear` effects and named-key `get`
projection facts from `local_container_protocol` calls. The reader matches the
indexed call syntax, completion/binding, receiver objects, source evidence and
incoming effect/result contexts. Clearing mutates the current mapping object;
aliases share that object while proven shallow copies retain independent
contents. A `get` result is consumed only when downstream use requires its
value. Missing/conflicting facts and unknown receiver effects remain unknown.

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
| Instance arguments | direct `instance_type`, exact ordinary/implicit receiver bindings, `analysis_contexts.parameter_facts` | Source instance evidence can cross an exact plain-method or ordinary helper edge. Scan checks matching incoming instances on each expanded context; missing, mixed or invalidated facts remain boundaries. This does not establish heap contents or arbitrary runtime dispatch. |
| Class lookup preservation | partial `class_attribute_write_set` effects, `class_lookup_mutations`, binding `lookup_preservation` / `lookup_hierarchy` | Scan validates the bounded writes, unaffected lookup, source hashes and matching incoming state. Written methods, lost state, unbounded names and unproved effects remain boundaries. A partial class effect does not establish cache values or carrier effects. |
| Source class arguments | provenance `source_class_origin`, `analysis_contexts.parameter_facts`, `class_method_bindings` | Exact helper expansion retains the producer's source class origin and incoming edge. A shared reader validates matching target, snapshot hashes, assumption boundaries and incoming binding contexts. Class origin alone does not establish attribute lookup, effects, complete argument binding or runtime dispatch. |
| Constructor invocation | `constructor_bindings`, implicit `constructor_class` / `constructor_instance` argument, `body_execution` | Partial; scan can enter a proven synchronous source `__new__`, or a source `__init__` selected after ordinary builtin allocation, with the actual receiver. The reader matches call/source hashes, implicit binding, phase and incoming contexts. It does not establish initialized state, later phases after a custom allocator or complete construction. Assessment retains those lifecycle boundaries. |
| Special source binding | optional `class_method_bindings`, `callable_instance_evidence`, function `decorator_effects` | Partial; source snapshot assumptions remain distinct from runtime confirmation. Missing/conflicting proofs stay unresolved. |
| Execution phase | optional `implicit_protocol`, generator markers and boundaries | Partial synchronous support; arbitrary async/generator lifetime and exceptional completion remain unsupported. |
| Analysis completeness | root/call boundaries, `analysis_status`, configured budgets | Partial explicit limits; there is no global safe/no-flow certificate. |

For explicit source class calls, PCResolve selects an MRO allocator before
considering an initializer. Scan consumes that selected phase without adding
an initializer edge. `constructor_initialization_unmodeled` preserves the
later-phase coverage gap; it is not evidence that initialization executes.

Class API queries consume optional `inputs.entry_binding` instead of selecting
an initializer in the consumer. The reader matches the actual class, source MRO,
selected phase/target, implicit parameter, hashes and assumption boundary. Class
queries retain distinct producer and scan cache entries from generic method
queries, even when they share an implementation. Missing or conflicting entry
facts stop resolution. Assessment preserves the allocator lifecycle boundary.
The producer also checks source-MRO class-definition evaluation before binding
an allocator or initializer. Unknown definition effects may replace that phase;
an unconfirmed proof stops scan and assessment from using the old body. The
consumer does not evaluate those class definitions or infer an alternative phase.

For a synchronous initializer invocation, assess can consume the same exact
`constructor_bindings` proof to follow that phase despite a broader
`dynamic_construction` boundary. This requires the initializer phase, matching
implicit receiver/context, source hashes and assumption witness. It does not
authorize entering an allocator's later phases, inferring returned instance state
or treating instance attributes as ordinary dictionary stores. Bounded class
decoration is established by the producer; assess does not execute decorators or
infer their effects from names.

Public API resolution also consumes PCResolve's module-entry binding uncertainty
before using a direct or reexported source definition. Visible global rebinding
of the API name or its class prefix stops both scan and assess at that lookup.
Lexical body facts remain available in PCResolve; they cannot establish that the
current public object still uses that body. Captured source aliases retain their
separate binding proof.
The resolver validates `inputs.module_global_rebindings` against the analyzed
source hashes and checks the requested public prefix even when the implementation
is inherited from another class. Missing or conflicting namespace records retain
`entry_binding_facts_unavailable`, rather than approving a public lookup.

Finite class-write sets may include producer-proven local string concatenations
and subsequent reads of builtin literal payloads definitely written by that same
helper. Scan consumes the unaffected-lookup proof without reconstructing names or
descriptor behavior. Existing descriptors, conditional cache initialization and
unknown replacement values still require producer evidence. Such partial facts
do not establish complete helper effects or selected-argument handling.
The producer may preserve read safety for builtin literal payloads carried
through local aliases and all branches of an assignment. Scan consumes the same
bounded write set and source evidence. Assessment still requires its own
selected-argument and constructor-lifecycle facts; a recovered scan finding
does not settle whether that argument is accepted or consumed downstream.

Computed class-write names may carry a producer `class_name_literal` entry
premise in `name_metadata`. The reader requires a `source_bound` canonical
`__name__`, the exact class/helper/parameter/call, matching full snapshot hashes,
source read evidence and the declared metadata-preservation assumptions. Missing,
unconfirmed or mismatched premises cannot preserve downstream lookup. VPPDetector
does not infer the literal from class spelling. The premise does not establish
conditional cache-read safety, cached payload types or a configured backend.
Producer-detected class references escaping through containers, aliases or
deferred captures can invalidate this premise even when the final call does not
spell the class name. Both consumers honor the resulting unconfirmed fact;
neither reconstructs a canonical name or restores the old target. Escape
containment facts do not establish a class identity for a container or call result.

Conditional class-cache reads may carry a producer
`class_attribute_read_invariant`: the attribute is absent or holds a builtin
literal payload under the recorded source-snapshot assumptions. The producer
uses an unshadowed `hasattr` branch and definite writes to justify later reads.
The reader validates `read_basis`, every `read_premises` entry and its probe
evidence against the exact class/helper/parameter/call and snapshot hashes.
Missing, conflicting or unconfirmed premises cannot preserve a downstream
lookup. The consumer does not infer descriptor behavior or cache contents, and
assessment retains its separate argument-consumption and lifecycle boundaries.

VPPDetector 1.1.0 requires PCResolve 1.0.8 or newer. Local release checks must
exercise both packaged producer/consumer code and current development source.
The version requirement alone does not establish support for every optional
fact: structural admission, exact source evidence and per-operation capability
checks still apply. Experimental `flow-0.2` remains separate from stable
ownership schema `1.0`.

Build release wheels from a fresh checkout or source export, then compare the
packaged module set and content with that source. A reused `build/lib` directory
can otherwise retain modules removed from the current source tree.

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

## Conditional source-state queries

`inputs.conditional_source_state=true` marks a producer query under explicit
source-lookup requirements. It is separate from ordinary facts, with separate
adapter and expansion cache entries. Scan requests it only for a bound class
entry with a producer `source_lookup_candidate` boundary. The reader validates
`conditional_source_bindings` against the target, receiver classes, exact call
span, source hashes, required predicates and incoming contexts. Missing or
conflicting records stop the path. Allocated `candidate_paths` retain their own
conditions; opposite outcomes of the same source test cannot form one finding.
`ForwardingStep.conditions` and `ForwardingFinding.conditions` expose these
requirements. Empty conditions preserve ordinary structural behavior.

For constructor calls, the optional `conditional_constructor_signature` fact
has `scope="signature_only"`. Scan validates its original unconfirmed binding,
source hashes, call evidence, preceding type checks and required
`source_constructor_lookup` predicate. It can compare an expansion against a
fixed signature and retains that predicate on the finding. It cannot propagate
into a variadic constructor body. Assess does not request this conditional mode.

These records establish a conditional source path, not effect completeness,
feasibility or runtime dispatch. Unknown class/call effects remain boundaries.
The ordinary classmethod and constructor proof readers reject this query mode;
assessment never obtains these facts from the scan cache.

If this optional query is unsupported or its records fail validation, scan
retains `conditional_source_query_unavailable` and still visits valid ordinary
facts. Failure of the additional query cannot discard an already established
ordinary forwarding path or supply a conditional one. Coverage remains limited.

## Isolated incoming call contexts

When an ordinary expansion merges incoming contexts, scan can request
PCResolve's `expand(..., isolate=True)`. The adapter separately caches this
snapshot and validates its `inputs.expansion_context` against the exact edge,
caller, target and entry. Scan still checks every incoming call record and
class/instance requirement before propagating the variadic carrier. Recursion
keys include the producer's incoming parameter facts; unchanged contexts and
the scan depth budget still stop traversal. Assessment retains ordinary
expansion behavior. Finite generated source dispatch tables arrive through the
existing producer candidate facts; VPPDetector does not evaluate comprehensions
or reflective namespace expressions.

Assessment can consume `builtin_scalar_truth` only after validating its call,
source hash, binding, input precondition and every incoming protocol record.
The query must supply an exact modeled builtin scalar; an unknown object or a
custom truth protocol remains unresolved. The converted value retains the
selected-value marker. Merely discarding an optional-pop conversion does not
establish consumption. Missing external decorator source is separately exposed
as `decorator_source_unavailable`, while the primary assessment remains
`UNKNOWN/decorated_entry`; the diagnostic does not approve the decorated body.

Closed decorator proofs may contain finite string-suffix, string-slice and
string-length operations, plus scalar builtin exception exits. Assess validates
their protocol, argument/result shapes, slice bounds and completion kind. Length
and exception effects additionally require the producer's builtin namespace
preservation assumptions and hashes covering the whole analyzed source scope.
Exceptional paths do not imply successful decoration. Arbitrary callbacks,
imports, exception protocols or changed namespace facts cannot approve a body.
For a cached local import inside a closed decorator proof, assess matches the
producer's callback and decorated-entry identities, local import AST and aliases,
preceding top-level initialization witness, full source hashes and cache/import
assumptions. It accepts only `normal_cached_import_return` binding effects. This
does not establish ordinary module execution, callback completion or a returned
class/instance type; missing or inconsistent evidence keeps the decorated body
unconfirmed.
When a package has a property-based module `__getattr__`, assess additionally
requires the producer's matching `source_module_getattr_missing` premise for the
initialized child. It checks the requested name is outside the finite property
set, the source class/factory identities and full hashes, and the standard cache
and preserved-table assumptions. A missing premise, selected property or runtime
confirmation substituted for this source proof does not approve the import.

## Source API alias selection

PCResolve can supply `inputs.entry_alias` for a captured plain source function.
The common API resolver checks its requested identity, original function,
assignment chain and spans, fixed source hashes, assumptions and conditional
definition boundaries. The alias query has its own cache identity and retains
the user's API name; implementation steps name the original source definition.
Deleting the original namespace name does not delete an earlier captured alias.
This selects a source body and does not confirm runtime attribute binding or
activate a conditional fallback. Missing/conflicting alias evidence, visible
replacement and definitions absent from the selected version remain unavailable.

## Optional caller literals

The adapter reads PCResolve's internal `source_callsite_inputs` contract in a
separate source store. Each query rereads the caller; these records are absent
from library analysis/expansion and scan caches. Assess validates the exact
full call span, syntax, qualified import binding, source hash, argument slots,
typed finite literals, evidence and source assumptions before binding values.
It never executes the caller or imports its target. An older producer or a
partial/mismatched record supplies no additional values. Unmodeled operations
on recovered containers stop the proof rather than reuse stale contents.

Assessment can consume `builtin_exact_callability` only for the producer's
listed exact builtin input types, after checking its source, call, binding,
result, dependency scope and every incoming context. Unknown/custom callable
objects retain a boundary. A selected scalar object may be inspected through
this protocol. Checking a capture tuple/dict's type does not inspect its selected
elements, so the result carries no element-consumption marker.
Likewise, checking the fixed builtin type of a derived comparison/length result
does not consume the value or presence that produced that temporary result.
