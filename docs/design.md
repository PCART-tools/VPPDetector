# Design

[Project overview](../README.md) · [API reference](api.md) ·
[Analysis coverage and limits](analysis-limits.md)

## Two analysis questions

VPPDetector separates structural forwarding detection from call-specific
argument handling.

| Analysis | Question | Result |
| --- | --- | --- |
| Whole-package or on-demand scan | Does an API's open variadic container reach an expansion into a signature without the corresponding variadic parameter? | `ScanReport` with findings, paths and boundaries. |
| Parameter-level assessment | How is one supplied changed argument handled under the original call's conditions? | `ParameterAssessment` with a state, evidence and boundaries. |

The two scan scopes share one detection core. Whole-package scanning considers
indexed non-overload function entries; on-demand scanning starts from one
resolved API implementation and retains its requested public identity.

A structural finding can coexist with a handled argument. For example,
`wrapper(**kwargs)` forwarding to `target(allowed=0)` has a VPP structure,
while `wrapper(allowed=7)` binds the supplied argument to an explicit downstream
parameter. Assessment examines the selected name or positional element and
call conditions.

Scan and assessment share program facts, but neither consumes the other's
conclusion. They retain separate propagation state and depth budgets.

## Source preparation and program facts

Source indexing derives module names from import roots, collects function and
constructor identities, and extracts signature facts from the Python AST.
Source files are read using Python's declared source encoding.

`AnalysisContext` combines this source index with a narrow PCResolve adapter.
PCResolve supplies call targets, parameter bindings, receiver and callable
contexts, and container/value-flow facts. VPPDetector uses those facts to
identify variadic propagation and interpret downstream signatures.

Full-source preparation and API-scoped preparation use the same index model.
API-scoped preparation discovers explicit package-local imports from a known
implementation file and can include external sources through configured import
roots, subject to the [source selection limits](analysis-limits.md#source-scope-boundaries).
Dependency discovery and indexing share one AST parse. Source and PCResolve
facts are cached for reuse within an unchanged source snapshot. Assessment
results depend on the supplied call, rather than
only on the API identity.

The common adapter validates the producer schema, required call fields and
source hashes before admitting a fact snapshot. Cached fact trees are read-only;
producer expansion creates a separate snapshot. Unsupported producer contracts
retain an explicit boundary in either consumer. The
[fact consumption contract](fact-contract.md) describes the available fields,
their limits and the source freshness checks.

## Structural propagation

A scan begins with an API's `*args` or `**kwargs` container. The shared core
follows supported forwarding, aliases and source-resolved helper calls.

An ordinary mapping or sequence argument can carry variadic data through an
intermediate helper. The finding point is an eventual `**mapping` or
`*sequence` expansion whose downstream signature lacks the matching variadic
parameter.

Whole-container propagation is distinguished from selected elements and finite
contents. For returned containers, the analysis uses supported return-shape,
slot and alias facts. The evidence path retains source-resolved hops, including
return-producing calls, and each hop counts toward the depth limit.

Resolved targets and source candidates retain their status. Unresolved targets,
unsupported effects, recursion and exhausted depth are recorded as boundaries.
The [coverage document](analysis-limits.md) describes these cases in detail.

## Parameter-level analysis

The caller supplies one identified deletion or rename and an original call.
Assessment binds the call to the selected new implementation and tracks the
changed keyword or positional element captured by the corresponding variadic
parameter. Finite positional containers retain the selected element's identity
through supported ordering operations; they are not treated as open structural
carriers for deciding a concrete argument's acceptance.

Supported literal/default-value guards, named-key operations, forwarding and
downstream binding produce call-specific evidence. The result identifies
whether the selected argument is `handled`, `rejected`, `ignored`, or `unknown`
when evidence is insufficient. `not_entered` records a proved unrelated entry
binding failure that prevented the original call from entering the implementation.
The [API reference](api.md#parameter-level-assessment) documents the inputs
and output models.

## Source layout

| File | Responsibility |
| --- | --- |
| [`vppdetector.py`](../vppdetector.py) | Source-checkout entry point that invokes the packaged CLI. |
| [`vppdetector/cli.py`](../vppdetector/cli.py) | Whole-package scan CLI, argument parsing and JSON serialization. |
| [`vppdetector/__init__.py`](../vppdetector/__init__.py) | Public Python interfaces. |
| [`vppdetector/models.py`](../vppdetector/models.py) | Source identities, findings and parameter-level evidence. |
| [`vppdetector/source/discovery.py`](../vppdetector/source/discovery.py) | Source roots, Python file discovery and module names. |
| [`vppdetector/source/build.py`](../vppdetector/source/build.py) | Import-aware source graph construction and boundary collection. |
| [`vppdetector/source/__init__.py`](../vppdetector/source/__init__.py) | Exports the current source indexing and query services. |
| [`vppdetector/source/index.py`](../vppdetector/source/index.py) | Indexed functions, constructors, classes and source-location lookup. |
| [`vppdetector/source/records.py`](../vppdetector/source/records.py) | Indexed source records and signatures. |
| [`vppdetector/source/queries.py`](../vppdetector/source/queries.py) | Cached AST structure and syntax queries. |
| [`vppdetector/_records.py`](../vppdetector/_records.py) | Shared record operations for source, facts, scanning and assessment. |
| [`vppdetector/_analysis_context.py`](../vppdetector/_analysis_context.py) | Source preparation and reusable context that assembles the source and fact services and the consumer-specific caches. |
| [`vppdetector/facts/adapter.py`](../vppdetector/facts/adapter.py) | Producer capability checks, source validation and read-only fact caching. |
| [`vppdetector/facts/readonly.py`](../vppdetector/facts/readonly.py) | Immutable cached facts and mutable copies for isolated expansion. |
| [`vppdetector/facts/calls.py`](../vppdetector/facts/calls.py) | Shared call identities, target status and validated call facts. |
| [`vppdetector/facts/bindings.py`](../vppdetector/facts/bindings.py) | Source alias and class method binding proofs. |
| [`vppdetector/facts/conditional_bindings.py`](../vppdetector/facts/conditional_bindings.py) | Conditional lookup and signature-only binding facts. |
| [`vppdetector/facts/conditions.py`](../vppdetector/facts/conditions.py) | Bounded literal conditions and path-consistency facts. |
| [`vppdetector/facts/containers.py`](../vppdetector/facts/containers.py) | Exact copy, mapping-operation and preserved-remainder facts. |
| [`vppdetector/facts/creation.py`](../vppdetector/facts/creation.py) | Source class creation and constructor binding proofs. |
| [`vppdetector/facts/creation_metadata.py`](../vppdetector/facts/creation_metadata.py) | Bounded source class metadata query evidence. |
| [`vppdetector/facts/callable_metadata.py`](../vppdetector/facts/callable_metadata.py) | Proof premises for callable metadata queried during class creation. |
| [`vppdetector/facts/builtin_protocols.py`](../vppdetector/facts/builtin_protocols.py) | Exact builtin truth, callability and length protocols. |
| [`vppdetector/facts/locations.py`](../vppdetector/facts/locations.py) | AST and producer source locations. |
| [`vppdetector/facts/scope.py`](../vppdetector/facts/scope.py) | Capture lookup and synchronous function body facts. |
| [`vppdetector/scan/engine.py`](../vppdetector/scan/engine.py) | Structural scan scheduling, forwarding decisions and witness construction. |
| [`vppdetector/scan/cache.py`](../vppdetector/scan/cache.py) | Context-local transformation locations and completed scan results with isolated mutable evidence. |
| [`vppdetector/scan/flow.py`](../vppdetector/scan/flow.py) | Shared structural flow helpers. |
| [`vppdetector/scan/returns.py`](../vppdetector/scan/returns.py) | Bounded returned-container routing. |
| [`vppdetector/scanner.py`](../vppdetector/scanner.py) | Whole-package and on-demand scan scopes. |
| [`vppdetector/assessment.py`](../vppdetector/assessment.py) | Public parameter-assessment API facade. |
| [`vppdetector/assess/values.py`](../vppdetector/assess/values.py) | Abstract values tracked through one assessment path. |
| [`vppdetector/assess/binding.py`](../vppdetector/assess/binding.py) | Finite call binding and binding stop outcomes. |
| [`vppdetector/assess/calls.py`](../vppdetector/assess/calls.py) | Source call lookup and call-result interpretation for assessment frames. |
| [`vppdetector/assess/inputs.py`](../vppdetector/assess/inputs.py) | Call-time capture and callable-instance binding checks. |
| [`vppdetector/assess/expressions.py`](../vppdetector/assess/expressions.py) | Bounded literal, container, operator and conditional expression interpretation. |
| [`vppdetector/assess/fresh.py`](../vppdetector/assess/fresh.py) | Source-backed member lookup for fresh receivers. |
| [`vppdetector/assess/frame.py`](../vppdetector/assess/frame.py) | Mutable abstract state for one function path and its bounded operations. |
| [`vppdetector/assess/statements.py`](../vppdetector/assess/statements.py) | Statement dispatch for return, import, loops, guards and definitions. |
| [`vppdetector/assess/semantics/`](../vppdetector/assess/semantics/__init__.py) | Separate handlers for assignments, attribute calls, builtins, conditions and outcomes. |
| [`vppdetector/assess/context_cache.py`](../vppdetector/assess/context_cache.py) | Context-local constructor and dispatch reuse and package initialization proofs. |
| [`vppdetector/assess/runner.py`](../vppdetector/assess/runner.py) | Public call-specific assessment orchestration and evidence recording. |
| [`vppdetector/assess/engine.py`](../vppdetector/assess/engine.py) | Proof state, boundaries and bounded recursive source-call orchestration. |
| [`vppdetector/assess/proofs/decorators.py`](../vppdetector/assess/proofs/decorators.py) | Evidence checks for decorator effects and preservation of the wrapped body. |
| [`vppdetector/assess/observations/contextvars.py`](../vppdetector/assess/observations/contextvars.py) | Validates caller-input facts and constructs source-backed ContextVar conditions. |
| [`vppdetector/assess/observations/contextvar_support.py`](../vppdetector/assess/observations/contextvar_support.py) | Small AST, import and source-hash helpers used by observation proofs. |
| [`vppdetector/assess/observations/contextvar_proxy.py`](../vppdetector/assess/observations/contextvar_proxy.py) | Proves supported proxy boolean and descriptor behavior from source. |
| [`vppdetector/assess/observations/contextvar_packages.py`](../vppdetector/assess/observations/contextvar_packages.py) | Reads and indexes package source, resolves source targets, and assembles one bounded package proof. |
| [`vppdetector/assess/observations/contextvar_package_scan.py`](../vppdetector/assess/observations/contextvar_package_scan.py) | Performs the bounded worklist traversal and applies call-specific ContextVar write rules using an explicit package scan state. |
| [`vppdetector/assess/observations/__init__.py`](../vppdetector/assess/observations/__init__.py) | Internal observation service exports. |
| [`vppdetector/encoding.py`](../vppdetector/encoding.py) | Retained encoding helper; source indexing uses Python's declared source encoding. |

The scan cache keys results by entry identity, depth and the entry's class
and alias query. It copies mutable producer evidence when storing results and
when returning them to scan callers. Assessment allocates a proof per call
and a frame per interpreted function. A speculative branch copies its mutable
proof and affected frames with a single copy memo to preserve aliases within
that branch. Assessment caches reusable child contexts and package
initialization proofs, while call-specific conditions and evidence stay with
the proof.

## Version 1.0 research scanner

The original implementation is retained in
[`legacy_vppdetector.py`](../legacy_vppdetector.py) for reproducibility. It
requires the original `Path.getPath` and `Tool.tool` helper modules and
contains dataset-specific paths. The current scan entry point is
`vppdetector.py`.

Historical outputs under `APIDefWithVariadicPara/` and
`VariadicParaPitfalls/` are unchanged. They contain the original scanner's
variadic API listings and potential pitfall records, respectively. Their
historical format differs from the current `ScanReport` format.
