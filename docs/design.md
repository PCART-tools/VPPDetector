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
| [`src/vppdetector/cli.py`](../src/vppdetector/cli.py) | Whole-package scan CLI, argument parsing and JSON serialization. |
| [`src/vppdetector/__init__.py`](../src/vppdetector/__init__.py) | Public Python interfaces. |
| [`src/vppdetector/models.py`](../src/vppdetector/models.py) | Source identities, findings and parameter-level evidence. |
| [`src/vppdetector/source/discovery.py`](../src/vppdetector/source/discovery.py) | Source roots, Python file discovery and module names. |
| [`src/vppdetector/source/build.py`](../src/vppdetector/source/build.py) | Import-aware source graph construction and boundary collection. |
| [`src/vppdetector/source/__init__.py`](../src/vppdetector/source/__init__.py) | Exports the current source indexing and query services. |
| [`src/vppdetector/source/index.py`](../src/vppdetector/source/index.py) | Indexed functions, constructors, classes and source-location lookup. |
| [`src/vppdetector/source/records.py`](../src/vppdetector/source/records.py) | Indexed source records and signatures. |
| [`src/vppdetector/source/queries.py`](../src/vppdetector/source/queries.py) | Cached AST structure and syntax queries. |
| [`src/vppdetector/_records.py`](../src/vppdetector/_records.py) | Shared record operations for source, facts, scanning and assessment. |
| [`src/vppdetector/_analysis_context.py`](../src/vppdetector/_analysis_context.py) | Source preparation and reusable context that assembles the source and fact services and the consumer-specific caches. |
| [`src/vppdetector/facts/adapter.py`](../src/vppdetector/facts/adapter.py) | Producer capability checks, source validation and read-only fact caching. |
| [`src/vppdetector/facts/readonly.py`](../src/vppdetector/facts/readonly.py) | Immutable cached facts and mutable copies for isolated expansion. |
| [`src/vppdetector/facts/calls.py`](../src/vppdetector/facts/calls.py) | Shared call identities, target status and validated call facts. |
| [`src/vppdetector/facts/bindings.py`](../src/vppdetector/facts/bindings.py) | Source alias and class method binding proofs. |
| [`src/vppdetector/facts/conditional_bindings.py`](../src/vppdetector/facts/conditional_bindings.py) | Conditional lookup and signature-only binding facts. |
| [`src/vppdetector/facts/conditions.py`](../src/vppdetector/facts/conditions.py) | Bounded literal conditions and path-consistency facts. |
| [`src/vppdetector/facts/containers.py`](../src/vppdetector/facts/containers.py) | Exact copy, mapping-operation and preserved-remainder facts. |
| [`src/vppdetector/facts/creation.py`](../src/vppdetector/facts/creation.py) | Source class creation and constructor binding proofs. |
| [`src/vppdetector/facts/creation_metadata.py`](../src/vppdetector/facts/creation_metadata.py) | Bounded source class metadata query evidence. |
| [`src/vppdetector/facts/callable_metadata.py`](../src/vppdetector/facts/callable_metadata.py) | Proof premises for callable metadata queried during class creation. |
| [`src/vppdetector/facts/builtin_protocols.py`](../src/vppdetector/facts/builtin_protocols.py) | Exact builtin truth, callability and length protocols. |
| [`src/vppdetector/facts/locations.py`](../src/vppdetector/facts/locations.py) | AST and producer source locations. |
| [`src/vppdetector/facts/scope.py`](../src/vppdetector/facts/scope.py) | Capture lookup and synchronous function body facts. |
| [`src/vppdetector/scan/engine.py`](../src/vppdetector/scan/engine.py) | Structural scan scheduling, forwarding decisions and witness construction. |
| [`src/vppdetector/scan/cache.py`](../src/vppdetector/scan/cache.py) | Context-local transformation locations and completed scan results with isolated mutable evidence. |
| [`src/vppdetector/scan/flow.py`](../src/vppdetector/scan/flow.py) | Shared structural flow helpers. |
| [`src/vppdetector/scan/returns.py`](../src/vppdetector/scan/returns.py) | Bounded returned-container routing. |
| [`src/vppdetector/scanner.py`](../src/vppdetector/scanner.py) | Whole-package and on-demand scan scopes. |
| [`src/vppdetector/assessment.py`](../src/vppdetector/assessment.py) | Public parameter-assessment API facade. |
| [`src/vppdetector/assess/values.py`](../src/vppdetector/assess/values.py) | Abstract values tracked through one assessment path. |
| [`src/vppdetector/assess/binding.py`](../src/vppdetector/assess/binding.py) | Finite call binding and binding stop outcomes. |
| [`src/vppdetector/assess/calls.py`](../src/vppdetector/assess/calls.py) | Source call lookup and call-result interpretation for assessment frames. |
| [`src/vppdetector/assess/inputs.py`](../src/vppdetector/assess/inputs.py) | Call-time capture and callable-instance binding checks. |
| [`src/vppdetector/assess/expressions.py`](../src/vppdetector/assess/expressions.py) | Bounded literal, container, operator and conditional expression interpretation. |
| [`src/vppdetector/assess/fresh.py`](../src/vppdetector/assess/fresh.py) | Source-backed member lookup for fresh receivers. |
| [`src/vppdetector/assess/frame.py`](../src/vppdetector/assess/frame.py) | Mutable abstract state for one function path and its bounded operations. |
| [`src/vppdetector/assess/statements.py`](../src/vppdetector/assess/statements.py) | Statement dispatch for return, import, loops, guards and definitions. |
| [`src/vppdetector/assess/semantics/`](../src/vppdetector/assess/semantics/__init__.py) | Separate handlers for assignments, attribute calls, builtins, conditions and outcomes. |
| [`src/vppdetector/assess/context_cache.py`](../src/vppdetector/assess/context_cache.py) | Context-local constructor and dispatch reuse and package initialization proofs. |
| [`src/vppdetector/assess/runner.py`](../src/vppdetector/assess/runner.py) | Public call-specific assessment orchestration and evidence recording. |
| [`src/vppdetector/assess/engine.py`](../src/vppdetector/assess/engine.py) | Proof state, boundaries and bounded recursive source-call orchestration. |
| [`src/vppdetector/assess/proofs/decorators.py`](../src/vppdetector/assess/proofs/decorators.py) | Evidence checks for decorator effects and preservation of the wrapped body. |
| [`src/vppdetector/assess/observations/contextvars.py`](../src/vppdetector/assess/observations/contextvars.py) | Validates caller-input facts and constructs source-backed ContextVar conditions. |
| [`src/vppdetector/assess/observations/contextvar_support.py`](../src/vppdetector/assess/observations/contextvar_support.py) | Small AST, import and source-hash helpers used by observation proofs. |
| [`src/vppdetector/assess/observations/contextvar_proxy.py`](../src/vppdetector/assess/observations/contextvar_proxy.py) | Proves supported proxy boolean and descriptor behavior from source. |
| [`src/vppdetector/assess/observations/contextvar_packages.py`](../src/vppdetector/assess/observations/contextvar_packages.py) | Reads and indexes package source, resolves source targets, and assembles one bounded package proof. |
| [`src/vppdetector/assess/observations/contextvar_package_scan.py`](../src/vppdetector/assess/observations/contextvar_package_scan.py) | Performs the bounded worklist traversal and applies call-specific ContextVar write rules using an explicit package scan state. |
| [`src/vppdetector/assess/observations/__init__.py`](../src/vppdetector/assess/observations/__init__.py) | Internal observation service exports. |
| [`src/vppdetector/encoding.py`](../src/vppdetector/encoding.py) | Retained encoding helper; source indexing uses Python's declared source encoding. |

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
`vppdetector.cli`.

Historical outputs under `APIDefWithVariadicPara/` and
`VariadicParaPitfalls/` are unchanged. They contain the original scanner's
variadic API listings and potential pitfall records, respectively. Their
historical format differs from the current `ScanReport` format.
