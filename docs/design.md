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
implementation file, sharing one AST parse between dependency discovery and
indexing. Source and PCResolve facts are cached for reuse within an unchanged
source snapshot. Assessment results depend on the supplied call, rather than
only on the API identity.

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
whether the selected argument is handled, rejected, ignored or unresolved.
The [API reference](api.md#parameter-level-assessment) documents the inputs
and output models.

## Source layout

| File | Responsibility |
| --- | --- |
| [`vppdetector.py`](../vppdetector.py) | Standalone whole-package scan CLI and JSON serialization. |
| [`vppdetector/__init__.py`](../vppdetector/__init__.py) | Public Python interfaces. |
| [`vppdetector/models.py`](../vppdetector/models.py) | Source identities, findings and parameter-level evidence. |
| [`vppdetector/source.py`](../vppdetector/source.py) | Source indexing, import roots and API location. |
| [`vppdetector/core.py`](../vppdetector/core.py) | Shared propagation logic, PCResolve adapter and reusable analysis context. |
| [`vppdetector/scanner.py`](../vppdetector/scanner.py) | Whole-package and on-demand scan scopes. |
| [`vppdetector/assessment.py`](../vppdetector/assessment.py) | Call-specific analysis of one supplied parameter change. |
| [`vppdetector/encoding.py`](../vppdetector/encoding.py) | Retained encoding helper; source indexing uses Python's declared source encoding. |

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
