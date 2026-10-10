# VPPDetector

VPPDetector detects potential variadic-parameter pitfalls in Python library
source. A VPP occurs when a library API's `*args` or `**kwargs` propagates to
a downstream expansion whose signature lacks the corresponding variadic
parameter. Findings identify the root API, parameter channel, forwarding
path and source locations.

Two scan scopes share the same detection core:

- `scan_package()` scans a whole library version for VPPs.
- `scan_api()` scans one API and its downstream forwarding paths on demand.

Both return a `ScanReport` with positive findings and `has_vpp`. Analysis
limits are recorded separately in `boundaries`; an empty findings collection
means no VPP was detected within the supported analysis, rather than proof
that all dynamic Python behavior is compatible.

VPPDetector uses PCResolve for program facts and call resolution. API matching,
parameter-change detection, repair selection and repair verification belong
to PCART. A separate `assess_change()` interface supplies call-specific handling
facts for one already identified parameter change; it does not produce patches.
The repository remains a research scanner and an incubation area for later
PCART integration. Formal PCART integration has not shipped, and there is no
separate PyPI release.

## Requirements

- Python 3.9 or newer
- PCResolve newer than 1.0.7 (`pcresolve>1.0.7`)

The analyzer requires callable, container and incoming-context facts introduced
after PCResolve's `v1.0.7` tag. No Git revision is pinned; pip selects a
compatible release newer than 1.0.7.

From this checkout, install the package in editable mode:

```shell
python -m pip install -e .
```

This installs PCResolve and the other declared dependencies.
PCResolve runs in the analyzer's Python environment; the analyzed library does
not need to be installed or imported. Until a PCResolve release newer than
1.0.7 is available on the package index, this installation command cannot
resolve the dependency.

## Minimal example

Create the following source layout, with an empty `__init__.py`:

```text
example_lib/
└── example/
    ├── __init__.py
    └── api.py
```

Put this code in `example_lib/example/api.py`:

```python
def target(allowed=0):
    return allowed


def wrapper(**kwargs):
    return target(**kwargs)


def consumed(**kwargs):
    return kwargs.pop("obsolete", 0)
```

The scan examples below detect `wrapper` forwarding `**kwargs` to the fixed
signature of `target`. Parameter-level analysis distinguishes
`wrapper(obsolete=7)` (`rejected`) from `wrapper(allowed=7)` (`handled`) and
`consumed(obsolete=7)` (`handled`). The change itself is supplied by the caller;
VPPDetector does not compare library versions to discover it.

## Whole-package scan

Scan one source version and print a JSON report:

```shell
python vppdetector.py example_lib
```

Write the report to a file:

```shell
python vppdetector.py example_lib --output report.json
```

Use repeated `--import-root` options when module names cannot be derived from
the package root. The root script remains a thin whole-package scan entry
point, with optional JSON output for standalone use.

Run `python vppdetector.py --help` for the complete option list. `--max-depth`
defaults to five forwarding hops; source-resolved return-producing calls also
count toward this limit. `--output` writes to a file in an existing directory;
without it, the report is printed to standard output.

### Scan report

Python callers receive a `ScanReport`; only the standalone CLI serializes it
to JSON. Important fields are:

| Field | Meaning |
| --- | --- |
| `has_vpp` | Whether at least one structural finding was detected. |
| `functions_scanned` | Indexed, non-overload function entries considered in this scope; not a count of proven-safe APIs. |
| `variadic_functions` | Entries with `*args` or `**kwargs`. |
| `findings` | Root API, variadic channel, downstream signature, source locations and forwarding path. |
| `boundaries` | Unresolved targets, unsupported effects and other analysis limits; these are not findings. |
| `target_api` / `resolved_api` | Requested and resolved implementation identities for an on-demand scan; absent for a whole-package scan. |
| `analyzer_schema_version` | PCResolve program-fact schema version, not a VPPDetector JSON-format version. |

Each finding and path step retains `target_status`. A source candidate is not
necessarily an exact runtime target, so `has_vpp` is not a client-call failure
or compatibility verdict. Enum values in JSON are lowercase strings such as
`var_keyword`; paths are serialized as strings.

## Python API

### Whole-library scan

```python
from vppdetector import scan_package

report = scan_package("example_lib")
print(report.has_vpp)
for finding in report.findings:
    print(finding.function, finding.parameter_kind, finding.target)
    for step in finding.path:
        print(step.function, step.callee_expression, step.callsite)
```

### On-demand API scan

```python
from pathlib import Path

from vppdetector import AnalysisContext, FunctionIdentity, SourceContext, scan_api

source = SourceContext(Path("example_lib"))
context = AnalysisContext.from_source(source)
report = scan_api(
    source,
    FunctionIdentity("example.api", "wrapper"),
    context=context,
)
print(report.has_vpp)
```

### Source identities

`package_root` selects the source scope. An `import_root` is the directory
relative to which Python module names are formed, not necessarily the package
directory itself. In the example, the module is `example.api`, the function's
`qualname` is `wrapper`, and its file is `example_lib/example/api.py`.
For methods, use a qualified name such as `Client.fetch`.

Default import roots follow the source layout:

| Source scope | Default import root |
| --- | --- |
| Package directory containing `__init__.py` | Its parent directory. |
| Project directory containing `src/` | The `src/` directory. |
| Other source directory | The directory itself. |
| One source file | Its parent directory. |

Supply `SourceContext(..., import_roots=(Path(...),))` or CLI `--import-root`
when these defaults do not match the library's layout. `file_path`, when
provided, must lie within the source scope. It locates the implementation,
not a client file; an optional `lineno` must match its definition.

Reusing an `AnalysisContext` retains the source index and analysis caches for
multiple APIs from the same library version. Both scan functions accept
`max_depth` (default five) and optional `import_roots`. On-demand scans resolve
the requested API to its source implementation; findings retain the requested
API identity and the path retains implementation identities.

When the implementation file is known, prepare a smaller context without
depending on any particular API-mapping tool:

```python
from pathlib import Path

from vppdetector import AnalysisContext, FunctionIdentity, SourceContext, scan_api

source = SourceContext(Path("example_lib"))
target = FunctionIdentity(
    "example.api", "wrapper", file_path=source.package_root / "example" / "api.py"
)
context = AnalysisContext.for_api(source, target)
report = scan_api(source, target, context=context)
```

`for_api()` indexes the located file, package initializers and explicit imports
within the source root, sharing one AST parse for dependency discovery and VPP
indexing. It also works with `assess_change()`. Without a file hint it retains
full-source preparation. File/name/line conflicts are not resolved by guessing;
unavailable implementations and unproven downstream calls remain boundaries.
Dynamic dependencies are not inferred, and an import closure is not proof of
complete runtime coverage. Module names are derived from `SourceContext`'s import
roots, not from PCART-specific metadata or files.

An API-scoped context cannot be used for `scan_package()`; use `from_source()`
for whole-library scanning. Reuse a context only for definitions/dependencies
already in its fixed file set and while its source snapshot is unchanged. A
different entry outside that set needs its own context or a full-source context.

### Scan coverage and limits

The scanner supports functions, methods, `async def`, cross-file imports,
aliases, public class re-exports, inherited methods and source constructor
entries (`__init__`, otherwise `__new__`). Ambiguous constructor definitions
are not replaced with a guessed entry. Bounded multi-hop propagation includes
source-resolved helpers returning a whole container, including selection through
exact nonnegative tuple return slots. Slot dependencies are routed before checking
the final open-container shape; finite contents and selected input elements are
not treated as open forwarding. The evidence path retains return-producing calls,
and they count toward `max_depth`. Classmethod and
`__new__` helper forwarding retains source-proven incoming PCResolve receiver
contexts. Missing or mixed receiver facts remain boundaries; mutable configuration
attributes and class-context container returns are not inferred. Passing a mapping
or sequence as an ordinary parameter is a propagation hop, not a VPP
by itself; a finding requires an eventual `**mapping` or `*sequence` expansion
into a signature without the matching variadic parameter. Unresolved targets,
unsupported propagation, recursion and depth limits remain visible diagnostics.
Ordinary helpers also retain incoming source-callable bindings when PCResolve
provides an exact call-edge context. Mixed incoming contexts remain boundaries;
the scanner does not infer callable targets from names or strings.
Unknown effects on returned containers and transformations without open-shape
facts (including comprehensions, copies and slices) remain analysis boundaries.
When PCResolve supplies a proven returned-object alias, the scanner uses its
separately materialized current contents, not the object's old input dependencies.
Modeled finite-key removal retains the open remainder; clearing an alias does not
restore the original contents. Object identity alone does not establish VPP.
Complete ordinary-parameter constant-key removal facts can also preserve
propagation through an existing alias. Normal-return effects do not prove call
success or unconditional removal on exception paths; unproven effects remain
analysis boundaries.
When PCResolve proves a decorated callable's identity but leaves its effects
unmodeled, the scanner does not use that callee's body to prove container returns
or further forwarding. Direct expansion findings against its nominal signature
retain the effects diagnostic; they do not assert that decoration was effect-free.
Source-candidate paths retain their target status: a finding does not establish
exact runtime dispatch or prove that a particular client call will fail.

Structural findings alone are not permission to delete or rename an argument:
a fixed downstream signature may still accept that particular name, or the
library may consume its value before forwarding the remaining keywords.

### Parameter-level assessment

```python
from pathlib import Path

from vppdetector import (
    AnalysisContext,
    ChangeKind,
    FunctionIdentity,
    ParameterChange,
    SourceContext,
    assess_change,
)

source = SourceContext(Path("example_lib"))
target = FunctionIdentity(
    "example.api", "wrapper", file_path=source.package_root / "example" / "api.py"
)
context = AnalysisContext.for_api(source, target)

assessment = assess_change(
    source,
    target,
    ParameterChange(ChangeKind.DELETE, "obsolete"),
    "wrapper(obsolete=7)",
    context=context,
)
print(assessment.state.value)  # rejected
```

The input is the new source snapshot, selected API implementation, one deletion
or rename, and the original call expression or `ast.Call`. Results are ordinary
Python objects with binding/use/path evidence and analysis boundaries:

- `HANDLED`: the argument's value or presence is used, or its value binds to a
  downstream explicit parameter. This is not a guarantee of behavior equivalence.
- `REJECTED`: the supported call conditions lead to a parameter-specific binding
  rejection. PCART still has to generate and verify a repair candidate.
- `IGNORED`: the supported executed paths do not use the argument's value or
  presence. Ignoring an argument is not itself permission to delete it.
- `UNKNOWN`: binding, control flow, dispatch or effects prevent a definite result.

`ParameterAssessment` retains `target_api`, `resolved_api`, `change` and the
original `call_text`. Its `state` is a `ParameterState` enum (serialized values
are `handled`, `rejected`, `ignored`, `unknown`); `reason` explains the outcome,
`evidence` records supporting bindings/uses/paths, and `boundaries` records
analysis limits. These are argument-handling facts, not a repair instruction.

The initial scope covers changed keywords captured by `**kwargs` (regardless of
the container's name), direct/alias forwarding, finite expansions, bounded `pop`
effects, simple literal/default-value guards and source-resolved downstream
binding. Positional-element propagation, exception recovery, unknown mutation,
deferred execution and unsupported transformations remain explicit boundaries.
Assessment does not require a positive structural finding first.

`CallContext` can additionally carry `bound_receiver`, trusted primitive
`known_values` under source parameter names or receiver attribute paths, and
`known_targets` pairing exact library `SourceSpan` locations with confirmed
`FunctionIdentity` implementations. Facts must describe this call and this
source version. A nominal PCResolve candidate is not a target confirmation;
uncertain class dispatch remains `UNKNOWN` without independent evidence.
The analyzer never executes client argument expressions or loads runtime object
graphs. Context caches retain program facts, not API-only assessment decisions.

These facts are intended to refine PCART's variadic preservation rule per
changed argument, not for the entire `*args`/`**kwargs` channel. API evolution
facts stay intact; PCART owns final compatibility decisions, candidate
operations and whole-call verification. No separate assessment CLI is provided.

## Source layout

| File | Responsibility |
| --- | --- |
| `vppdetector.py` | Standalone whole-package scan CLI and JSON serialization. |
| `vppdetector/__init__.py` | Public Python interfaces. |
| `vppdetector/models.py` | Source identities, findings and parameter-level evidence. |
| `vppdetector/source.py` | Source indexing, import roots and API location. |
| `vppdetector/core.py` | Shared propagation logic, PCResolve adapter and reusable analysis context. |
| `vppdetector/scanner.py` | Whole-package and on-demand scan scopes. |
| `vppdetector/assessment.py` | Call-specific analysis of one already identified parameter change. |
| `vppdetector/encoding.py` | Retained encoding helper; source indexing uses Python's declared source encoding. |

The shared analyzer does not read PCART configuration or API-mapping artifacts.
A future PCART adapter will translate those inputs into these Python models and
consume returned objects; JSON is not required between the two tools.

## Version 1.0 research scanner

The original implementation is retained in `legacy_vppdetector.py`; it
depends on PCART internals and contains dataset-specific paths. It is no longer
the default `vppdetector.py` entry point.

Historical outputs under `APIDefWithVariadicPara/` and
`VariadicParaPitfalls/` are unchanged. They contain the original scanner's
variadic API listings and potential pitfall records, respectively; they use the
historical format, not the current `ScanReport` format.

## Publication

```bibtex
@inproceedings{zhang2024coding,
  title={Coding Pitfalls: Demystifying the Potential API Compatibility Risk of Variadic Parameters in Python},
  author={Zhang, Shuai and He, Gangqiang and Xiao, Guanping},
  booktitle={2024 IEEE 35th International Symposium on Software Reliability Engineering Workshops (ISSREW)},
  pages={105--106},
  year={2024},
  organization={IEEE}
}
```

## License

VPPDetector is licensed under GNU AGPLv3. PCResolve is an MIT-licensed
dependency; see `THIRD_PARTY_NOTICES.md`.
