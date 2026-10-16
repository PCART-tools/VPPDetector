"""Versioned PCResolve facts, independent of either VPP consumer's policy."""

from __future__ import annotations

import hashlib
import os
from dataclasses import asdict, dataclass, fields, is_dataclass

from ._readonly import readonly
from .source import _python_files


class ResolutionError(RuntimeError):
    """An unavailable producer or fact contract; consumers retain a boundary."""

    def __init__(self, message, code="flow_analysis_failed"):
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class FactCapabilities:
    schema: str
    call_fields: tuple
    basis: str = "structural_contract"


_CALL_FIELDS = (
    "id", "caller", "callee_name", "lineno", "col_offset", "end_lineno", "end_col_offset",
    "target", "target_status", "target_candidates", "analysis_status", "binding_status",
    "binding_issues", "argument_sources", "argument_flows", "parameter_bindings", "parameter_flows",
    "return_flows", "return_dependencies", "result_sources", "effects", "capture_bindings",
    "receiver_sources", "receiver_type_evidence", "analysis_contexts", "conditional_returns",
    "callable_sources",
)
_CALL_LISTS = (
    "target_candidates", "binding_issues", "argument_sources", "argument_flows",
    "parameter_bindings", "parameter_flows", "return_flows", "return_dependencies",
    "result_sources", "effects",
    "capture_bindings", "receiver_sources", "receiver_type_evidence", "analysis_contexts",
    "conditional_returns", "callable_sources",
)


def _path(path):
    return os.path.normcase(os.path.abspath(path))


def _digest(path):
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        return None


class PCResolveAdapter:
    """Keep source-only immutable facts; all domain query state stays outside."""

    def __init__(self, index):
        try:
            from pcresolve import FlowAnalyzer, FlowCall
        except ImportError as exc:
            raise ResolutionError("PCResolve value-flow analysis is required") from exc
        self._analyzer = FlowAnalyzer(source_files=index.files,
                                      import_roots=index.source.import_roots)
        self._import_roots = tuple(_path(path) for path in self._analyzer.roots)
        self.capabilities = FactCapabilities("flow-0.2", tuple(
            item.name for item in fields(FlowCall)) if is_dataclass(FlowCall) else ())
        self._index = index
        # A caller-built index may deliberately contain only selected files.
        # Only a full package snapshot can promise detection of added files.
        self._full_package = (not index.is_api_scope and
                              tuple(_python_files(index.source.package_root)) == index.files)
        self._source_hashes = {path: _digest(path) for path in index.files}
        self._flow_hashes = {}
        for path in index.files:
            try:
                with path.open(encoding="utf-8-sig") as stream:
                    text = stream.read()
            except (OSError, UnicodeError):
                continue
            self._flow_hashes[_path(path)] = hashlib.sha256(text.encode("utf-8")).hexdigest()
        self._analysis_cache = {}
        self._expansion_cache = {}

    def validate_source(self):
        """Validate once per public query, including before a domain cache hit."""

        if (self._full_package
                and tuple(_python_files(self._index.source.package_root)) != self._index.files):
            raise ValueError("Source files changed; create a new analysis context")
        if any(_digest(path) != digest for path, digest in self._source_hashes.items()):
            raise ValueError("Source content changed; create a new analysis context")

    def _validate(self, analysis):
        missing = [name for name in ("entry", "inputs", "functions", "calls", "boundaries")
                   if not hasattr(analysis, name)]
        if missing or getattr(analysis, "schema_version", None) != self.capabilities.schema:
            raise ResolutionError("PCResolve fact contract unavailable: schema or root fields",
                                  "pcresolve_fact_contract_unavailable")
        if (not isinstance(analysis.inputs, dict)
                or not all(isinstance(getattr(analysis, name), list)
                           for name in ("functions", "calls", "boundaries"))
                or not hasattr(analysis.entry, "file_path")
                or not all(isinstance(item, dict)
                           for item in analysis.functions + analysis.boundaries)):
            raise ResolutionError("PCResolve fact contract unavailable: root field types",
                                  "pcresolve_fact_contract_unavailable")
        for call in analysis.calls:
            absent = [name for name in _CALL_FIELDS if not hasattr(call, name)]
            if absent or not is_dataclass(call):
                raise ResolutionError("PCResolve fact contract unavailable: call fields "
                                      + ", ".join(absent), "pcresolve_fact_contract_unavailable")
            if (not all(isinstance(getattr(call, name), list) for name in _CALL_LISTS)
                    or not hasattr(call.caller, "file_path")):
                raise ResolutionError("PCResolve fact contract unavailable: call field types",
                                      "pcresolve_fact_contract_unavailable")
        inputs = analysis.inputs
        sources = inputs.get("source_files")
        hashes = inputs.get("sha256")
        roots = inputs.get("import_roots")
        if (not isinstance(sources, list) or not isinstance(hashes, dict)
                or not isinstance(roots, list)
                or not all(isinstance(path, str) for path in sources + roots + list(hashes))
                or {_path(path) for path in sources} != {_path(p) for p in self._index.files}
                or tuple(_path(path) for path in roots) != self._import_roots
                or _path(analysis.entry.file_path) not in {_path(p) for p in hashes}
                or any(self._flow_hashes.get(_path(path)) != digest
                       for path, digest in hashes.items())):
            raise ResolutionError("PCResolve fact contract unavailable: source snapshot mismatch",
                                  "pcresolve_fact_contract_unavailable")

    def analyze(self, function, max_depth=1, *, conditional_source_state=False):
        from pcresolve import FunctionRef

        key = ((function, max_depth, 'conditional_source_state')
               if conditional_source_state else (function, max_depth))
        if key not in self._analysis_cache:
            entry = FunctionRef(module=function.module, qualname=function.qualname,
                                file_path=str(function.file_path or ""),
                                lineno=function.lineno or 0)
            try:
                if conditional_source_state:
                    result = self._analyzer.analyze(entry, max_depth=max_depth,
                                                    conditional_source_state=True)
                else:
                    result = self._analyzer.analyze(entry, max_depth=max_depth)
            except (KeyError, RuntimeError, ValueError, TypeError) as exc:
                raise ResolutionError(str(exc)) from exc
            self._validate(result)
            if (conditional_source_state
                    and result.inputs.get('conditional_source_state') is not True):
                raise ResolutionError('PCResolve conditional source-state facts are unavailable')
            self._analysis_cache[key] = readonly(result)
        self._analysis_cache[key] = readonly(self._analysis_cache[key])
        return self._analysis_cache[key]

    def expand(self, analysis, call_id, *, isolate=False):
        key = (id(analysis), call_id, 'isolated') if isolate else (id(analysis), call_id)
        if key not in self._expansion_cache:
            self._validate(analysis)
            try:
                if isolate:
                    result = self._analyzer.expand(analysis, call_id, additional_depth=1,
                                                   isolate=True)
                else:
                    result = self._analyzer.expand(analysis, call_id, additional_depth=1)
            except (KeyError, RuntimeError, StopIteration, ValueError, TypeError) as exc:
                raise ResolutionError(str(exc)) from exc
            self._validate(result)
            if isolate:
                edge = next(call for call in analysis.calls if call.id == call_id)
                marker = result.inputs.get('expansion_context', {})
                if (not isinstance(marker, dict) or marker.get('incoming_call_id') != call_id
                        or marker.get('caller') != asdict(edge.caller)
                        or edge.target is None or marker.get('target') != asdict(edge.target)
                        or result.entry != edge.target
                        or not isinstance(marker.get('parameter_facts'), dict)):
                    raise ResolutionError('PCResolve isolated incoming context is unavailable')
            self._expansion_cache[key] = analysis, readonly(result)
        return self._expansion_cache[key][1]
