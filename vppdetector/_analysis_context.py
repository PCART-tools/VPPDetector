"""Fixed source preparation and shared facts, independent of scan/assess policy."""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Optional, Sequence, Union

from ._fact_adapter import PCResolveAdapter, ResolutionError
from ._program_facts import (
    identity_from_target,
    source_alias_entry,
    source_constructor_entry_binding,
)
from ._source_queries import SourceQueries
from .models import FunctionIdentity, SourceContext
from .source import IndexedFunction, SourceIndex, build_source_index, normalized_import_roots

PathLike = Union[str, Path]
ScanSource = Union[PathLike, SourceContext]


@dataclass
class AnalysisContext:
    """Reusable source and PCResolve state for one library source version."""

    index: SourceIndex
    adapter: PCResolveAdapter
    _scan_cache: dict = field(default_factory=dict, init=False, repr=False)
    _class_context_cache: dict = field(default_factory=dict, init=False, repr=False)
    _transform_spans: dict = field(default_factory=dict, init=False, repr=False)
    _return_transform_spans: dict = field(default_factory=dict, init=False, repr=False)
    _constant_tests: dict = field(default_factory=dict, init=False, repr=False)
    _dispatch_context_cache: dict = field(default_factory=dict, init=False, repr=False)
    _source_queries: SourceQueries = field(default_factory=SourceQueries, init=False, repr=False)

    @classmethod
    def from_source(cls, source: SourceContext) -> "AnalysisContext":
        return cls.from_index(build_source_index(source))

    @classmethod
    def for_api(cls, source: SourceContext, target_api: FunctionIdentity) -> "AnalysisContext":
        """Prepare a located API and its explicit package-local import closure.

        Without a file hint, retain full-source preparation. Reuse this context
        only for APIs whose implementations/dependencies are in its fixed file
        set and only while the source snapshot remains unchanged.
        """

        return cls.from_index(build_source_index(source, target_api=target_api))

    @classmethod
    def from_index(cls, index: SourceIndex) -> "AnalysisContext":
        context = cls(index=index, adapter=PCResolveAdapter(index))
        context._source_queries = SourceQueries(index.source_store)
        return context

    def resolve_api(self, identity: FunctionIdentity) -> Optional[IndexedFunction]:
        entry = self.index.find(identity)
        if entry is not None:
            return self._checked_entry(entry, identity)
        source_class = self.index.resolve_class(identity)
        # Assess callers often identify a constructor by its implementation
        # (`Widget.__init__`) rather than by the class (`Widget`).  Entry
        # binding is a class-call fact, so resolve that exact owning class
        # before falling back to inherited method lookup.  Preserve file and
        # line hints: they identify the PCBench source version being assessed.
        if source_class is None and identity.qualname.endswith('.__init__'):
            owner = identity.qualname.rpartition('.')[0]
            if owner:
                source_class = self.index.resolve_class(replace(
                    identity, qualname=owner))
        if source_class is not None:
            analysis = self.adapter.analyze(source_class)
            fact = source_constructor_entry_binding(analysis, source_class)
            entry = self.index.find(identity_from_target(analysis.entry))
            parameters = (entry.node.args.posonlyargs + entry.node.args.args) if entry else ()
            if (fact is None or not parameters
                    or fact["implicit_binding"]["parameter"] != parameters[0].arg):
                raise ResolutionError(
                    "Source class invocation binding is unavailable or unconfirmed.",
                    "constructor_entry_unconfirmed")
            return self._checked_entry(
                replace(entry, query_class=source_class, is_bound_method=True), identity, analysis)
        entry = self.index.resolve_imported(identity)
        if entry is not None:
            return self._checked_entry(entry, identity)
        if identity.file_path or identity.lineno:
            try:
                analysis = self.adapter.analyze(identity)
            except ResolutionError:
                return None
            entry = self.index.find(identity_from_target(analysis.entry))
            return (self._checked_entry(replace(entry, query_alias=identity), identity, analysis)
                    if entry and source_alias_entry(analysis, identity) else None)
        # Resolve the public class prefix before asking PCResolve for an
        # inherited implementation. Never fall back to a terminal name match.
        method = self.index.resolve_method_identity(identity)
        analysis = self.adapter.analyze(method or identity)
        entry = self.index.find(identity_from_target(analysis.entry))
        if ('entry_alias' in analysis.inputs
                or any(boundary.get('reason') == 'source_entry_alias'
                       for boundary in analysis.boundaries)
                or entry and entry.identity.qualname.rsplit('.', 1)[-1]
                    != (method or identity).qualname.rsplit('.', 1)[-1]):
            if entry is None or source_alias_entry(analysis, method or identity) is None:
                raise ResolutionError('Source API alias evidence is unavailable or conflicting.')
            return self._checked_entry(
                replace(entry, query_alias=method or identity), identity, analysis)
        return self._checked_entry(entry, identity, analysis) if entry is not None else None

    def _checked_entry(
        self, entry: IndexedFunction, lookup: FunctionIdentity, analysis=None,
    ) -> IndexedFunction:
        """Reject an explicitly uncertain public lookup, separately from body facts."""
        analysis = analysis or self.adapter.analyze(entry.query_alias or entry.identity)
        root_name = lookup.qualname.partition('.')[0]
        records = analysis.inputs.get('module_global_rebindings')
        if (not isinstance(records, (list, tuple)) or any(not isinstance(record, dict)
                or record.get('kind') != 'module_global_rebinding'
                or record.get('status') != 'may_write' or record.get('basis') != 'source_snapshot'
                or not isinstance(record.get('module'), str) or not record['module']
                or not isinstance(record.get('name'), str) or not record['name']
                or not isinstance(record.get('source_hash'), str)
                or not isinstance(record.get('declarations'), (list, tuple))
                or not record['declarations']
                or any(not isinstance(source, dict)
                    or source.get('file_path') not in analysis.inputs.get('sha256', {})
                    or any(type(source.get(key)) is not int for key in (
                        'lineno', 'col_offset', 'end_lineno', 'end_col_offset'))
                    or source['lineno'] < 1 or source['col_offset'] < 0
                    or source['end_col_offset'] < 0
                    or (source['end_lineno'], source['end_col_offset'])
                        <= (source['lineno'], source['col_offset'])
                    or analysis.inputs['sha256'][source['file_path']] != record['source_hash']
                    for source in record['declarations']) for record in records)):
            raise ResolutionError('Module entry binding facts are unavailable or conflicting.',
                                  'entry_binding_facts_unavailable')
        rebound = any(record['module'] == lookup.module and record['name'] == root_name
                      for record in records)
        if any(boundary.get('reason') == 'module_callable_binding_unconfirmed'
               and (boundary.get('lookup_scope') == 'module_entry'
                    or not boundary.get('call_id'))
               for boundary in analysis.boundaries) or rebound:
            raise ResolutionError('The public source callable has visible global rebinding.',
                                  'entry_callable_binding_unconfirmed')
        return entry


def prepare_context(
    package_root: ScanSource,
    import_roots: Optional[Sequence[PathLike]],
    context: Optional[AnalysisContext],
) -> tuple[SourceIndex, Optional[AnalysisContext]]:
    if isinstance(package_root, SourceContext):
        source = package_root
        if import_roots is not None:
            source = replace(source, import_roots=tuple(Path(path) for path in import_roots))
    else:
        source = SourceContext(
            package_root=Path(package_root),
            import_roots=tuple(Path(path) for path in (import_roots or ())),
        )
    if context is not None:
        expected = SourceContext(source.package_root.resolve(), normalized_import_roots(source))
        actual = context.index.source
        if (
            actual.package_root.resolve() != expected.package_root
            or normalized_import_roots(actual) != expected.import_roots
        ):
            raise ValueError("Analysis context must use the requested source root and import roots")
        context.adapter.validate_source()
        return context.index, context
    index = build_source_index(source)
    return index, AnalysisContext.from_index(index) if index.files else None


def validate_depth(max_depth: int) -> None:
    if isinstance(max_depth, bool) or not isinstance(max_depth, int) or max_depth < 1:
        raise ValueError("max_depth must be a positive integer")


