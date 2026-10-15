"""Fixed source preparation and shared facts, independent of scan/assess policy."""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Optional, Sequence, Union

from ._fact_adapter import PCResolveAdapter
from ._program_facts import identity_from_target
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
    _transform_spans: dict = field(default_factory=dict, init=False, repr=False)
    _return_transform_spans: dict = field(default_factory=dict, init=False, repr=False)
    _constant_tests: dict = field(default_factory=dict, init=False, repr=False)

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
        return cls(index=index, adapter=PCResolveAdapter(index))

    def resolve_api(self, identity: FunctionIdentity) -> Optional[IndexedFunction]:
        entry = self.index.find(identity) or self.index.resolve_imported(identity)
        if entry is not None:
            return entry
        if identity.file_path or identity.lineno:
            return None
        # Resolve the public class prefix before asking PCResolve for an
        # inherited implementation. Never fall back to a terminal name match.
        method = self.index.resolve_method_identity(identity)
        analysis = self.adapter.analyze(method or identity)
        return self.index.find(identity_from_target(analysis.entry))


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


