## @package vppdetector._analysis_context
#  Prepare reusable analysis state for one library source snapshot.
#
#
#  Build the source index and fact adapter together, then attach caches for one source snapshot.
#  Check entry identity and binding before handing definitions to consumers.
#  为同一源码快照装配索引、事实适配器及各类缓存，并在交付定义前校验入口身份和绑定。



from pathlib import Path

from ._records import MutableRecord
from .assess.context_cache import AssessmentContexts, ContextVarPackageCache
from .facts.adapter import PCResolveAdapter, ResolutionError
from .facts.bindings import source_alias_entry
from .facts.calls import identity_from_target
from .facts.conditions import ConstantTests
from .facts.creation import source_constructor_entry_binding
from .models import SourceContext, replace_record
from .scan.cache import ScanResults, TransformLocations
from .source import build_source_index, normalized_import_roots
from .source.queries import SourceQueries


## Reusable source and PCResolve state for one library source version.
#
## 单个库源码版本的可复用源码及 PCResolve 状态。
class AnalysisContext(MutableRecord):
    _record_fields = (
        "index",
        "adapter",
        "scan_results",
        "assessment_contexts",
        "transform_locations",
        "constant_tests",
        "contextvar_packages",
        "_source_queries",
    )
    _record_repr_fields = ("index", "adapter")
    __match_args__ = ("index", "adapter")

    ## Initialize source analysis state and its context-local caches.
    ## 初始化源码分析状态及上下文级缓存。
    #
    #  @param index Source index shared by this analysis context
    #  @param adapter PCResolve adapter bound to the source index
    #  @param source_store Optional validated source store reused for source queries
    def __init__(self, index, adapter, source_store=None):
        self.index = index
        self.adapter = adapter
        self.scan_results = ScanResults()
        self.assessment_contexts = AssessmentContexts()
        self.transform_locations = TransformLocations()
        self.constant_tests = ConstantTests()
        self.contextvar_packages = ContextVarPackageCache()
        self._source_queries = SourceQueries(source_store)

    ## Expose the context-owned source query service without replacing it.
    ## 提供上下文持有的源码查询服务，不允许替换该服务。
    #
    #  @return Source queries bound to this context's source store
    #           绑定到此上下文源码存储的源码查询服务
    @property
    def source_queries(self):
        return self._source_queries

    ## Build a reusable analysis context from a source context
    ## 根据源码上下文构建可复用的分析上下文
    #
    #  @param cls Analysis context class receiving the factory call
    #  @param source Library source directory, file, or source context
    #  @return Reusable context built from the indexed source snapshot
    @classmethod
    def from_source(cls, source):
        return cls.from_index(build_source_index(source))

    ## Prepare a located API and its explicit package-local import closure
    ## 准备指定API及其明确的包内导入闭包
    #
    #  @param cls Analysis context class receiving the factory call
    #  @param source Library source directory, file, or source context
    #  @param target_api Source identity of the API being analyzed
    #  @return Context indexed for the requested API and its package-local imports
    @classmethod
    def for_api(cls, source, target_api):
        return cls.from_index(build_source_index(source, target_api=target_api))

    ## Build analysis state from an already prepared source index
    ## 根据已准备的源码索引构建分析状态
    #
    #  @param cls Analysis context class receiving the factory call
    #  @param index Source index used for definitions and imports
    #  @return Context sharing the index's validated source documents
    @classmethod
    def from_index(cls, index):
        # Share only the producer's validated source documents; query results stay local.
        # 仅共享生产者校验过的源码文档，查询结果仍属于当前上下文。
        return cls(index=index, adapter=PCResolveAdapter(index), source_store=index.source_store)

    ## Resolve the requested API to one source implementation with checked entry facts
    ## 将请求的API解析为唯一源码实现并校验入口事实
    #
    #  @param identity Source-level identity used for lookup
    #  @return Checked source implementation, or None if no implementation is resolved
    #  @exception ResolutionError If required entry binding or source facts are unavailable
    def resolve_api(self, identity):
        entry = self.index.find(identity)
        if entry is not None:
            return self._checked_entry(entry, identity)
        source_class = self.index.resolve_class(identity)

        # Assess callers often identify a constructor by its implementation
        # (`Widget.__init__`) rather than by the class (`Widget`).  Entry
        # binding is a class-call fact, so resolve that exact owning class
        # before falling back to inherited method lookup.  Preserve file and
        # line hints: they identify the PCBench source version being assessed.
        # 调用方可能用构造器实现（`Widget.__init__`）而非类名标识目标；入口绑定属于类调用事实，
        # 因此先解析所属类，再尝试继承方法查找，并保留用于定位PCBench源码版本的文件和行号。
        if source_class is None and identity.qualname.endswith(".__init__"):
            owner = identity.qualname.rpartition(".")[0]
            if owner:
                source_class = self.index.resolve_class(replace_record(identity, qualname=owner))
        if source_class is not None:
            try:
                analysis = self.adapter.analyze(source_class)
            except ResolutionError as exc:
                if exc.code != "flow_analysis_failed":
                    raise
                raise ResolutionError(str(exc), "constructor_analysis_failed") from exc
            fact = source_constructor_entry_binding(analysis, source_class)
            entry = self.index.find(identity_from_target(analysis.entry))
            parameters = (entry.node.args.posonlyargs + entry.node.args.args) if entry else ()
            if (
                entry is None
                or fact is None
                or not parameters
                or fact["implicit_binding"]["parameter"] != parameters[0].arg
            ):
                raise ResolutionError(
                    "Source class invocation binding is unavailable or unconfirmed.",
                    "constructor_entry_unconfirmed",
                )
            return self._checked_entry(
                replace_record(entry, query_class=source_class, is_bound_method=True),
                identity,
                analysis,
            )
        entry = self.index.resolve_imported(identity)
        if entry is not None:
            return self._checked_entry(entry, identity)
        if identity.file_path or identity.lineno:
            try:
                analysis = self.adapter.analyze(identity)
            except ResolutionError:
                return None
            entry = self.index.find(identity_from_target(analysis.entry))
            return (
                self._checked_entry(replace_record(entry, query_alias=identity), identity, analysis)
                if entry and source_alias_entry(analysis, identity)
                else None
            )

        # Resolve the public class prefix before asking PCResolve for an
        # inherited implementation. Never fall back to a terminal name match.
        # 查询继承实现前先解析公开类前缀；绝不回退到仅按末尾名称匹配。
        method = self.index.resolve_method_identity(identity)
        analysis = self.adapter.analyze(method or identity)
        entry = self.index.find(identity_from_target(analysis.entry))
        if (
            "entry_alias" in analysis.inputs
            or any(
                boundary.get("reason") == "source_entry_alias" for boundary in analysis.boundaries
            )
            or entry
            and entry.identity.qualname.rsplit(".", 1)[-1]
            != (method or identity).qualname.rsplit(".", 1)[-1]
        ):
            if entry is None or source_alias_entry(analysis, method or identity) is None:
                raise ResolutionError("Source API alias evidence is unavailable or conflicting.")
            return self._checked_entry(
                replace_record(entry, query_alias=method or identity), identity, analysis
            )
        return self._checked_entry(entry, identity, analysis) if entry is not None else None

    ## Reject an explicitly uncertain public lookup, separately from body facts
    ## 将公开入口查找的不确定性与函数体事实分开校验
    #
    #  @param entry Resolved source entry for the requested API
    #  @param lookup Requested source identity for the lookup
    #  @param analysis Optional producer analysis; obtained from the adapter when omitted
    #  @return The indexed entry after its public binding facts are checked
    #  @exception ResolutionError If entry binding facts are missing or conflicting
    def _checked_entry(
        self,
        entry,
        lookup,
        analysis=None,
    ):
        analysis = analysis or self.adapter.analyze(entry.query_alias or entry.identity)
        root_name = lookup.qualname.partition(".")[0]
        records = analysis.inputs.get("module_global_rebindings")
        if not isinstance(records, (list, tuple)) or any(
            not isinstance(record, dict)
            or record.get("kind") != "module_global_rebinding"
            or record.get("status") != "may_write"
            or record.get("basis") != "source_snapshot"
            or not isinstance(record.get("module"), str)
            or not record["module"]
            or not isinstance(record.get("name"), str)
            or not record["name"]
            or not isinstance(record.get("source_hash"), str)
            or not isinstance(record.get("declarations"), (list, tuple))
            or not record["declarations"]
            or any(
                not isinstance(source, dict)
                or source.get("file_path") not in analysis.inputs.get("sha256", {})
                or any(
                    type(source.get(key)) is not int
                    for key in ("lineno", "col_offset", "end_lineno", "end_col_offset")
                )
                or source["lineno"] < 1
                or source["col_offset"] < 0
                or source["end_col_offset"] < 0
                or (source["end_lineno"], source["end_col_offset"])
                <= (source["lineno"], source["col_offset"])
                or analysis.inputs["sha256"][source["file_path"]] != record["source_hash"]
                for source in record["declarations"]
            )
            for record in records
        ):
            raise ResolutionError(
                "Module entry binding facts are unavailable or conflicting.",
                "entry_binding_facts_unavailable",
            )

        # Rebinding the public root requires matching entry evidence.
        # 公开 API 的根名称被重新绑定时，需要匹配的入口证据。
        rebound = any(
            record["module"] == lookup.module and record["name"] == root_name for record in records
        )
        if (
            any(
                boundary.get("reason") == "module_callable_binding_unconfirmed"
                and (boundary.get("lookup_scope") == "module_entry" or not boundary.get("call_id"))
                for boundary in analysis.boundaries
            )
            or rebound
        ):
            raise ResolutionError(
                "The public source callable has visible global rebinding.",
                "entry_callable_binding_unconfirmed",
            )
        return entry


## Validate or construct the source index and matching analysis context
## 校验或构建源码索引及对应的分析上下文
#
#  @param package_root Root directory or file of the library source
#  @param import_roots Module roots used to resolve source imports
#  @param context Reusable analysis context for the selected source snapshot
#  @return Source index and matching context; the context is None if no files were found
#  @exception ValueError If a supplied context uses different source or import roots
def prepare_context(
    package_root,
    import_roots,
    context,
):
    if isinstance(package_root, SourceContext):
        source = package_root
        if import_roots is not None:
            source = replace_record(source, import_roots=tuple(Path(path) for path in import_roots))
    else:
        source = SourceContext(
            package_root=Path(package_root),
            import_roots=tuple(Path(path) for path in (import_roots or ())),
        )

    # A reusable context is valid only for the same source and import scope.
    # 复用的分析上下文必须与当前源码及导入范围一致。
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


## Require a positive integer forwarding-depth limit
## 要求转发深度限制为正整数
#
#  @param max_depth Maximum number of forwarding steps to analyze
#  @exception ValueError If max_depth is not a positive integer or is a boolean
def validate_depth(max_depth):
    if isinstance(max_depth, bool) or not isinstance(max_depth, int) or max_depth < 1:
        raise ValueError("max_depth must be a positive integer")
