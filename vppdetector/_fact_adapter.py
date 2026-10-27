## @package vppdetector._fact_adapter
#  Adapt versioned PCResolve facts for VPP consumers.
#  为VPP分析消费者适配带版本的PCResolve事实。

"""Versioned PCResolve facts, independent of either VPP consumer's policy."""

from __future__ import annotations

import hashlib
import inspect
import os
from dataclasses import asdict, dataclass, fields, is_dataclass

from ._readonly import readonly
from .source import _python_files


class ResolutionError(RuntimeError):
    """An unavailable producer or fact contract; consumers retain a boundary."""

    ## Initialize the object state required by the enclosing class
    ## 初始化所属类所需的对象状态
    #
    #  @param message Value named `message` supplied by the enclosing analysis.
    #  @param code Value named `code` supplied by the enclosing analysis.
    #  @return None.
    def __init__(self, message, code="flow_analysis_failed"):
        super().__init__(message)
        self.code = code


## Describe the PCResolve fact schema fields supported by the adapter.
## 描述适配器支持的PCResolve事实模式及字段。
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


## Normalize a filesystem path for stable identity comparisons
## 规范化文件系统路径以便稳定比较身份
#
#  @param path Filesystem path of the source being read or checked.
#  @return Result of the `_path` operation.
def _path(path):
    return os.path.normcase(os.path.abspath(path))


## Return the content digest of a source file when it can be read
## 在源码文件可读取时返回其内容摘要
#
#  @param path Filesystem path of the source being read or checked.
#  @return Result of the `_digest` operation.
def _digest(path):
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        return None


## Read once while retaining both byte and flow-text source identities
## 一次读取源码，同时保留字节摘要和flow文本摘要
#
#  @param path Filesystem path of the source being read or checked.
#  @return Result of the `_source_digests` operation.
def _source_digests(path):
    try:
        raw = path.read_bytes()
    except OSError:
        return None, None
    raw_digest = hashlib.sha256(raw).hexdigest()
    try:

        # Match open(..., encoding="utf-8-sig") with universal-newline
        # translation, which is the existing flow digest policy.
        # 按现有flow摘要策略模拟open(..., encoding="utf-8-sig")及通用换行转换。
        text = raw.decode("utf-8-sig").replace("\r\n", "\n").replace("\r", "\n")
    except UnicodeError:
        return raw_digest, None
    return raw_digest, hashlib.sha256(text.encode("utf-8")).hexdigest()


## Return the digest under PCResolve flow decoding and newline rules
## 按PCResolve的flow解码及换行规则返回源码摘要
#
#  @param path Filesystem path of the source being read or checked.
#  @return Result of the `_flow_digest` operation.
def _flow_digest(path):
    try:
        with open(path, encoding='utf-8-sig') as stream:
            return hashlib.sha256(stream.read().encode('utf-8')).hexdigest()
    except (OSError, UnicodeError):
        return None


class PCResolveAdapter:
    """Keep source-only immutable facts; all domain query state stays outside."""

    ## Initialize the object state required by the enclosing class
    ## 初始化所属类所需的对象状态
    #
    #  @param index Source index used for definitions and imports.
    #  @return None.
    def __init__(self, index):
        try:
            from pcresolve import FlowAnalyzer, FlowCall
        except ImportError as exc:
            raise ResolutionError("PCResolve value-flow analysis is required") from exc
        options = {}
        if 'support_source_protocols' in inspect.signature(FlowAnalyzer).parameters:
            options['support_source_protocols'] = True

        # Older PCResolve releases do not expose SourceStore; keep their existing path.
        # 旧版PCResolve没有SourceStore接口时，继续使用原有分析路径。
        if (index.source_store is not None
                and 'source_store' in inspect.signature(FlowAnalyzer).parameters):
            options['source_store'] = index.source_store
        self._analyzer = FlowAnalyzer(source_files=index.files,
                                      import_roots=index.source.import_roots, **options)
        self._import_roots = tuple(_path(path) for path in self._analyzer.roots)
        self.capabilities = FactCapabilities("flow-0.2", tuple(
            item.name for item in fields(FlowCall)) if is_dataclass(FlowCall) else ())
        self._index = index

        # A caller-built index may deliberately contain only selected files.
        # Only a full package snapshot can promise detection of added files.
        # 调用方构建的索引可能只包含指定文件；只有完整包快照才能检测新增文件。
        self._full_package = (not index.is_api_scope and
                              tuple(_python_files(index.source.package_root)) == index.files)
        self._source_hashes = {}
        self._flow_hashes = {}
        for path in index.files:
            raw_digest, flow_digest = _source_digests(path)
            self._source_hashes[path] = raw_digest
            if flow_digest is not None:
                self._flow_hashes[_path(path)] = flow_digest
        self._analysis_cache = {}
        self._expansion_cache = {}
        self._caller_store = None
        self._supporting_hashes = {}

    ## Reject supporting-source changes after a fact snapshot is registered
    ## 在登记事实快照后拒绝支持源码发生变化
    #
    #  @return Result of the `_validate_supporting_sources` operation.
    def _validate_supporting_sources(self):
        if any(_flow_digest(path) != digest for path, digest in self._supporting_hashes.items()):
            raise ValueError('Source protocol content changed; create a new analysis context')

    ## Validate and record source hashes referenced by supporting facts
    ## 校验并登记支持事实引用的源码哈希
    #
    #  @param hashes Source-content hashes supplied by the producer.
    #  @return Result of the `_register_supporting_sources` operation.
    def _register_supporting_sources(self, hashes):
        if (not isinstance(hashes, dict)
                or any(not isinstance(path, str) or not os.path.isabs(path)
                       or not isinstance(digest, str) or len(digest) != 64
                       or any(char not in '0123456789abcdef' for char in digest)
                       or _path(path) in self._flow_hashes
                       for path, digest in hashes.items())):
            raise ResolutionError('PCResolve supporting source snapshot is malformed',
                                  'pcresolve_fact_contract_unavailable')
        for path, digest in hashes.items():
            normalized = _path(path)
            if not any(os.path.commonpath([normalized, root]) == root
                       for root in self._import_roots
                       if os.path.splitdrive(normalized)[0] == os.path.splitdrive(root)[0]):
                raise ResolutionError(
                    'PCResolve supporting source is outside supplied import roots',
                    'pcresolve_fact_contract_unavailable')
            if (_flow_digest(path) != digest
                    or normalized in self._supporting_hashes
                    and self._supporting_hashes[normalized] != digest):
                raise ValueError('Source protocol content changed; create a new analysis context')
        self._supporting_hashes.update({_path(path): digest for path, digest in hashes.items()})

    ## Read optional caller facts independently of cached library flow/scan
    ## 读取可选调用方事实，不依赖已缓存的库flow或scan结果
    #
    #  @param callsite Source location and facts for the original call.
    #  @return Result of the `caller_inputs` operation.
    def caller_inputs(self, callsite):
        try:
            from pcresolve._caller_inputs import literal_inputs
            from pcresolve.program_facts import SourceSpan
            from pcresolve.source_snapshot import SourceStore
        except ImportError:
            return None
        if self._caller_store is None:
            self._caller_store = SourceStore()
        span = SourceSpan(str(callsite.file_path), callsite.lineno, callsite.col_offset,
                          callsite.end_lineno, callsite.end_col_offset)
        fact = literal_inputs(span, store=self._caller_store, import_roots=self._import_roots)
        supporting = fact.get('supporting_source_sha256', {}) if isinstance(fact, dict) else {}
        if supporting:
            self._register_supporting_sources(supporting)
        return readonly(fact)

    ## Validate once per public query, including before a domain cache hit
    ## 每次公开查询都校验源码，包括命中领域缓存前
    #
    #  @return Result of the `validate_source` operation.
    def validate_source(self):

        # 复用分析事实前同时检查源码集合、文件内容和额外支持源码
        if (self._full_package
                and tuple(_python_files(self._index.source.package_root)) != self._index.files):
            raise ValueError("Source files changed; create a new analysis context")
        if any(_digest(path) != digest for path, digest in self._source_hashes.items()):
            raise ValueError("Source content changed; create a new analysis context")
        self._validate_supporting_sources()

    ## Check PCResolve result fields, schema, scope and source hashes
    ## 校验PCResolve结果字段、模式、作用域及源码哈希
    #
    #  @param analysis PCResolve analysis result being validated or consumed.
    #  @return Result of the `_validate` operation.
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
        self._register_supporting_sources(inputs.get('supporting_source_sha256', {}))

    ## Analyze one function and validate the returned PCResolve facts
    ## 分析指定函数并校验返回的PCResolve事实
    #
    #  @param function Indexed source function under analysis.
    #  @param max_depth Maximum number of forwarding steps to analyze.
    #  @param conditional_source_state Whether to request conditional source-state facts.
    #  @return Result of the `analyze` operation.
    def analyze(self, function, max_depth=1, *, conditional_source_state=False):
        from pcresolve import FunctionRef

        self._validate_supporting_sources()
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

    ## Expand one call edge and validate its isolated context when requested
    ## 扩展指定调用边，并在需要时校验隔离上下文
    #
    #  @param analysis PCResolve analysis result being validated or consumed.
    #  @param call_id Identifier of the producer call edge.
    #  @param isolate Value named `isolate` supplied by the enclosing analysis.
    #  @param preserve_lineage Value named `preserve_lineage` supplied by the enclosing analysis.
    #  @return Result of the `expand` operation.
    def expand(self, analysis, call_id, *, isolate=False, preserve_lineage=False):
        if type(isolate) is not bool or type(preserve_lineage) is not bool:
            raise ValueError('Expansion isolation options must be bool')
        if preserve_lineage and not isolate:
            raise ValueError('preserve_lineage requires isolate=True')
        self._validate_supporting_sources()
        key = ((id(analysis), call_id, 'isolated', 'lineage') if preserve_lineage else
               (id(analysis), call_id, 'isolated') if isolate else (id(analysis), call_id))
        if key not in self._expansion_cache:
            self._validate(analysis)
            try:
                if isolate:
                    result = self._analyzer.expand(
                        analysis, call_id, additional_depth=1, isolate=True,
                        preserve_lineage=preserve_lineage)
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
