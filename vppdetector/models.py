## @package vppdetector.models
#  Source identities, findings and parameter-level evidence models.
#  定义源码身份、检测结果及参数级证据模型。

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Optional, Tuple, Union


## Enum whose values remain convenient at CLI and report boundaries.
#
#  在命令行和报告边界便于使用其值的枚举。
class StringEnum(str, Enum):
    ## Return the enum value used at report and CLI boundaries
    ## 返回报告和命令行边界使用的枚举值
    #
    #  @return Enum value as a string
    def __str__(self):
        return self.value


## Identify whether a variadic parameter captures positional or keyword arguments.
## 标识可变参数捕获的是位置实参还是关键字实参。
class VariadicKind(StringEnum):
    POSITIONAL = "var_positional"
    KEYWORD = "var_keyword"


## Identify the supported parameter change operation.
## 标识受支持的参数变更操作。
class ChangeKind(StringEnum):
    DELETE = "delete"
    RENAME = "rename"


## Disposition of one changed argument, not a repair or compatibility verdict.
#
#  单个变更实参的处置状态，不代表修复或兼容性结论。
class ParameterState(StringEnum):
    HANDLED = "handled"
    REJECTED = "rejected"
    IGNORED = "ignored"
    UNKNOWN = "unknown"
    NOT_ENTERED = "not_entered"


## Observed analysis limits, never a proof of complete coverage.
#
#  记录观察到的分析限制，不证明覆盖完整。
class ScanCoverageStatus(StringEnum):
    NO_KNOWN_BOUNDARY = "no_known_boundary"
    LIMITED = "limited"
    UNAVAILABLE = "unavailable"


## One parameter deletion or rename supplied by the caller.
#
#  调用方提供的单项参数删除或重命名。
@dataclass(frozen=True)
class ParameterChange:
    kind: ChangeKind
    old_name: str
    new_name: Optional[str] = None
    old_position: Optional[int] = None

    ## Validate and normalize the parameter-change fields
    ## 校验并规范化参数变更字段
    #
    #  @exception ValueError If a parameter name or old position is invalid
    def __post_init__(self):
        object.__setattr__(self, "kind", ChangeKind(self.kind))
        if not self.old_name.isidentifier():
            raise ValueError("old_name must be a parameter name")
        if self.kind is ChangeKind.RENAME and (
            not self.new_name or not self.new_name.isidentifier()
        ):
            raise ValueError("A rename requires new_name")
        if self.old_position is not None and (
            type(self.old_position) is not int or self.old_position < 0
        ):
            raise ValueError("old_position must be a nonnegative integer")


## Source files and module roots available to the analysis.
#
#  分析可使用的源文件和模块根目录。
@dataclass(frozen=True)
class SourceContext:
    package_root: Path
    import_roots: Tuple[Path, ...] = field(default_factory=tuple)
    dependency_modules: Tuple[str, ...] = field(default_factory=tuple)


## Source-level identity of one function or method.
#
#  函数或方法的源码级身份。
@dataclass(frozen=True)
class FunctionIdentity:
    module: str
    qualname: str
    file_path: Optional[Path] = None
    lineno: Optional[int] = None


## Represent a complete source range with start and end coordinates.
## 表示带有起止坐标的完整源码范围。
@dataclass(frozen=True)
class SourceSpan:
    file_path: Path
    lineno: int
    col_offset: int
    end_lineno: int
    end_col_offset: int


## Trusted, call-specific runtime checkpoint; never a static lookup proof.
#
#  The observation must come from an uncaught exception trace of the original
#  call. The entry and checker mappings contained this same primitive value,
#  and the checker lookup produced lookup_value at raise_span.
#
#  可信的特定调用运行时检查点，不构成静态查找证明。观察须来自原调用的未捕获异常轨迹
#  ；入口和检查器映射包含同一原始值，且检查器在 raise_span 处查找得到
#  lookup_value。
@dataclass(frozen=True)
class ObservedKeywordCheck:
    entry: FunctionIdentity
    call_text: str
    keyword: str
    value: object
    checker: FunctionIdentity
    raise_span: SourceSpan
    mapping_parameter: str
    key_variable: str
    lookup_variable: str
    attribute_name: str
    lookup_value: object
    exception: str
    uncaught: bool
    source_hashes: Tuple[Tuple[Path, str], ...]


## Trusted original-call element provenance into an actual fixed method formal.
#
#  A traced source call expanded this exact builtin mapping into the identified
#  bound method, which actually entered with the same original primitive in the
#  fixed parameter. The original invocation completed normally. This records
#  binding consumption, not a general dispatch or compatibility proof.
#
#  原调用元素进入实际方法固定形参的可信来源。轨迹中的源码调用将该精确内置映射展开到
#  指定绑定方法，并以相同原始值进入固定参数；原调用正常完成。这只记录绑定消耗，不证
#  明一般分派或兼容性。
@dataclass(frozen=True)
class ObservedFixedBinding:
    entry: FunctionIdentity
    call_text: str
    keyword: str
    value: object
    caller: FunctionIdentity
    call_span: SourceSpan
    target: FunctionIdentity
    parameter: str
    mapping_variable: str
    target_bound_receiver: bool
    received_builtin_dict: bool
    origin_confirmed: bool
    target_entered: bool
    completed_normally: bool
    source_hashes: Tuple[Tuple[Path, str], ...]


## Trusted original-call rejection by a source nonempty-dictionary guard.
#
#  The checker received the selected original primitive in an exact builtin
#  dictionary, completed the whole guard with a true outcome and raised the
#  uncaught exception at the recorded source statement.
#
#  原调用被源码中的非空字典守卫拒绝的可信记录。检查器在精确内置字典中接收所选原始值
#  ，完整守卫结果为真，并在记录的源码语句处抛出未捕获异常。
@dataclass(frozen=True)
class ObservedCaptureRejection:
    entry: FunctionIdentity
    call_text: str
    keyword: str
    value: object
    checker: FunctionIdentity
    guard_span: SourceSpan
    raise_span: SourceSpan
    mapping_parameter: str
    exception: str
    received_builtin_dict: bool
    origin_confirmed: bool
    guard_value: bool
    guard_completed: bool
    uncaught: bool
    source_hashes: Tuple[Tuple[Path, str], ...]


## Trusted completed class construction retaining the original keyword capture.
#
#  The original invocation used type.__call__, object.__new__ and ordinary
#  object attribute access/store. Its original constructor receiver is the
#  returned instance, whose plain state retains the same builtin capture dict
#  and selected primitive after this source assignment and normal completion.
#
#  类构造正常完成后保留原始关键字捕获的可信记录。原调用使用
#  type.__call__、object.__new__ 和普通对象属性读写；原构造器接收
#  者是返回实例，其普通状态在源码赋值及正常完成后仍保留同一内置捕获字典和所选原始值。
@dataclass(frozen=True)
class ObservedAttributeRetention:
    entry: FunctionIdentity
    call_text: str
    keyword: str
    value: object
    attribute: str
    store_span: SourceSpan
    retained_builtin_dict: bool
    construction_confirmed: bool
    store_completed: bool
    completed_normally: bool
    source_hashes: Tuple[Tuple[Path, str], ...]


## Trusted execution of a source predicate on the selected argument's carrier.
#
#  The caller independently establishes that this original call entered entry,
#  the original element/presence reached selection in the checker's exact builtin
#  container, this predicate completed, and the entry body completed normally.
#  No runtime object graphs or argument values are accepted in this record.
#
#  对所选实参的承载容器执行源码谓词的可信记录。调用方独立确认原调用进入 entry、原始元素
#  或存在性到达检查器精确内置容器中的选择位置、谓词执行完成且入口函数体正常完成。此记录不接受
#  运行时对象图或实参值。
@dataclass(frozen=True)
class ObservedContainerPredicate:
    entry: FunctionIdentity
    call_text: str
    parameter_name: str
    old_position: Optional[int]
    checker: FunctionIdentity
    predicate_span: SourceSpan
    container_parameter: str
    container_kind: str
    selection: Union[str, int]
    container_size: int
    key_variable: Optional[str]
    predicate_value: bool
    origin_confirmed: bool
    predicate_completed: bool
    completed_normally: bool
    source_hashes: Tuple[Tuple[Path, str], ...]


## Trusted original-call completion with the same captured primitive value.
#
#  The actual source frame received keyword/value and returned an exact builtin
#  dict normally at return_span. This attestation alone proves no consumption;
#  a matching PCResolve retention fact is additionally required.
#
#  原调用以相同捕获原始值完成的可信记录。实际源码帧接收关键字和值，并在
#  return_span 正常返回精确内置字典；该证明本身不证明消耗，还需要匹配的
#  PCResolve 保留事实。
@dataclass(frozen=True)
class ObservedNormalReturn:
    entry: FunctionIdentity
    call_text: str
    keyword: str
    value: object
    return_span: SourceSpan
    returned_builtin_dict: bool
    source_hashes: Tuple[Tuple[Path, str], ...]


## Original call and optional trusted, finite facts for that call only.
#
#  known_values supplies primitive constants under source parameter names or
#  receiver attribute paths, e.g. (("self.closed", False),). These are caller
#  evidence, not expressions to execute. None is distinct from an unknown value.
#  bound_receiver overrides the indexed method convention for unbound calls.
#  known_targets confirms implementations at exact library call locations;
#  copying a nominal PCResolve candidate is not an independent confirmation.
#  known_conditions supplies independently established predicate outcomes at
#  exact source spans. observed_keyword_checks supplies an explicit original
#  call trace checkpoint; these runtime facts never enter scan/producer caches.
#  observed_normal_returns confirms original-call completion for a matching
#  conditional source retention proof; completion alone never implies handling.
#  callsite optionally identifies the exact original source call. Matching
#  PCResolve caller facts may recover bounded literals under explicit source
#  assumptions; missing/mismatched source keeps syntax-only assessment.
#  execution_directory supplies the process working directory for relative
#  caller-side file paths
#
#  原调用及仅适用于该调用的可选可信有限事实。known_values
#  按源码参数名或接收者属性路径提供原始常量，作为调用方证据而不执行；None
#  不同于未知值。bound_receiver
#  为非绑定调用覆盖索引方法约定。known_targets
#  在精确调用位置确认实现，复制名义候选不构成独立确认。known_conditions
#  提供精确源码范围内独立确定的谓词结果。observed_keyword_checks 提供
#  原调用轨迹检查点，这些运行时事实不进入扫描或生产者缓存。observed_normal_r
#  eturns 确认匹配条件式源码保留证明的原调用完成，本身不意味着已处理。callsite
#  可标识精确原始调用；在明确源码假设下可从匹配的 PCResolve 调用方事实恢复有限字面
#  量，源码缺失或不匹配时保持仅基于语法的评估。execution_directory
#  指定调用方相对文件路径使用的进程工作目录。
@dataclass(frozen=True)
class CallContext:
    expression: Union[str, ast.Call]
    bound_receiver: Optional[bool] = None
    known_values: Tuple[Tuple[str, object], ...] = ()
    callsite: Optional[SourceSpan] = None
    known_targets: Tuple[Tuple[SourceSpan, FunctionIdentity], ...] = ()
    known_conditions: Tuple[Tuple[SourceSpan, bool], ...] = ()
    observed_keyword_checks: Tuple[ObservedKeywordCheck, ...] = ()
    observed_normal_returns: Tuple[ObservedNormalReturn, ...] = ()
    observed_container_predicates: Tuple[ObservedContainerPredicate, ...] = ()
    observed_attribute_retentions: Tuple[ObservedAttributeRetention, ...] = ()
    observed_capture_rejections: Tuple[ObservedCaptureRejection, ...] = ()
    observed_fixed_bindings: Tuple[ObservedFixedBinding, ...] = ()
    execution_directory: Optional[Path] = None

    ## Validate and normalize the immutable call-context fields
    ## 校验并规范化不可变调用上下文字段
    #
    #  @exception ValueError If supplied facts, observations or execution directory are invalid
    def __post_init__(self):
        if self.execution_directory is not None:
            try:
                directory = Path(self.execution_directory)
            except (TypeError, ValueError):
                raise ValueError('execution_directory must be an absolute path or None')
            if not directory.is_absolute():
                raise ValueError('execution_directory must be an absolute path or None')
            object.__setattr__(self, 'execution_directory', directory)
        if self.bound_receiver is not None and type(self.bound_receiver) is not bool:
            raise ValueError("bound_receiver must be bool or None")
        names = [name for name, _ in self.known_values]
        if len(set(names)) != len(names) or any(
            not all(part.isidentifier() for part in name.split(".")) for name in names
        ):
            raise ValueError("known_values requires unique parameter or attribute paths")
        if any(
            type(value) not in (str, bytes, int, float, bool, type(None))
            for _, value in self.known_values
        ):
            raise ValueError("known_values accepts only primitive constants")
        spans = [span for span, _ in self.known_targets]
        if len(set(spans)) != len(spans):
            raise ValueError("known_targets requires unique library call locations")
        conditions = [span for span, _ in self.known_conditions]
        if (any(not isinstance(span, SourceSpan) or type(value) is not bool
                for span, value in self.known_conditions)
                or len(set(conditions)) != len(conditions)):
            raise ValueError('known_conditions requires unique source spans and bool outcomes')
        observation_types = (
            ('observed_keyword_checks', ObservedKeywordCheck),
            ('observed_normal_returns', ObservedNormalReturn),
            ('observed_container_predicates', ObservedContainerPredicate),
            ('observed_attribute_retentions', ObservedAttributeRetention),
            ('observed_capture_rejections', ObservedCaptureRejection),
            ('observed_fixed_bindings', ObservedFixedBinding),
        )
        present = 0
        for name, record_type in observation_types:
            records = getattr(self, name)
            if len(records) > 8 or any(not isinstance(value, record_type) for value in records):
                raise ValueError(name + ' requires bounded observation records')
            present += bool(records)
        if present > 1:
            raise ValueError('Supply one observation family for an assessment')


## A diagnostic explaining an analysis limit, rather than a VPP finding.
#
#  解释分析限制的诊断，不属于 VPP 发现。
@dataclass(frozen=True)
class AnalysisBoundary:
    code: str
    message: str
    function: Optional[FunctionIdentity] = None
    callsite: Optional[SourceSpan] = None
    root_function: Optional[FunctionIdentity] = None
    parameter_name: Optional[str] = None
    parameter_kind: Optional[VariadicKind] = None


## A binding, use, drop or selected condition supporting an assessment.
#
#  支持评估的绑定、使用、丢弃或选定条件。
@dataclass(frozen=True)
class ParameterEvidence:
    function: FunctionIdentity
    reason: str
    detail: str
    callsite: Optional[SourceSpan] = None
    target: Optional[FunctionIdentity] = None


## Handling state and supporting evidence for one changed argument in a call.
#
#  调用中一个变更实参的处理状态及其证据。
@dataclass(frozen=True)
class ParameterAssessment:
    target_api: FunctionIdentity
    change: ParameterChange
    call_text: str
    state: ParameterState
    reason: str
    evidence: Tuple[ParameterEvidence, ...] = ()
    boundaries: Tuple[AnalysisBoundary, ...] = ()
    resolved_api: Optional[FunctionIdentity] = None
    callsite: Optional[SourceSpan] = None


## Report one indexed source function and its variadic channels.
## 报告一个已索引源码函数及其可变参数通道。
@dataclass(frozen=True)
class VariadicFunction:
    function: FunctionIdentity
    parameters: Tuple[Tuple[str, VariadicKind], ...]
    implementation: Optional[FunctionIdentity] = None


## One source or proven builtin-protocol hop in an API's forwarding path.
#
#  API 转发路径中的一个源码或已证明的内置协议步骤。
@dataclass(frozen=True)
class ForwardingStep:
    function: FunctionIdentity
    parameter_name: str
    callee_expression: str
    callsite: SourceSpan
    target: FunctionIdentity
    target_status: str = "resolved"
    conditions: Tuple[dict, ...] = field(default_factory=tuple)


## A root variadic parameter reaches an incompatible expansion signature.
#
#  根可变参数到达不兼容的展开签名。
@dataclass(frozen=True)
class ForwardingFinding:
    function: FunctionIdentity
    parameter_name: str
    parameter_kind: VariadicKind
    callee_expression: str
    callsite: SourceSpan
    target: FunctionIdentity
    reason_code: str
    path: Tuple[ForwardingStep, ...] = field(default_factory=tuple)
    target_status: str = "resolved"
    target_candidates: Tuple[FunctionIdentity, ...] = field(default_factory=tuple)
    receiver_type_evidence: Tuple[dict, ...] = field(default_factory=tuple)
    conditions: Tuple[dict, ...] = field(default_factory=tuple)


## One root channel's findings and recorded limits in a scan snapshot.
#
#  扫描快照中一个根通道的发现和记录的限制。
@dataclass(frozen=True)
class VariadicCoverage:
    function: FunctionIdentity
    parameter_name: str
    parameter_kind: VariadicKind
    status: ScanCoverageStatus
    finding_count: int = 0
    boundary_codes: Tuple[str, ...] = ()
    implementation: Optional[FunctionIdentity] = None


## Positive VPP findings and diagnostics for one scan scope.
#
#  一个扫描范围内的正向 VPP 发现和诊断。
@dataclass(frozen=True)
class ScanReport:
    source: SourceContext
    functions_scanned: int
    variadic_functions: Tuple[VariadicFunction, ...]
    findings: Tuple[ForwardingFinding, ...]
    boundaries: Tuple[AnalysisBoundary, ...] = field(default_factory=tuple)
    analyzer_schema_version: Optional[str] = None
    target_api: Optional[FunctionIdentity] = None
    resolved_api: Optional[FunctionIdentity] = None
    coverage: Tuple[VariadicCoverage, ...] = ()

    ## Whether this scan found a VPP; false does not prove full coverage
    ## 判断扫描是否发现VPP；False不代表分析覆盖完整
    #
    #  @return Whether at least one finding was recorded
    @property
    def has_vpp(self):
        return bool(self.findings)

    ## Compatibility alias for the positive findings collection
    ## 提供兼容旧调用方的潜在问题只读别名
    #
    #  @return The report's tuple of positive findings
    @property
    def potential_pitfalls(self):
        return self.findings
