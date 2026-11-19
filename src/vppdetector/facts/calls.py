## @package vppdetector.facts.calls
#  Translate producer call identities, spans and resolution status.
#
#
#  Normalize producer call identities and candidate statuses, and expose binding and boundary
#  facts to both consumers.
#  统一生产者调用身份和候选状态，向两类分析提供绑定和边界事实。



from pathlib import Path

from .._records import MutableRecord
from ..models import FunctionIdentity, SourceSpan


## Convert a producer target record into a function identity.
## 将生产者目标记录转换为函数身份。
#
#  @param target Producer target record or selected source target
#  @return FunctionIdentity assembled from the target fields
def identity_from_target(target):
    ## Read one identity field from a producer record.
    ## 从生产者记录读取一个身份字段。
    #
    #  @param name Name to match or validate in the current scope
    #  @param default Fallback when the record or object lacks the requested field
    #  @return The field value or its fallback
    def value(name, default):
        if isinstance(target, dict):
            return target.get(name, default)
        return getattr(target, name, default)

    # Producer references can omit source coordinates. A missing path stays unset.
    # 生产者的引用可以省略源码坐标；缺少路径时保持未设置。
    path = value("file_path", "")
    return FunctionIdentity(
        module=value("module", ""),
        qualname=value("qualname", ""),
        file_path=Path(path) if path else None,
        lineno=value("lineno", 0) or None,
    )


## Convert and deduplicate function identities from call candidate records
## 转换并去重调用候选记录中的函数身份
#
#  @param call PCResolve producer call record being analyzed
#  @return Tuple of distinct converted candidate identities
def candidate_identities(call):
    result = []
    for candidate in getattr(call, "target_candidates", ()):
        identity = identity_from_target(candidate)
        if identity not in result:
            result.append(identity)
    return tuple(result)


## Return direct calls made by the selected source function
## 返回指定源码函数发出的直接调用
#
#  @param analysis PCResolve analysis result being validated or consumed
#  @param caller Source identity of the calling function
#  @return Iterator over producer call records owned by the selected function
def direct_calls(analysis, caller):
    for call in analysis.calls:
        owner = identity_from_target(call.caller)
        if (
            owner.module == caller.module
            and owner.qualname == caller.qualname
            and (not caller.lineno or owner.lineno == caller.lineno)
            and (not caller.file_path or owner.file_path == caller.file_path)
        ):
            yield call


## Build a source span from one PCResolve call fact
## 根据一条 PCResolve 调用事实构建源码范围
#
#  @param call PCResolve producer call record being analyzed
#  @return Source span using the call's recorded coordinates
def call_span(call):
    return SourceSpan(
        file_path=Path(call.caller.file_path or ""),
        lineno=call.lineno,
        col_offset=call.col_offset,
        end_lineno=call.end_lineno or call.lineno,
        end_col_offset=call.end_col_offset or call.col_offset,
    )


## Classify whether the producer resolved the call target
## 判定生产者对调用目标的解析状态
#
#  @param analysis PCResolve analysis result being validated or consumed
#  @param call PCResolve producer call record being analyzed
#  @return Producer target status, adjusted for conditional or dynamic boundaries
def target_status(analysis, call):
    if getattr(call, "conditional_source_bindings", ()):
        return "conditional_source_candidate"
    if call.target_status != "resolved":
        return call.target_status
    if any(
        boundary.get("call_id") == call.id
        and boundary.get("reason", "").startswith("dynamic_")
        and boundary.get("reason") != "dynamic_argument_expansion"
        for boundary in analysis.boundaries
    ):
        return "source_candidate"
    return "resolved"


## Provide access to producer facts for one call.
## 提供单个调用的生产者事实访问接口。
class CallFacts(MutableRecord):
    _record_fields = ("analysis", "call")
    __match_args__ = _record_fields

    ## Pair one call fact with the analysis that owns it.
    ## 将单条调用事实与其所属分析配对保存。
    #
    #  @param analysis Producer analysis containing the call
    #  @param call Producer call record
    def __init__(self, analysis, call):
        self.analysis = analysis
        self.call = call

    ## Report whether the call has a complete argument binding
    ## 报告调用是否具有完整实参绑定
    #
    #  @return Whether binding is complete and has no reported issues
    @property
    def complete_binding(self):
        return self.call.binding_status == "complete" and not self.call.binding_issues

    ## Return the call binding status
    ## 返回调用绑定状态
    #
    #  @return Target resolution status for the call
    @property
    def status(self):
        return target_status(self.analysis, self.call)

    ## Return analysis boundaries attached to the call
    ## 返回该调用关联的分析边界
    #
    #  @return Tuple of analysis boundaries associated with this call
    @property
    def boundaries(self):
        return tuple(b for b in self.analysis.boundaries if b.get("call_id") == self.call.id)
