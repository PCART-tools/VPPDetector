## @package vppdetector.scan.captures
#  Record conservative capture boundaries for variadic forwarding scans.
#
#
#  Identify relevant calls and variadic captures, and record boundaries when capture execution
#  cannot be established.
#  识别相关调用及可变参数捕获，在无法证明捕获执行时记录边界。



from pathlib import Path

from ..facts.calls import candidate_identities, identity_from_target
from ..facts.scope import capture_names
from ..models import AnalysisBoundary, FunctionIdentity, SourceSpan
from .flow import _parameter_dependency


## Check whether a call uses the selected parameter
## 检查调用是否使用选定参数
#
#  @param call Producer call record being analyzed
#  @param parameter Parameter name being checked
#  @return Whether a receiver, argument or capture source depends on the parameter
def call_depends_on_parameter(call, parameter):
    values = [*call.receiver_sources, *call.argument_flows]
    values.extend(value for item in call.argument_sources for value in item.get("sources", ()))
    values.extend(
        value for item in getattr(call, "capture_bindings", ()) for value in item.get("sources", ())
    )
    return any(_parameter_dependency(value, parameter) for value in values)


## Check whether a local callable captures the selected parameter
## 检查局部可调用对象是否捕获选定参数
#
#  @param index Source index containing local callable definitions
#  @param state Current carrier state
#  @param target Source identity of the local target function
#  @return Whether the indexed local target captures the selected parameter
def _lexical_capture(
    index,
    state,
    target,
):
    identity = state.function.identity
    if target.module != identity.module or not target.qualname.startswith(identity.qualname + "."):
        return False
    definition = index.find(target)
    if definition is None:
        return False
    return state.parameter in capture_names(definition.node, (state.parameter,))


## Check producer capture evidence and the bounded lexical fallback
## 检查生产者捕获证据和受限的词法回退
#
#  @param index Source index containing local callable definitions
#  @param state Current carrier state
#  @param call Producer call record being analyzed
#  @return Whether the call captures the selected parameter
def call_captures_parameter(
    index,
    state,
    call,
):
    if any(
        _parameter_dependency(value, state.parameter)
        for capture in getattr(call, "capture_bindings", ())
        for value in capture.get("sources", ())
    ):
        return True

    # Older flow-0.2 snapshots can identify a lexical callee but omit captures.
    # This fallback records a limit, never supplies a missing propagation edge.
    # 旧版 flow-0.2 可识别词法调用目标但可能缺失捕获；回退仅记录边界。
    return any(
        _lexical_capture(index, state, target)
        for target in (
            *((identity_from_target(call.target),) if call.target else ()),
            *candidate_identities(call),
        )
    )


## Find returned local callables that capture the selected parameter
## 查找捕获选定参数并作为返回值的局部可调用对象
#
#  @param index Source index containing local callable definitions
#  @param analysis PCResolve analysis result being checked
#  @param state Current carrier state
#  @return Boundaries for returned local callables whose execution is deferred
def deferred_capture_boundaries(
    index,
    analysis,
    state,
):
    identity = state.function.identity

    # Inspect nested summaries for captured values whose use never becomes a direct tracked call.
    # 检查嵌套摘要，找出未形成直接跟踪调用的捕获值使用。
    for summary in analysis.functions:
        if identity_from_target(summary["function"]) != identity:
            continue
        for value in summary.get("returns", ()):
            if value.get("kind") not in {"callable", "function"}:
                continue
            target = FunctionIdentity(value.get("module", identity.module), value.get("source", ""))
            if not _lexical_capture(index, state, target):
                continue
            span = None
            for evidence in reversed(value.get("evidence", ())):
                if evidence.get("file_path") and evidence.get("lineno"):
                    span = SourceSpan(
                        Path(evidence["file_path"]),
                        evidence["lineno"],
                        evidence.get("col_offset", 0),
                        evidence.get("end_lineno", evidence["lineno"]),
                        evidence.get("end_col_offset", 0),
                    )
                    break
            yield AnalysisBoundary(
                "deferred_callable_not_followed",
                "A returned local callable lexically captures this carrier; "
                "deferred execution is not followed.",
                identity,
                span,
            )


## Return all declared parameter names in source signature order
## 按源码签名顺序返回全部已声明参数名称
#
#  @param function Indexed source function under analysis
#  @return Positional, keyword-only and variadic parameter names
def parameter_names(function):
    signature = function.signature
    return tuple(
        name
        for name in (
            *signature.positional_only,
            *signature.positional_or_keyword,
            *signature.keyword_only,
            signature.vararg,
            signature.kwarg,
        )
        if name is not None
    )
