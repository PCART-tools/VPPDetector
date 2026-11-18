## @package vppdetector.scan.boundaries
#  Translate PCResolve flow limits into scan-level analysis boundaries.
#
#
#  Translate producer limits and unsupported carrier operations into diagnostics scoped to the
#  current forwarding path.
#  将生产者限制和不支持的载体操作转换为当前转发路径的诊断。



from ..facts.calls import call_span, direct_calls, identity_from_target
from ..models import AnalysisBoundary
from .flow import _parameter_dependency, _whole_container


## Locate an earlier unresolved receiver operation consuming the carrier
## 定位较早的、消费载体的未解析接收者操作
#
#  @param analysis PCResolve analysis result being checked
#  @param identity Source identity used for lookup
#  @param parameter Parameter name being checked
#  @param destination Producer call where the carrier is consumed
#  @return Span of an unresolved receiver operation, or None if none was found
def carrier_operation_boundary(
    analysis,
    identity,
    parameter,
    destination,
):
    destination_end = (
        destination.end_lineno or destination.lineno,
        destination.end_col_offset or destination.col_offset,
    )

    # Skip unresolved receiver calls whose source starts after the destination call's end.
    # 跳过源码起始位置位于目标调用结束位置之后的未解析接收者调用。
    for call in direct_calls(analysis, identity):
        if call.target_status != "receiver_unresolved":
            continue
        if (call.lineno, call.col_offset) > destination_end:
            continue
        if any(
            value.get("kind") == "parameter"
            and value.get("source") == parameter
            and _whole_container(value)
            for value in call.receiver_sources
        ):
            return call_span(call)
    return None


## Keep producer boundaries that can affect the selected scan channel
## 保留可能影响所选扫描通道的生产者边界
#
#  @param analysis PCResolve analysis result being checked
#  @param identity Source identity used for lookup
#  @param relevant_calls Producer call identifiers relevant to this channel
#  @param parameter Parameter name being checked
#  @return Iterator of translated boundaries relevant to the selected channel
def analysis_boundaries(
    analysis,
    identity,
    relevant_calls,
    parameter,
):
    calls = {call.id: call for call in direct_calls(analysis, identity)}
    for boundary in analysis.boundaries:
        reason = boundary.get("reason", "unspecified")

        # The scanner composes its own depth-limited container paths. Unknown
        # expansion elements are its input, not concrete client-binding errors.
        # 扫描器自行组合有深度限制的容器路径，未知展开元素是分析输入。
        if reason in {"depth_limit", "dynamic_argument_expansion"}:
            continue
        owner = boundary.get("function")
        if owner and identity_from_target(owner) != identity:
            continue
        if not owner and not boundary.get("call_id"):
            if identity_from_target(analysis.entry) != identity:
                continue
        call_id = boundary.get("call_id")
        affected = boundary.get("affected_values", ())
        if boundary.get("affected_scope") == "none":
            continue
        if (
            boundary.get("affected_scope") == "known"
            and affected
            and not any(_parameter_dependency(value, parameter) for value in affected)
        ):
            continue
        if call_id and call_id not in relevant_calls:
            call = calls.get(call_id)
            if call is None:
                continue
            protocol = getattr(call, "implicit_protocol", {})
            implicit_exit = (
                protocol.get("kind") == "context_manager_exit"
                and protocol.get("method") == "__exit__"
                and reason.startswith("context_exit_")
            )

            # Exit effects can affect the pending frame without receiving its
            # carrier as an argument. Their affected roots determine coverage.
            # 退出时的效果即使不接收容器，也可能影响当前帧；受影响的根决定覆盖范围。
            if not implicit_exit:
                if reason not in {
                    "unsupported_expression",
                    "receiver_unresolved",
                    "definition_unavailable",
                } or not _call_depends_on_parameter(call, parameter):
                    continue
        yield AnalysisBoundary(
            "pcresolve_" + reason,
            "PCResolve boundary: {}.".format(reason),
            identity,
            call_span(calls[call_id]) if call_id in calls else None,
        )


## Check whether a call uses the selected parameter
## 检查调用是否使用选定参数
#
#  @param call Producer call record being analyzed
#  @param parameter Parameter name being checked
#  @return Whether a receiver, argument or capture source depends on the parameter
def _call_depends_on_parameter(call, parameter):
    values = [*call.receiver_sources, *call.argument_flows]
    values.extend(value for item in call.argument_sources for value in item.get("sources", ()))
    values.extend(
        value for item in getattr(call, "capture_bindings", ()) for value in item.get("sources", ())
    )
    return any(_parameter_dependency(value, parameter) for value in values)
