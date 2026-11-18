## @package vppdetector.scan.engine
#  Run the shared structural forwarding scan.
#
#
#  Schedule source-resolved forwarding by entry and variadic channel, and collect findings and
#  conservative boundaries in path order.
#  按入口及可变参数通道调度可解析的源码转发，沿传播路径收集发现和保守边界。



from collections import deque

from .._records import FrozenRecord
from ..facts.adapter import ResolutionError
from ..facts.bindings import source_classmethod_binding
from ..facts.calls import call_span, candidate_identities, direct_calls, identity_from_target
from ..facts.calls import target_status as _target_status
from ..facts.conditional_bindings import (
    conditional_constructor_signature,
    conditional_source_binding,
)
from ..facts.conditions import (
    conditional_path_conditions,
    conditions_possible,
    consistent_conditions,
)
from ..facts.creation import source_constructor_binding
from ..models import (
    AnalysisBoundary,
    ForwardingFinding,
    ForwardingStep,
    VariadicKind,
)
from ..models import replace_record as replace
from .boundaries import analysis_boundaries, carrier_operation_boundary
from .captures import (
    call_captures_parameter,
    call_depends_on_parameter,
    deferred_capture_boundaries,
    parameter_names,
)
from .flow import (
    _callee_body_boundaries,
    _capture_flows,
    _expand_body,
    _expansion_kind,
    _open_container,
    _receiver_contexts,
    _return_operation_boundary,
    _target_definition,
)
from .returns import _returned_flows


## Hold scan state for one variadic forwarding channel.
## 保存单个可变参数转发通道的扫描状态。
class _State(FrozenRecord):
    _record_fields = (
        "function",
        "parameter",
        "origin_parameter",
        "kind",
        "path",
        "ancestry",
        "analysis",
        "capture",
        "conditional",
        "constructor_query",
    )
    _record_compare_fields = tuple(name for name in _record_fields if name != "analysis")
    _record_repr_fields = _record_compare_fields
    __match_args__ = _record_fields

    ## Store the active function and forwarding state for one scan path.
    ## 保存一条扫描路径中的当前函数和转发状态。
    #
    #  @param function Current indexed source function
    #  @param parameter Parameter currently tracked
    #  @param origin_parameter Original API parameter
    #  @param kind Positional or keyword variadic kind
    #  @param path Forwarding steps accumulated so far
    #  @param ancestry Function identities already traversed
    #  @param analysis Producer analysis for the current function
    #  @param capture Whether the path follows a deferred capture
    #  @param conditional Whether the path depends on a condition
    #  @param constructor_query Whether this path evaluates constructor bindings
    def __init__(
        self,
        function,
        parameter,
        origin_parameter,
        kind,
        path=(),
        ancestry=(),
        analysis=None,
        capture=False,
        conditional=False,
        constructor_query=False,
    ):
        object.__setattr__(self, "function", function)
        object.__setattr__(self, "parameter", parameter)
        object.__setattr__(self, "origin_parameter", origin_parameter)
        object.__setattr__(self, "kind", kind)
        object.__setattr__(self, "path", path)
        object.__setattr__(self, "ancestry", ancestry)
        object.__setattr__(self, "analysis", analysis)
        object.__setattr__(self, "capture", capture)
        object.__setattr__(self, "conditional", conditional)
        object.__setattr__(self, "constructor_query", constructor_query)


## Follow open variadic containers to fixed expansion signatures
## 沿开放可变参数容器追踪到固定参数展开签名
#
#  @param context Reusable analysis context for the selected source snapshot
#  @param entry Resolved source entry for the requested API
#  @param max_depth Maximum number of forwarding steps to analyze
#  @return Findings, analysis boundaries and the PCResolve schema version
def scan_function(
    context,
    entry,
    max_depth=5,
):
    return context.scan_results.scan(
        entry, max_depth, lambda: _scan_function_uncached(context, entry, max_depth)
    )


## Compute one scan without accessing the completed-result cache.
## 计算一次扫描，不访问已完成结果缓存。
#
#  @param context Reusable source and producer state
#  @param entry Resolved source entry for the requested API
#  @param max_depth Maximum number of forwarding steps
#  @return Findings, boundaries and producer schema version
def _scan_function_uncached(
    context,
    entry,
    max_depth,
):
    # Each state tracks an entry parameter and its current forwarding path.
    # 每个状态跟踪一个入口参数及其当前转发路径
    pending = deque(_State(entry, name, name, kind) for name, kind in entry.variadic_parameters)
    findings = []
    boundaries = []
    schema = None
    while pending:
        state = pending.popleft()
        boundary_start = len(boundaries)
        identity = state.function.identity
        try:
            analysis = state.analysis or context.adapter.analyze(
                state.function.query_class or state.function.query_alias or identity
            )
        except ResolutionError as exc:
            boundaries.append(
                _root_boundary(AnalysisBoundary(exc.code, str(exc), identity), entry, state)
            )
            continue

        # Keep conditional evidence in a separate scan state from ordinary producer facts.
        # 将条件证据保存在独立于普通生产者事实的扫描状态中。
        if state.analysis is None and (
            state.function.query_class is not None
            and any(b.get("reason") == "source_lookup_candidate" for b in analysis.boundaries)
            or any(
                b.get("reason") == "constructor_binding_unconfirmed" for b in analysis.boundaries
            )
        ):
            try:
                conditioned = context.adapter.analyze(
                    state.function.query_class or state.function.query_alias or identity,
                    conditional_source_state=True,
                )
            except ResolutionError as exc:
                boundaries.append(
                    _root_boundary(
                        AnalysisBoundary(
                            "conditional_source_query_unavailable",
                            "Conditional source query unavailable: " + str(exc),
                            identity,
                        ),
                        entry,
                        state,
                    )
                )
            else:
                conditional_state = replace(
                    state,
                    analysis=conditioned,
                    conditional=True,
                    constructor_query=state.function.query_class is None,
                )
                if conditional_state not in pending:
                    pending.append(conditional_state)

        # Detect recursion using the parameter, receiver and expansion context.
        # 用参数、接收者和展开上下文识别当前路径中的递归
        state_key = (
            identity,
            state.parameter,
            state.kind,
            state.capture,
            state.conditional,
            _receiver_contexts(analysis, identity),
            repr(analysis.inputs.get("expansion_context", {}).get("parameter_facts", {})),
        )
        if state_key in state.ancestry:
            boundaries.append(
                _root_boundary(
                    AnalysisBoundary(
                        "recursive_forwarding", "Recursive forwarding path.", identity
                    ),
                    entry,
                    state,
                )
            )
            continue

        schema = getattr(analysis, "schema_version", schema)
        relevant_calls = set()

        for call in direct_calls(analysis, identity):
            _scan_call(
                context,
                entry,
                max_depth,
                state,
                state_key,
                analysis,
                call,
                pending,
                findings,
                boundaries,
                relevant_calls,
            )

        boundaries.extend(deferred_capture_boundaries(context.index, analysis, state))
        boundaries.extend(analysis_boundaries(analysis, identity, relevant_calls, state.parameter))
        boundaries[boundary_start:] = [
            _root_boundary(boundary, entry, state) for boundary in boundaries[boundary_start:]
        ]

    # Deduplicate boundaries while preserving their first occurrence in scan order.
    # 为边界去重并保留它们在扫描中首次出现的顺序。
    result = (tuple(findings), tuple(dict.fromkeys(boundaries)), schema)
    return result


## Visit one call, adding its findings, boundaries and successor states in order.
## 访问一个调用并按顺序记录发现、边界和后继状态。
#
#  @param context Analysis context for source and producer facts.
#  @param entry Scanned entry function.
#  @param max_depth Maximum forwarding depth.
#  @param state Current scan path state.
#  @param state_key Deduplication key for the state.
#  @param analysis Producer flow analysis.
#  @param call Call fact being processed.
#  @param pending Work queue receiving successor scan states.
#  @param findings Findings collected for the current entry point.
#  @param boundaries Analysis limits collected during traversal.
#  @param relevant_calls Producer call identifiers affecting the tracked parameter.
#  @return None; updates the supplied queue, findings, boundaries and call set.
def _scan_call(
    context,
    entry,
    max_depth,
    state,
    state_key,
    analysis,
    call,
    pending,
    findings,
    boundaries,
    relevant_calls,
):
    identity = state.function.identity
    if state.constructor_query and conditional_constructor_signature(analysis, call) is None:
        return
    if call_depends_on_parameter(call, state.parameter):
        relevant_calls.add(call.id)
    capture_flows = _capture_flows(
        context.index,
        context.constant_tests,
        context.transform_locations,
        analysis,
        state,
        call,
    )
    if call_captures_parameter(context.index, state, call) and not capture_flows:
        relevant_calls.add(call.id)
        boundaries.append(
            AnalysisBoundary(
                "closure_capture_not_followed",
                "A local callable captures this carrier; closure propagation is not followed.",
                identity,
                call_span(call),
            )
        )
    object_arguments = [
        item.get("argument")
        for item in call.argument_sources
        if any(
            value.get("object_only") or value.get("container_object")
            for value in item.get("sources", ())
        )
    ]
    inputs = (
        [
            dict(flow, source_parameter=state.parameter)
            for flow in call.argument_flows
            if flow.get("kind") == "capture" and flow.get("source") == state.parameter
        ]
        if state.capture
        else call.parameter_flows
    )
    flows = [
        flow
        for flow in inputs
        if flow.get("source_parameter") == state.parameter
        and flow.get("argument") not in object_arguments
        and conditions_possible(context.index, context.constant_tests, flow)
    ]
    flows.extend(capture_flows)
    flows.extend(
        _returned_flows(context, analysis, state, call, max_depth - len(state.path) - 1, boundaries)
    )
    if not flows:
        return
    relevant_calls.add(call.id)

    # Follow open carriers and record an analysis boundary for unknown transformations.
    # 仅追踪仍可作为开放容器传递的事实，未知变换记录为分析边界
    carried = [
        flow
        for flow in flows
        if _open_container(context.index, context.transform_locations, flow)
    ]
    span = call_span(call)
    uncertain_operation = carrier_operation_boundary(analysis, identity, state.parameter, call)
    if state.capture and uncertain_operation is None:
        uncertain_operation = next(
            (
                operation
                for flow in carried
                for operation in (_return_operation_boundary(analysis, state.function, flow, call),)
                if operation is not None
            ),
            None,
        )
    if carried and uncertain_operation is not None:
        boundaries.append(
            AnalysisBoundary(
                "unsupported_carrier_operation",
                "Unknown receiver effect obscures later container contents.",
                identity,
                uncertain_operation,
            )
        )
        return
    if not carried:
        boundaries.append(
            AnalysisBoundary(
                "unsupported_variadic_transformation",
                "Flow facts do not establish an open variadic container at this call.",
                identity,
                span,
            )
        )
        return

    # Resolve targets only after establishing that an open carrier reaches this call.
    # 先确认开放容器到达当前调用，再解析目标。
    candidates, targets, constructor_fact, constructor_signature = _resolve_targets(
        context.index, analysis, call, identity, boundaries
    )
    if not targets:
        boundaries.append(
            AnalysisBoundary(
                "downstream_target_unresolved",
                "No source target for forwarding call.",
                identity,
                span,
            )
        )
        return

    for target in targets:
        _scan_target(
            context,
            entry,
            max_depth,
            state,
            state_key,
            analysis,
            call,
            target,
            candidates,
            carried,
            constructor_fact,
            constructor_signature,
            pending,
            findings,
            boundaries,
        )


## Hold one candidate forwarding path and its conditions.
## 保存一条候选转发路径及其条件。
class _PathCandidate(FrozenRecord):
    _record_fields = ("steps", "conditions", "status")
    __match_args__ = _record_fields

    ## Store the steps, path conditions and status for one candidate flow.
    ## 保存一条候选转发流的步骤、路径条件和状态。
    #
    #  @param steps Forwarding steps accumulated by the scan
    #  @param conditions Conditions required for this path
    #  @param status Candidate path status
    def __init__(self, steps, conditions, status):
        object.__setattr__(self, "steps", steps)
        object.__setattr__(self, "conditions", conditions)
        object.__setattr__(self, "status", status)


## Identify a destination parameter and any captured binding.
## 标识目标参数及其捕获绑定。
class _FlowDestination(FrozenRecord):
    _record_fields = ("parameter", "captured")
    __match_args__ = _record_fields

    ## Store the destination parameter and its captured binding state.
    ## 保存目标参数及其捕获绑定状态。
    #
    #  @param parameter Destination parameter name
    #  @param captured Captured binding information
    def __init__(self, parameter, captured):
        object.__setattr__(self, "parameter", parameter)
        object.__setattr__(self, "captured", captured)


## Extend a forwarding candidate with one condition-checked call hop.
## 将一条经过条件校验的调用边加入转发候选路径。
#
#  @param state Current forwarding path and source function
#  @param analysis Producer analysis for the caller
#  @param call Call fact being considered
#  @param definition Resolved downstream function definition
#  @param flow Producer forwarding fact
#  @param max_depth Maximum allowed path length
#  @param boundaries Mutable collection receiving unresolved path limits
#  @return Extended path candidate, or None when conditions or depth reject it
def _conditioned_path(
    state,
    analysis,
    call,
    definition,
    flow,
    max_depth,
    boundaries,
):
    identity = state.function.identity
    span = call_span(call)
    status = _target_status(analysis, call)
    conditions = conditional_path_conditions(analysis, call, definition.identity, flow)
    if conditions is None:
        return None
    step = ForwardingStep(
        identity,
        state.parameter,
        call.callee_name,
        span,
        definition.identity,
        status,
        conditions=conditions,
    )
    path = (*state.path, *flow.get("return_steps", ()), step)
    path_conditions = []
    for hop in path:
        for condition in hop.conditions:
            if condition not in path_conditions:
                path_conditions.append(condition)
    if not consistent_conditions(path_conditions):
        return None
    if len(path) > max_depth:
        boundaries.append(
            AnalysisBoundary(
                "max_forwarding_depth_reached", "Forwarding depth limit reached.", identity, span
            )
        )
        return None
    return _PathCandidate(path, tuple(path_conditions), status)


## Resolve the downstream parameter receiving a forwarded container.
## 解析接收转发容器的下游参数。
#
#  @param entry Public source entry being scanned
#  @param state Current forwarding path and parameter
#  @param call Call fact being considered
#  @param definition Resolved downstream function definition
#  @param candidates Possible targets reported by the producer
#  @param flow Producer forwarding fact
#  @param candidate Condition-checked path candidate
#  @param constructor_signature Optional constructor-only signature
#  @param boundaries Mutable collection receiving unsupported binding limits
#  @param findings Mutable collection receiving confirmed findings
#  @return Destination binding, or None when propagation cannot be established
def _flow_destination(
    entry,
    state,
    call,
    definition,
    candidates,
    flow,
    candidate,
    constructor_signature,
    boundaries,
    findings,
):
    identity = state.function.identity
    span = call_span(call)
    expansion = _expansion_kind(flow.get("argument", {}))
    if expansion is not None:
        if expansion != state.kind:
            boundaries.append(
                AnalysisBoundary(
                    "variadic_channel_transformation",
                    "Cross-channel variadic expansion is not supported.",
                    identity,
                    span,
                )
            )
            return None
        if not definition.signature.accepts_variadic(expansion):
            finding = ForwardingFinding(
                function=entry.identity,
                parameter_name=state.origin_parameter,
                parameter_kind=state.kind,
                callee_expression=call.callee_name,
                callsite=span,
                target=definition.identity,
                reason_code="target_lacks_corresponding_variadic_parameter",
                path=candidate.steps,
                target_status=candidate.status,
                target_candidates=candidates,
                receiver_type_evidence=tuple(getattr(call, "receiver_type_evidence", ())),
                conditions=candidate.conditions,
            )
            if finding not in findings:
                findings.append(finding)
            return None
        next_parameter = (
            definition.signature.kwarg
            if expansion is VariadicKind.KEYWORD
            else definition.signature.vararg
        )
    else:
        next_parameter = flow.get("target_capture", flow.get("target_parameter"))
        if flow.get("target_path"):
            next_parameter = None

    # A captured destination uses a lexical binding instead of the target's formal parameter list.
    # 捕获目标通过词法绑定传递，无需在目标的形参列表里查找。
    captured = flow.get("target_capture") is not None
    if not isinstance(next_parameter, str):
        boundaries.append(
            AnalysisBoundary(
                "propagation_binding_unavailable",
                "No whole-container binding to a downstream formal parameter.",
                identity,
                span,
            )
        )
        return None
    if constructor_signature is not None:
        boundaries.append(
            AnalysisBoundary(
                "conditional_constructor_body_not_followed",
                "The conditional constructor reference establishes only a signature.",
                identity,
                span,
            )
        )
        return None
    if not captured and next_parameter not in parameter_names(definition):
        boundaries.append(
            AnalysisBoundary(
                "propagation_binding_unavailable",
                "No whole-container binding to a downstream formal parameter.",
                identity,
                span,
            )
        )
        return None
    return _FlowDestination(next_parameter, captured)


## Queue a downstream body when its execution is within the scan boundary.
## 仅在下游函数体的执行处于扫描边界内时加入待处理队列。
#
#  @param context Analysis context for the indexed source snapshot
#  @param entry Public source entry being scanned
#  @param max_depth Maximum forwarding depth
#  @param state Current forwarding path and parameter
#  @param state_key Identity key for the propagated parameter state
#  @param analysis Producer analysis for the caller
#  @param call Call fact being considered
#  @param definition Resolved downstream function definition
#  @param candidate Condition-checked path candidate
#  @param destination Resolved downstream parameter binding
#  @param constructor_fact Optional constructor execution evidence
#  @param pending Mutable work queue of source functions
#  @param boundaries Mutable collection receiving scan limits
def _enqueue_target_body(
    context,
    entry,
    max_depth,
    state,
    state_key,
    analysis,
    call,
    definition,
    candidate,
    destination,
    constructor_fact,
    pending,
    boundaries,
):
    identity = state.function.identity
    span = call_span(call)
    if constructor_fact is not None and constructor_fact["body_execution"] != "synchronous":
        boundaries.append(
            AnalysisBoundary(
                "deferred_callee_body_not_followed",
                "The bound constructor body executes in a deferred phase.",
                identity,
                span,
            )
        )
        return
    body_boundaries = _callee_body_boundaries(analysis, call)
    if body_boundaries:
        boundaries.extend(body_boundaries)
        return
    if len(candidate.steps) >= max_depth:
        boundaries.append(
            AnalysisBoundary(
                "max_forwarding_depth_reached", "Forwarding depth limit reached.", identity, span
            )
        )
        return
    try:
        child = _expand_body(context, analysis, call, definition)
    except ResolutionError as exc:
        boundaries.append(
            AnalysisBoundary("forwarding_context_unavailable", str(exc), identity, span)
        )
        return
    next_state = _State(
        definition,
        destination.parameter,
        state.origin_parameter,
        state.kind,
        candidate.steps,
        (*state.ancestry, state_key),
        child,
        destination.captured,
        state.conditional,
    )
    if next_state not in pending:
        pending.append(next_state)


## Propagate one call by validating its path, destination, then child body.
## 依次校验路径、目标和子函数体后传播调用。
#
#  @param context Analysis context for source and producer facts.
#  @param entry Scanned entry function.
#  @param max_depth Maximum forwarding depth.
#  @param state Current scan path state.
#  @param state_key Deduplication key for the state.
#  @param analysis Producer flow analysis.
#  @param call Call fact being propagated.
#  @param target Candidate source target selected for propagation.
#  @param candidates Producer-reported candidate targets for the call.
#  @param carried Flows that preserve the open variadic container.
#  @param constructor_fact Optional evidence that constructor execution is safe.
#  @param constructor_signature Optional constructor binding signature.
#  @param pending Work queue receiving successor scan states.
#  @param findings Findings collected for the current entry point.
#  @param boundaries Analysis limits collected during traversal.
#  @return None; updates the supplied queue, findings and boundaries.
def _scan_target(
    context,
    entry,
    max_depth,
    state,
    state_key,
    analysis,
    call,
    target,
    candidates,
    carried,
    constructor_fact,
    constructor_signature,
    pending,
    findings,
    boundaries,
):
    identity = state.function.identity
    span = call_span(call)
    definition = _target_definition(context.index, target)
    if definition is None:
        boundaries.append(
            AnalysisBoundary(
                "target_definition_unavailable",
                "Forwarding target source is unavailable.",
                identity,
                span,
            )
        )
        return
    for flow in carried:
        candidate = _conditioned_path(
            state, analysis, call, definition, flow, max_depth, boundaries
        )
        if candidate is None:
            continue
        destination = _flow_destination(
            entry,
            state,
            call,
            definition,
            candidates,
            flow,
            candidate,
            constructor_signature,
            boundaries,
            findings,
        )
        if destination is None:
            continue
        _enqueue_target_body(
            context,
            entry,
            max_depth,
            state,
            state_key,
            analysis,
            call,
            definition,
            candidate,
            destination,
            constructor_fact,
            pending,
            boundaries,
        )


## Resolve forwarding candidates without promoting unproved source bindings.
## 解析转发候选，不将未证明的源码绑定提升为确定目标。
#
#  @param index Source index for indexed identities.
#  @param analysis Producer flow analysis containing target evidence.
#  @param call Call fact whose forwarding targets are resolved.
#  @param identity Identity of the caller function.
#  @param boundaries Conservative analysis boundaries to update.
#  @return Producer candidate identities, targets to follow, constructor binding fact,
#          and conditional constructor signature. The targets to follow use the selected identity
#          alone when it is available and the call is resolved. Otherwise they combine any selected
#          identity, producer candidates and receiver-allocation candidates. Identity or binding
#          checks can clear the targets. Each constructor field can be None.
#          依次返回生产者候选身份、扫描跟进目标、构造器绑定事实和条件构造器签名。
#          调用已解析且有选定身份时，仅跟进该目标。其他情况下合并可用的选定目标、生产者候选和
#          根据接收者分配推导的候选。身份或绑定校验可清空跟进目标。两项构造器信息均可为空。
def _resolve_targets(
    index,
    analysis,
    call,
    identity,
    boundaries,
):
    candidates = candidate_identities(call)
    selected = identity_from_target(call.target) if call.target else None
    allocated_classes = tuple(
        dict.fromkeys(
            identity_from_target(candidate)
            for source in getattr(call, "receiver_sources", ())
            if isinstance(source, dict)
            and source.get("kind") == "call_result"
            and source.get("relation") == "direct"
            and not source.get("projection")
            and not source.get("output_path")
            and source.get("evidence")
            for candidate in source.get("instance_candidates", ())
            if isinstance(candidate, dict)
            and candidate.get("module")
            and candidate.get("qualname")
            and candidate.get("file_path")
            and candidate.get("lineno")
        )
    )
    method_name = call.callee_name.rsplit(".", 1)[-1]
    allocation_candidates = tuple(
        dict.fromkeys(
            function.identity
            for owner in allocated_classes
            if owner is not None and owner in index.classes
            for function in index.functions
            if function.identity.module == owner.module
            and function.identity.qualname.startswith(owner.qualname + ".")
            and function.identity.qualname.rsplit(".", 1)[-1] == method_name
            and "." not in function.identity.qualname[len(owner.qualname) + 1 :]
        )
    )
    if allocation_candidates and any(
        source.get("value_incomplete") or source.get("attribute_provenance")
        for source in getattr(call, "receiver_sources", ())
        if isinstance(source, dict)
    ):
        boundaries.append(
            AnalysisBoundary(
                "pcresolve_class_attribute_state_unknown",
                "PCResolve identifies a possible allocated class, but class attribute state "
                "or alternative receiver types remain incomplete.",
                identity,
                call_span(call),
            )
        )

    # Retain uncertainty when the producer supplies candidates instead of a resolved target.
    # 当生产者只能给出候选目标时，保留目标身份的不确定性。
    targets = (
        (selected,)
        if selected and call.target_status == "resolved"
        else tuple(
            dict.fromkeys(((selected,) if selected else ()) + candidates + allocation_candidates)
        )
    )

    # Stop following targets when identity or class binding evidence is insufficient.
    # 目标身份或类绑定缺乏证据时停止追踪，避免将候选当作确定目标
    if any(
        boundary.get("call_id") == call.id
        and boundary.get("reason") == "callable_identity_incomplete"
        for boundary in analysis.boundaries
    ):
        targets = ()
    if (
        any(
            value.get("kind") == "parameter"
            and value.get("source_class_origin")
            or value.get("class_type")
            and value.get("class_lookup_mutations")
            for value in call.receiver_sources
        )
        or any("lookup_preservation" in fact for fact in getattr(call, "class_method_bindings", ()))
        or bool(getattr(call, "conditional_source_bindings", ()))
        and call.target_status != "constructor"
        or analysis.inputs.get("conditional_source_state") is True
        and call.target_status in ("super_new", "super_method", "classmethod")
    ):
        if (
            source_classmethod_binding(analysis, call) is None
            and conditional_source_binding(analysis, call) is None
        ):
            targets = ()
    constructor_fact = source_constructor_binding(analysis, call)
    constructor_signature = conditional_constructor_signature(analysis, call)
    if (
        (
            getattr(call, "constructor_bindings", ())
            or call.target_status == "constructor"
            and selected is not None
            and selected.qualname.endswith((".__new__", ".__init__"))
        )
        and constructor_fact is None
        and constructor_signature is None
    ):
        targets = ()
    return candidates, targets, constructor_fact, constructor_signature


## Build an analysis boundary attached to a root variadic parameter
## 构建关联到根可变参数的分析边界
#
#  @param boundary Existing analysis boundary to associate with the root channel
#  @param entry Resolved source entry for the requested API
#  @param state Current abstract or analysis state
#  @return Boundary annotated with the root function and variadic parameter
def _root_boundary(
    boundary,
    entry,
    state,
):
    return replace(
        boundary,
        root_function=entry.identity,
        parameter_name=state.origin_parameter,
        parameter_kind=state.kind,
    )
