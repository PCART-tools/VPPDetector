## @package vppdetector.scan.flow
#  Flow shape and source-call proof helpers shared by structural scan paths.
#
#
#  Check carrier shape, prior effects and producer call evidence when deciding whether a variadic
#  flow can be followed.
#  在判断能否跟进可变参数流时校验载体形态、既有效果和生产者调用证据。



from pathlib import Path

from ..facts.adapter import ResolutionError
from ..facts.calls import call_span, candidate_identities, direct_calls, identity_from_target
from ..facts.calls import target_status as _target_status
from ..facts.conditions import conditions_possible
from ..facts.containers import copy_protocol_target, preserved_mapping_remainder
from ..facts.creation import source_constructor_binding
from ..facts.scope import capture_names, immediate_body
from ..models import AnalysisBoundary, VariadicKind


## Use only exact call-time open captures of an immediately invoked local function
## 仅沿立即调用的局部函数读取精确的调用时开放捕获
#
#  @param index Source index used for exact target lookups
#  @param constant_tests Context-owned cache of source condition facts
#  @param transform_locations Context-owned cache of syntax locations
#  @param analysis PCResolve analysis result being validated or consumed
#  @param state Current abstract or analysis state
#  @param call PCResolve producer call record being analyzed
#  @return Validated flow records for exact open captured containers
def _capture_flows(
    index,
    constant_tests,
    transform_locations,
    analysis,
    state,
    call,
):
    if (
        call.target is None
        or _target_status(analysis, call) != "resolved"
        or call.analysis_status != "analyzed"
        or call.binding_status != "complete"
        or call.binding_issues
    ):
        return []
    target = identity_from_target(call.target)
    definition = _target_definition(index, target)
    if (
        definition is None
        or not immediate_body(definition.node)
        or target.module != state.function.identity.module
        or not target.qualname.startswith(state.function.identity.qualname + ".")
        or any(candidate != target for candidate in candidate_identities(call))
    ):
        return []

    # Check producer capture names against the target syntax before admitting individual flows.
    # 接纳单条传播流前，先用目标源码校验生产者提供的捕获名称。
    records = getattr(call, "capture_bindings", ())
    names = tuple(item.get("capture") for item in records)
    lexical = capture_names(definition.node, names)
    result = []
    for record in records:
        name = record.get("capture")
        binding = record.get("container_binding", {})
        roots = record.get("sources", ())
        if (
            name not in lexical
            or names.count(name) != 1
            or binding.get("status") != "exact"
            or binding.get("contents_unknown")
            or binding.get("shape") not in {"dict", "list", "tuple"}
            or not binding.get("evidence")
            or not conditions_possible(index, constant_tests, binding)
            or len(roots) != 1
            or roots[0].get("kind") != "container"
            or roots[0].get("source") != binding.get("source")
            or roots[0].get("container_shape") != binding.get("shape")
            or roots[0].get("relation") != "direct"
            or any(
                roots[0].get(flag)
                for flag in (
                    "value_incomplete",
                    "projection",
                    "output_path",
                )
            )
        ):
            continue
        contents = record.get("current_sources", ())
        if any(
            value.get("value_incomplete")
            or (value.get("object_only")
                and not conditions_possible(index, constant_tests, value))
            for value in contents
        ):
            continue
        for value in contents:
            if (
                not _parameter_dependency(value, state.parameter)
                or not _open_container(index, transform_locations, value)
                or not conditions_possible(index, constant_tests, value)
            ):
                continue
            expected = "dict" if state.kind is VariadicKind.KEYWORD else {"list", "tuple"}
            if (
                binding["shape"] != expected
                if isinstance(expected, str)
                else binding["shape"] not in expected
            ):
                continue
            result.append(
                dict(
                    value,
                    source_parameter=state.parameter,
                    argument={"capture": name},
                    target_capture=name,
                    target_parameter=None,
                    target_path=[],
                    relation="direct",
                    output_path=[],
                )
            )
    return result


## A source owner's contexts, not a proof that unknown contexts are absent
## 读取源码所有者的接收者上下文，但不证明未知上下文不存在
#
#  @param analysis PCResolve analysis result being validated or consumed
#  @param identity Source-level identity used for lookup
#  @return Tuple of source receiver identities recorded for the function
def _receiver_contexts(analysis, identity):
    return tuple(
        identity_from_target(receiver)
        for summary in analysis.functions
        if identity_from_target(summary["function"]) == identity
        for receiver in summary.get("receiver_contexts", ())
    )


## Retain source callable/class facts on unique helper edges
## 仅在唯一辅助调用边上保留源码可调用对象和类事实
#
#  @param context Reusable analysis context for the selected source snapshot
#  @param analysis PCResolve analysis result being validated or consumed
#  @param call PCResolve producer call record being analyzed
#  @param definition Indexed callee source function to analyze
#  @return Validated neutral or call-context-specific producer analysis
#  @exception ResolutionError If the call edge or required receiver facts are unusable
def _expand_body(
    context,
    analysis,
    call,
    definition,
):
    required, neutral = _receiver_context_requirement(context, call, definition)
    if neutral is not None:
        return neutral
    if (
        call.target is None
        or identity_from_target(call.target) != definition.identity
        or any(target != definition.identity for target in candidate_identities(call))
    ):
        raise ResolutionError("No unique usable call edge for callee-body propagation.")

    # Validate the expanded callee under the incoming receiver state before following its body.
    # 跟进函数体前，校验展开的被调用方是否符合传入接收者的状态。
    child = _expand_call_context(context.adapter, analysis, call, definition)
    _validate_class_lookup_states(call, child, definition)
    if required:
        _validate_class_receiver_context(call, child, definition)
    else:
        _validate_instance_contexts(context, analysis, call, child, definition)
    return child


## Decide whether expansion requires an explicit class receiver context.
## 判断展开是否要求显式类接收者上下文。
#
#  @param context Analysis context containing the source index and adapter
#  @param call Call fact whose incoming receiver is inspected
#  @param definition Indexed target definition
#  @return Requirement flag and neutral analysis when no receiver is required
#  @exception ResolutionError If the call binding is unusable
def _receiver_context_requirement(context, call, definition):
    if call.binding_status == "invalid":
        raise ResolutionError("No usable call binding for callee-body propagation.")
    required = (
        call.target_status in {"classmethod", "super_new"}
        or definition.node.name == "__new__"
        and any(
            owner.module == definition.identity.module
            and owner.file_path == definition.identity.file_path
            and definition.identity.qualname == owner.qualname + ".__new__"
            for owner in context.index.classes
        )
    )
    if not required:
        neutral = context.adapter.analyze(definition.identity)
        required = bool(_receiver_contexts(neutral, definition.identity))
        incoming_callable = any(
            value.get("kind") == "callable" or value.get("callable_type")
            for argument in call.argument_sources
            for value in argument.get("sources", ())
        )
        incoming_literal = any(
            argument.get("literal") is not None for argument in call.argument_sources
        )
        incoming_class = any(
            value.get("source_class_origin") and value.get("class_type")
            for argument in call.argument_sources
            for value in argument.get("sources", ())
        )
        incoming_instance = any(
            value.get("instance_type")
            for argument in call.argument_sources
            for value in argument.get("sources", ())
        )
        if (
            not required
            and not incoming_callable
            and not incoming_literal
            and not incoming_class
            and not incoming_instance
            and not getattr(call, "capture_bindings", ())
        ):
            # Instance-method source candidates and ordinary helpers retain
            # the existing nominal body analysis. Never use this fallback for
            # a missing class receiver context.
            # 实例方法候选和普通辅助函数仍沿用原有函数体分析；接收者类上下文缺失时不得使用此回退。
            return False, neutral
    return required, None


## Expand the callee body under exact incoming-call facts.
## 在精确入边事实下展开被调用函数体。
#
#  @param adapter Producer adapter used for isolated call expansion
#  @param analysis Parent producer analysis
#  @param call Exact call edge being expanded
#  @param definition Indexed source definition of the target
#  @return Expanded producer analysis with one usable callee summary
#  @exception ResolutionError If mixed or incomplete incoming contexts cannot be isolated
def _expand_call_context(
    adapter,
    analysis,
    call,
    definition,
):
    child = adapter.expand(analysis, call.id)
    if call.caller == call.target or any(
        not getattr(inner, "analysis_contexts", ())
        or any(item.get("incoming_call_id") != call.id for item in inner.analysis_contexts)
        for inner in direct_calls(child, definition.identity)
    ):
        try:
            child = adapter.expand(analysis, call.id, isolate=True)
        except (ResolutionError, TypeError) as exc:
            raise ResolutionError(
                "Mixed incoming callable contexts cannot prove one path."
            ) from exc
    summaries = [
        summary
        for summary in child.functions
        if identity_from_target(summary["function"]) == definition.identity
    ]
    if len(summaries) != 1:
        raise ResolutionError("Callee-body expansion is unavailable or budget-limited.")
    return child


## Confirm class lookup facts survive every isolated incoming call context.
## 确认类查找事实在每个隔离的入边上下文中保持一致。
#
#  @param call Parent call fact providing class lookup state
#  @param child Expanded analysis for the target body
#  @param definition Indexed target definition
#  @exception ResolutionError If incoming lookup state is absent or conflicting
def _validate_class_lookup_states(call, child, definition):
    class_states = [
        (
            argument.get("parameter"),
            value,
            "class_type" if value.get("class_type") else "instance_type",
        )
        for argument in call.argument_sources
        for value in argument.get("sources", ())
        if (value.get("class_type") or value.get("instance_type"))
        and value.get("class_lookup_mutations")
    ]
    if class_states:
        for inner in direct_calls(child, definition.identity):
            contexts = getattr(inner, "analysis_contexts", ())
            if not contexts:
                raise ResolutionError("Incoming class lookup state is unavailable.")
            for incoming in contexts:
                for parameter, value, type_key in class_states:
                    facts = incoming.get("parameter_facts", {}).get(parameter, ())
                    if not facts or any(
                        fact.get(type_key) != value[type_key]
                        or fact.get("class_lookup_mutations") != value["class_lookup_mutations"]
                        for fact in facts
                    ):
                        raise ResolutionError(
                            "Incoming class lookup state is incomplete or conflicting."
                        )


## Validate instance receiver facts across isolated incoming contexts.
## 校验隔离入边上下文中的实例接收者事实。
#
#  @param context Analysis context used for constructor binding
#  @param analysis Parent producer analysis
#  @param call Parent call fact being expanded
#  @param child Expanded analysis for the target body
#  @param definition Indexed target definition
#  @exception ResolutionError If receiver facts are incomplete or mixed
def _validate_instance_contexts(
    context,
    analysis,
    call,
    child,
    definition,
):
    # PCResolve's top-level calls merge incoming contexts. Do not combine
    # a target from one edge with container facts from another. Keep the
    # narrow single-edge case; mixed snapshots remain explicit boundaries.
    # PCResolve会合并顶层调用的输入上下文；不能把不同调用边的目标与容器事实拼在一起，
    # 混合快照保留为分析边界。
    ordinary = (
        *definition.signature.positional_only,
        *definition.signature.positional_or_keyword,
        *definition.signature.keyword_only,
    )
    instances = {}
    for argument in call.argument_sources:
        parameter = argument.get("parameter")
        if parameter in ordinary:
            for value in argument.get("sources", ()):
                if value.get("instance_type"):
                    instances.setdefault(parameter, []).append(value["instance_type"])
                    if value.get("value_incomplete") or argument.get("target_path"):
                        raise ResolutionError("Incoming instance binding is incomplete.")
    for inner in direct_calls(child, definition.identity):
        contexts = getattr(inner, "analysis_contexts", ())
        if not contexts or any(item.get("incoming_call_id") != call.id for item in contexts):
            raise ResolutionError("Mixed incoming callable contexts cannot prove one path.")
        for item in contexts:
            for parameter, types in instances.items():
                values = item.get("parameter_facts", {}).get(parameter, ())
                if (
                    not values
                    or any(
                        value.get("instance_type") not in types or value.get("value_incomplete")
                        for value in values
                    )
                    or any(
                        identity not in [value.get("instance_type") for value in values]
                        for identity in types
                    )
                ):
                    raise ResolutionError("Incoming instance context is incomplete or conflicting.")

    # A constructor must also preserve the incoming receiver evidence in its expanded body.
    # 展开的构造器还须保留传入接收者的证据。
    constructor = source_constructor_binding(analysis, call)
    if constructor is not None and constructor["phase"] == "__init__":
        parameter = constructor["implicit_binding"]["parameter"]
        positional = (
            *definition.signature.positional_only,
            *definition.signature.positional_or_keyword,
        )
        if not positional or positional[0] != parameter:
            raise ResolutionError("Initializer implicit receiver binding is unavailable.")


## Validate the class receiver facts selected for an expanded target body.
## 校验展开目标函数体所选用的类接收者事实。
#
#  @param call Parent call fact providing incoming receiver values
#  @param child Expanded analysis for the target body
#  @param definition Indexed target definition
#  @exception ResolutionError If receiver facts are absent, mixed or incomplete
def _validate_class_receiver_context(call, child, definition):
    receivers = _receiver_contexts(child, definition.identity)
    if len(receivers) > 1:
        raise ResolutionError("Mixed class receiver contexts cannot prove one forwarding path.")

    # Unknown contexts may be absent from receiver_contexts. Validate every
    # actual incoming receiver value, including the explicit first formal of
    # __new__, rather than treating a single listed class as complete proof.
    # 未知上下文可能不在receiver_contexts中；需核对每个实际接收者，包括__new__显式首参数，
    # 不能把单个类记录当作完整证明。
    if not receivers:
        raise ResolutionError("Incoming class receiver facts are incomplete or conflicting.")
    positional = (
        *definition.signature.positional_only,
        *definition.signature.positional_or_keyword,
    )
    values = [
        value
        for argument in call.argument_sources
        if positional and argument.get("parameter") == positional[0]
        for value in argument.get("sources", ())
    ]
    if not values or any(
        not value.get("class_type")
        or identity_from_target(value["class_type"]) != receivers[0]
        or value.get("relation") != "direct"
        or value.get("projection")
        or value.get("output_path")
        or any(
            value.get(flag) for flag in ("value_incomplete", "import_incomplete", "import_modified")
        )
        for value in values
    ):
        raise ResolutionError("Incoming class receiver facts are incomplete or conflicting.")


## Keep exact tuple slots until the router proves the selected open shape
## 保留精确tuple槽位，直到路由器证明开放形状
#
#  @param index Source index used to validate condition locations
#  @param transform_locations Context-owned cache of syntax locations
#  @param value Producer return value record considered for routing
#  @return Whether the value is an open container or a supported exact projection
def _routable_return(index, transform_locations, value):
    if value.get("object_only") or value.get("container_object"):
        return False
    if _open_container(index, transform_locations, value):
        return True
    if value.get("kind") not in {"parameter", "call_result"}:
        return False
    projection = value.get("projection", ())
    path = value.get("output_path", ())
    slots = path[:-1] if path and path[-1] == "*" else path
    if not projection and not slots:
        return False
    if any(type(slot) is not int or slot < 0 for slot in (*projection, *slots)):
        return False
    if projection and value.get("kind") != "call_result":
        return False
    if value.get("relation") != "contained" and not (
        projection and value.get("relation") == "derived"
    ):
        return False

    # Reuse the existing source-evidence rejection of finite comprehensions.
    # 有限推导式仍沿用现有的源码证据拒绝规则。
    if not _open_container(
        index,
        transform_locations,
        dict(value, projection=[], output_path=[], relation="direct"),
    ):
        return False
    for evidence in value.get("evidence", ()):
        source = Path(evidence.get("file_path", ""))
        location = tuple(
            evidence.get(name) for name in ("lineno", "col_offset", "end_lineno", "end_col_offset")
        )
        if transform_locations.contains(index.functions, source, location, returned=True):
            return False
    return True


## Resolve a call target to one indexed source definition
## 将调用目标解析为唯一索引源码定义
#
#  @param index Source index used for exact target lookups
#  @param target Source identity of the target to resolve
#  @return Matching indexed function, or None if it cannot be resolved uniquely
def _target_definition(index, target):
    return (
        index.find_by_location(target.file_path, target.lineno, identity=target)
        if target.file_path and target.lineno
        else index.find(target)
    )


## Flatten only PCResolve's exact expansion-to-capture wildcard binding
## 仅展开PCResolve精确记录的展开到捕获通配符绑定
#
#  @param item Producer argument binding record
#  @param function Indexed source function under analysis
#  @param root_kind Variadic channel kind at the root API
#  @return Binding path, with a proven capture wildcard flattened when applicable
def _return_binding_path(item, function, root_kind):
    path = tuple(item.get("target_path", ()))
    argument = item.get("argument")
    if path != ("*",) or not isinstance(argument, dict):
        return path
    channel = _expansion_kind(argument)
    if channel is not root_kind:
        return path
    formal = (
        function.signature.kwarg
        if channel is VariadicKind.KEYWORD
        else function.signature.vararg
        if channel is VariadicKind.POSITIONAL
        else None
    )
    return () if formal is not None and item.get("parameter") == formal else path


## Flatten only a capture's element wildcard, retaining exact tuple slots
## 仅展开捕获参数的元素通配符，同时保留精确tuple槽位
#
#  @param value Producer return value record to normalize
#  @param function Indexed source function under analysis
#  @return Original or normalized return value record
def _capture_return_value(value, function):
    path = value.get("output_path", ())
    if (
        value.get("kind") == "parameter"
        and value.get("source") in (function.signature.vararg, function.signature.kwarg)
        and not value.get("projection")
        and path[-1:] == ["*"]
        and all(type(slot) is int and slot >= 0 for slot in path[:-1])
    ):
        return dict(value, relation="contained" if path[:-1] else "direct", output_path=path[:-1])
    return value


## Unknown effects on a returned alias must not restore open contents
## 确保返回别名上的未知副作用不会重新开放容器内容
#
#  @param analysis PCResolve analysis result being validated or consumed
#  @param owner Indexed source function owning the returned value
#  @param value Returned alias record whose source effects are inspected
#  @param destination Source call or node where the returned value is read
#  @return Span of an obscuring operation, or None when no such operation is found
def _return_operation_boundary(
    analysis,
    owner,
    value,
    destination,
):
    endpoint = (
        destination.end_lineno or destination.lineno,
        destination.end_col_offset or destination.col_offset,
    )
    for call in direct_calls(analysis, owner.identity):
        if call.id == getattr(destination, "id", None):
            continue
        if (call.lineno, call.col_offset) > endpoint:
            continue

        # This narrow PCResolve proof already excludes unknown helper effects.
        # It is not a purity inference from a name or an input dependency.
        # 该窄范围PCResolve证明已排除未知辅助函数副作用；不能仅凭名称或输入依赖推断函数纯净。
        remainder = any(effect.get("kind") == "mapping_remainder" for effect in call.effects)
        if (
            call.result_sources
            and not remainder
            and all(_proven_object_alias(source) for source in call.result_sources)
        ):
            continue
        if (
            len(call.result_sources) == 1
            and copy_protocol_target(owner, analysis, call, call.result_sources[0]) is not None
        ):
            continue
        if _modeled_mapping_removal(analysis, call):
            # Only remove the unknown-effect barrier. Current content facts,
            # not this normal-return postcondition, still determine forwarding.
            # 此证明只移除未知副作用边界；转发结论仍由当前容器内容事实决定。
            continue
        if preserved_mapping_remainder(analysis, call, value):
            continue
        if (
            value.get("source") == call.id
            and value.get("container_object", {}).get("value_completeness")
            == "unaffected_keys_only"
        ):
            return call_span(call)
        receiver = call.receiver_sources if call.target_status == "receiver_unresolved" else ()
        ordinary = (
            source
            for item in call.argument_sources
            if isinstance(item.get("argument"), dict) and _expansion_kind(item["argument"]) is None
            for source in item.get("sources", ())
        )
        if any(
            source.get("kind") == value.get("kind")
            and source.get("source") == value.get("source")
            and (
                _whole_container(source)
                or source.get("kind") == "call_result"
                and source.get("projection") == value.get("projection")
                and source.get("projection")
                and all(type(slot) is int and slot >= 0 for slot in source["projection"])
                and not source.get("output_path")
            )
            for source in (*receiver, *ordinary)
        ):
            return call_span(call)
    return None


## Recognize a complete identity fact, not an element dependency
## 识别完整对象身份事实，不将元素依赖当作对象别名
#
#  @param value Producer return record to check for exact object identity
#  @return Whether the record proves an exact direct returned-object alias
def _proven_object_alias(value):
    obj = value.get("container_object", {})
    return bool(
        value.get("object_only")
        and value.get("kind") == "call_result"
        and value.get("relation") == "direct"
        and not value.get("projection")
        and not value.get("output_path")
        and not value.get("value_incomplete")
        and obj.get("identity") == "argument_alias"
        and obj.get("container_shape") in {"dict", "list", "tuple"}
        and obj.get("source")
        and obj.get("parameter")
        and obj.get("function")
    )


## Callable identity does not prove an effect-uncertain body is unchanged
## 避免仅凭可调用对象身份认定函数体无不确定副作用
#
#  @param analysis PCResolve analysis result being validated or consumed
#  @param call PCResolve producer call record being analyzed
#  @return Boundaries for unmodeled decorator effects, or an empty tuple
def _callee_body_boundaries(analysis, call):
    reason = "identity_decorator_effects_unmodeled"
    if not any(
        boundary.get("call_id") == call.id and boundary.get("reason") == reason
        for boundary in analysis.boundaries
    ):
        return ()
    identity, span = identity_from_target(call.caller), call_span(call)
    return (
        AnalysisBoundary(
            "callee_body_effects_unmodeled",
            "Unmodeled decorator effects prevent using the callee body for propagation.",
            identity,
            span,
        ),
        AnalysisBoundary(
            "pcresolve_" + reason, "PCResolve boundary: {}.".format(reason), identity, span
        ),
    )


## Do not confuse a comprehension dependency with an open parameter space
## 避免把推导式依赖误判为开放参数空间
#
#  @param index Source index used to validate source locations
#  @param transform_locations Context-owned cache of syntax locations
#  @param flow Producer data-flow record being checked
#  @return Whether the flow proves an open container under the current conditions
def _open_container(index, transform_locations, flow):
    if not _whole_container(flow):
        return False
    for evidence in flow.get("evidence", ()):
        path = Path(evidence.get("file_path", ""))
        location = tuple(
            evidence.get(name) for name in ("lineno", "col_offset", "end_lineno", "end_col_offset")
        )
        if transform_locations.contains(index.functions, path, location, returned=False):
            return False
    return True


## Use input dependencies only to select relevant return queries, not to prove shape
## 仅用输入依赖筛选返回查询，不据此证明容器形状
#
#  @param values Abstract values propagated through the analysis
#  @param parameter Parameter name or parameter fact being checked
#  @param calls Producer call records indexed by their source identifiers
#  @return Whether any value depends on the parameter through recorded calls
def _depends_on_parameter(values, parameter, calls):
    pending, seen = list(values), set()
    while pending:
        value = pending.pop()
        if value.get("kind") in {"parameter", "capture"} and value.get("source") == parameter:
            return True
        source = value.get("source")
        producer = calls.get(source) if isinstance(source, str) else None
        if value.get("kind") == "call_result" and producer and producer.id not in seen:
            seen.add(producer.id)
            pending.extend(
                value for item in producer.argument_sources for value in item.get("sources", ())
            )
            pending.extend(
                value
                for item in getattr(producer, "capture_bindings", ())
                for value in item.get("current_sources", ())
            )
    return False


## Recognize complete bounded effects, not purity from a helper's spelling
## 识别完整且有界的映射修改效果，不凭辅助函数名称推断纯度
#
#  @param analysis PCResolve analysis result being validated or consumed
#  @param call PCResolve producer call record being analyzed
#  @return Whether the call's mapping removals have complete bounded evidence
def _modeled_mapping_removal(analysis, call):
    if (
        not call.target
        or _target_status(analysis, call) != "resolved"
        or call.binding_status != "complete"
        or not call.effects
        or any(
            boundary.get("call_id") == call.id
            and boundary.get("reason")
            in {
                "mapping_effect_unproven",
                "mapping_effect_budget",
                "container_effect_unknown",
                "identity_decorator_effects_unmodeled",
            }
            for boundary in analysis.boundaries
        )
    ):
        return False
    return all(
        effect.get("kind") == "mapping_element"
        and effect.get("operation") in {"pop", "delete"}
        and effect.get("completion") == "normal_return"
        and effect.get("status") == "bounded"
        and effect.get("state_after") in {"absent", "conditional"}
        and effect.get("call_id") == call.id
        and effect.get("binding", {}).get("status") == "exact"
        and len(effect.get("element_path", ())) == 1
        and isinstance(effect["element_path"][0], str)
        for effect in call.effects
    )


## A recorded dependency, without asserting an open container shape
## 读取参数依赖，但不据此断言容器形状开放
#
#  @param value Producer flow record to check for parameter dependence
#  @param parameter Parameter name or parameter fact being checked
#  @return Whether the source record depends on the named parameter or its container
def _parameter_dependency(value, parameter):
    return bool(
        value.get("kind") in {"parameter", "capture"}
        and value.get("source", value.get("name")) == parameter
        or value.get("parameter_container") == parameter
    )


## Classify an argument as positional or keyword expansion
## 判定实参属于位置展开还是关键字展开
#
#  @param argument Producer argument record describing starred or keyword expansion
#  @return Positional or keyword variadic kind, or None for an ordinary argument
def _expansion_kind(argument):
    if argument.get("starred"):
        return VariadicKind.POSITIONAL
    if "keyword" in argument and argument["keyword"] is None:
        return VariadicKind.KEYWORD
    return None


## Require an open container, not a selected element or dict key
## 要求证据指向开放容器，而非选中元素或字典键
#
#  @param flow Producer data-flow record being checked
#  @return Whether the flow describes the whole container or its element wildcard
def _whole_container(flow):
    if flow.get("object_only") or flow.get("container_object"):
        return False
    if flow.get("projection") or flow.get("container_role") == "key":
        return False
    path = flow.get("output_path", [])
    if flow.get("relation") == "direct" and not path:
        return True
    return flow.get("relation") in {"contained", "derived"} and path == ["*"]
