## @package vppdetector.assess.runner
#  Public call-specific parameter-assessment orchestration.
#
#
#  Resolve the target entry, bind the selected argument, apply relevant caller facts and collect
#  the proof result.
#  解析目标入口，绑定选定实参，应用相关调用方事实并汇总证明结果。



import ast
import tokenize

from .._analysis_context import (
    AnalysisContext,
)
from .._analysis_context import (
    prepare_context as _prepare_context,
)
from .._analysis_context import (
    validate_depth as _validate_depth,
)
from ..facts.adapter import ResolutionError
from ..models import (
    AnalysisBoundary,
    CallContext,
    FunctionIdentity,
    ParameterAssessment,
    ParameterEvidence,
    ParameterState,
)
from .binding import _signature, _Stop
from .caller_arguments import caller_arguments
from .engine import _Proof
from .frame import _Frame
from .observations._attribute_retention import attribute_retention as observed_attribute_retention
from .observations._capture_rejection import capture_rejection as observed_capture_rejection
from .observations._container_predicates import container_predicate as observed_container_predicate
from .observations._fixed_binding import fixed_binding as observed_fixed_binding
from .observations._normal_returns import mapping_return as observed_mapping_return
from .observations._observed_checks import keyword_check as observed_keyword_check
from .observations.contextvars import caller_contextvar_conditions
from .values import (
    _UNKNOWN,
    _source_state,
    _Value,
)


## Apply caller-side facts that are bound to the selected entry call.
## 应用绑定到所选入口调用的调用方事实。
#
#  @param context Analysis context owning producer and source facts
#  @param call Parsed call supplied by the caller
#  @param node Source node for the entry call
#  @param target_api Requested API identity
#  @param change Requested parameter change
#  @param entry Resolved API entry
#  @param proof Proof ledger for this assessment
#  @param frame Initial interpretation frame
#  @param positional Abstract positional arguments
#  @param keywords Abstract keyword arguments
#  @return Updated analysis context and resolved API entry
#           更新后的分析上下文及已解析的 API 条目
def _apply_caller_facts(
    context,
    call,
    node,
    target_api,
    change,
    entry,
    proof,
    frame,
    positional,
    keywords,
):
    caller = caller_arguments(context.adapter, call, node, target_api, entry)
    if caller is not None:
        source_values, assumptions, source_target = caller
        caller_files = [
            (slot, value)
            for slot, value in source_values.items()
            if isinstance(value, dict) and value.get("kind") == "caller_file_text"
        ]

        # When the exact caller expression invokes the same source class
        # whose __init__ is being assessed, analyze the method through the
        # class-constructor entry. PCResolve then carries the fresh receiver
        # origin through super() and can validate instance-method bindings.
        # 若精确调用表达式构造的正是当前评估 __init__ 所属类，
        # 则从类构造入口分析该方法，并验证 super() 的新接收者和方法绑定。
        if (
            entry.query_class is None
            and entry.identity.qualname.endswith(".__init__")
            and entry.identity.module == target_api.module
        ):
            class_name = entry.identity.qualname.rpartition(".")[0]
            class_target = f"{entry.identity.module}.{class_name}"
            if source_target == class_target and class_name:
                class_identity = _class_identity_for_method(context, entry)
                if class_identity is not None:

                    ## Resolve the indexed class constructor entry for this caller.
                    ## 为当前调用方解析已索引的类构造入口。
                    #
                    #  @return Class context and entry, or None when resolution fails
                    def resolve_class_context():
                        try:
                            class_context = AnalysisContext.for_api(
                                context.index.source, class_identity
                            )
                            class_entry = class_context.resolve_api(class_identity)
                        except ResolutionError:
                            return None
                        return (class_context, class_entry) if class_entry is not None else None

                    cached = context.assessment_contexts.constructor(
                        class_identity, resolve_class_context
                    )
                    class_context, class_entry = cached if cached is not None else (None, None)
                    class_caller = (
                        caller_arguments(class_context.adapter, call, node, target_api, class_entry)
                        if class_context is not None
                        and class_entry is not None
                        and class_entry.identity == entry.identity
                        and class_entry.query_class == class_identity
                        else None
                    )
                    if (
                        class_caller is not None
                        and class_context is not None
                        and class_entry is not None
                    ):
                        context, entry, caller = class_context, class_entry, class_caller
                        proof.select_context(context)
                        caller_files = [
                            (slot, value)
                            for slot, value in class_caller[0].items()
                            if isinstance(value, dict) and value.get("kind") == "caller_file_text"
                        ]
                        proof.record_evidence(
                            ParameterEvidence(
                                entry.identity,
                                "source_callsite_constructor_receiver",
                                "The exact original call resolves to this source class, and "
                                "PCResolve proves its constructor entry; class-root analysis "
                                "carries the fresh receiver origin through super().",
                                call.callsite,
                                class_identity,
                            )
                        )
        applied, protocol_slots = [], []
        selected = (
            ("keyword", change.old_name)
            if change.old_name in keywords
            else ("position", change.old_position)
        )
        for slot, value in source_values.items():
            # A selected container needs element/identity tracking beyond
            # the scalar selection contract. Do not pretend it is a scalar.
            # 选中的容器需要超出标量选择契约的元素和身份跟踪；不能将其误当作标量。
            if slot == selected and value["kind"] != "literal":
                continue
            if slot[0] == "position" and isinstance(slot[1], int):
                previous = positional[slot[1]]
            elif slot[0] == "keyword" and isinstance(slot[1], str):
                previous = keywords[slot[1]]
            else:
                proof.unknown(
                    entry,
                    "conflicting_call_facts",
                    "Caller argument slot has an invalid kind or index.",
                )
                continue
            restored = _source_state(value)
            if (
                isinstance(restored, _Value)
                and restored.literal is not _UNKNOWN
                and restored.iterable is None
            ):
                # Immutable primitive arguments carry no mutable alias
                # state for an unrelated call to invalidate.
                # 不可变的原始实参没有可变别名状态，因此无关调用不会使其失效。
                restored = _Value(restored.literal)
            if (
                isinstance(previous, _Value)
                and previous.literal is not _UNKNOWN
                and (
                    not isinstance(restored, _Value)
                    or type(previous.literal) is not type(restored.literal)
                    or previous.literal != restored.literal
                )
            ):
                proof.unknown(
                    entry,
                    "conflicting_call_facts",
                    "Caller source and supplied argument syntax disagree.",
                )
            if slot[0] == "position" and isinstance(slot[1], int):
                positional[slot[1]] = restored
            elif slot[0] == "keyword" and isinstance(slot[1], str):
                keywords[slot[1]] = restored
            else:
                proof.unknown(
                    entry,
                    "conflicting_call_facts",
                    "Caller argument slot has an invalid kind or index.",
                )
                continue
            applied.append(str(slot))
            if source_values[slot].get("kind") == "iterable":
                protocol_slots.append(str(slot))
        if applied:
            description = (
                "PCResolve recovered bounded static protocol facts for slots "
                if protocol_slots
                else "PCResolve recovered finite literals for slots "
            )
            selected_slots = protocol_slots if protocol_slots else applied
            proof.record_evidence(
                ParameterEvidence(
                    entry.identity,
                    "source_caller_arguments",
                    description
                    + ", ".join(selected_slots)
                    + " from the exact original source call, conditional on: "
                    + "; ".join(assumptions),
                    call.callsite,
                )
            )
        for slot, value in caller_files:
            proof.record_evidence(
                ParameterEvidence(
                    entry.identity,
                    "source_caller_file_resource",
                    "PCResolve ties argument slot "
                    + str(slot)
                    + " to the exact open context manager; the file was read relative to "
                    + str(call.execution_directory)
                    + " and content SHA-256 is "
                    + value["sha256"]
                    + ".",
                    call.callsite,
                )
            )
    elif call.callsite is not None:
        proof.note(
            entry,
            "source_caller_arguments_unconfirmed",
            "Caller source facts are unavailable or do not match this exact call.",
        )
    return context, entry


## Bind the changed argument at the selected API entry.
## 在所选 API 入口绑定发生变更的实参。
#
#  @param entry Resolved API entry
#  @param change Requested parameter change
#  @param call Parsed caller invocation
#  @param proof Proof ledger for this assessment
#  @param positional Abstract positional arguments
#  @param keywords Abstract keyword arguments
#  @return Original changed value and bound local values
def _bind_selected_argument(
    entry,
    change,
    call,
    proof,
    positional,
    keywords,
):
    bound = entry.is_bound_method if call.bound_receiver is None else call.bound_receiver
    selected_position = None
    if change.old_name in keywords:
        original = keywords[change.old_name]
        capture = entry.signature.kwarg
        if not capture or change.old_name in (
            *entry.signature.positional_or_keyword,
            *entry.signature.keyword_only,
        ):
            proof.unknown(
                entry,
                "not_variadic_capture",
                "The changed keyword is not captured by **kwargs.",
            )
        destination = f"{capture}[{change.old_name!r}]"
    elif change.old_position is not None:
        position = change.old_position
        selected_position = position
        if position >= len(positional):
            proof.unknown(entry, "changed_argument_not_passed", "The selected position is absent.")
        original = positional[position]
        signature = _signature(entry, bound)
        fixed = sum(
            parameter.kind in (parameter.POSITIONAL_ONLY, parameter.POSITIONAL_OR_KEYWORD)
            for parameter in signature.parameters.values()
        )
        capture = entry.signature.vararg
        if not capture or position < fixed:
            proof.unknown(
                entry, "not_variadic_capture", "The changed element is not captured by *args."
            )
        destination = f"{capture}[{position - fixed}] (client position {position})"
    else:
        proof.unknown(entry, "changed_argument_not_passed", "The selected keyword is not supplied.")
    if not isinstance(original, _Value):
        proof.unknown(
            entry,
            "changed_value_unsupported",
            "Only primitive/unknown scalar arguments are modeled.",
        )

    # Replace exactly the selected argument with its tracked form before binding.
    # 绑定前仅将选定的实参替换为被跟踪的值。
    if change.old_name in keywords:
        keywords[change.old_name] = _Value(original.literal, tracked=True, type_selected=True)
    else:
        assert selected_position is not None
        positional[selected_position] = _Value(original.literal, tracked=True, type_selected=True)
    values = proof.bind(
        entry,
        positional,
        keywords,
        bound,
        change=change,
    )

    # Check supplied values against bound arguments and admit keys for receiver attributes.
    # 将提供的值与已绑定实参核对，并允许以接收者属性路径作为事实键。
    receiver = (entry.node.args.posonlyargs + entry.node.args.args)[:1]
    receiver_name = receiver[0].arg if receiver and entry.is_bound_method else None
    for name, value in call.known_values:
        if name in values and isinstance(values[name], _Value):
            known = values[name].literal
            if known is not _UNKNOWN and (type(known) is not type(value) or known != value):
                proof.unknown(entry, "conflicting_call_facts", f"Conflicting fact for {name}.")
        elif not (receiver_name and name.startswith(receiver_name + ".")):
            proof.unknown(entry, "unsupported_call_fact", f"No supported binding for {name}.")
    proof.note(entry, "entry_binding", f"{change.old_name} captured by {destination}.")
    return original, values


## Apply validated caller observations before interpreting the entry body.
## 在解释入口函数体前应用已校验的调用方观察事实。
#
#  @param context Analysis context owning source and producer facts
#  @param entry Resolved API entry
#  @param call Parsed caller invocation
#  @param change Requested parameter change
#  @param original Original argument state selected for the change
#  @param proof Proof ledger for this assessment
def _apply_observations(
    context,
    entry,
    call,
    change,
    original,
    proof,
):
    # Keep this precedence explicit: each category can terminate or reject the proof.
    # 每类观测都可能终止证明或得出拒绝结论，因此显式保留处理顺序。
    _apply_fixed_binding_observation(context, entry, call, change, original, proof)
    _apply_capture_rejection_observation(context, entry, call, change, original, proof)
    _apply_attribute_retention_observation(context, entry, call, change, original, proof)
    _apply_container_predicate_observation(context, entry, call, change, proof)
    _apply_normal_return_observation(context, entry, call, change, original, proof)
    _apply_keyword_check_observation(context, entry, call, change, original, proof)


## Apply an observed fixed-parameter binding as a terminal handled result
## 将已观测到的固定参数绑定作为终止的已处理结果
#
#  @param context Analysis context containing the source index
#  @param entry Entry function being assessed
#  @param call Caller observations for this assessment
#  @param change Parameter change under assessment
#  @param original Abstract value captured by the original parameter
#  @param proof Proof state receiving evidence or conservative failure
def _apply_fixed_binding_observation(
    context,
    entry,
    call,
    change,
    original,
    proof,
):
    if not call.observed_fixed_bindings:
        return
    target = observed_fixed_binding(context, entry, call, change, original.literal)
    if target is None:
        proof.unknown(
            entry,
            "observed_fixed_binding_unconfirmed",
            "Original-element provenance, actual fixed binding, normal "
            "completion or source call/signature evidence is unconfirmed.",
        )
    record = call.observed_fixed_bindings[0]
    checker = context.index.find(record.caller)
    if checker is None:
        proof.unknown(
            entry,
            "observed_fixed_binding_unconfirmed",
            "The observed fixed target is absent from the source index.",
        )
    proof.note(
        checker,
        "runtime_fixed_parameter_binding",
        "Caller independently traced the original captured primitive through "
        "this exact builtin mapping expansion into the actual bound method's "
        "fixed formal, and confirmed normal completion of the original call. "
        "PCResolve supplies the source call and target parameters.",
        node=record.call_span,
        target=target.identity,
    )
    raise _Stop(ParameterState.HANDLED, "observed_fixed_parameter_binding")


## Apply an observed source rejection caused by captured dictionary input
## 应用由捕获字典输入触发的源码拒绝观测
#
#  @param context Analysis context containing the source index
#  @param entry Entry function being assessed
#  @param call Caller observations for this assessment
#  @param change Parameter change under assessment
#  @param original Abstract value captured by the original parameter
#  @param proof Proof state receiving evidence or conservative failure
def _apply_capture_rejection_observation(
    context,
    entry,
    call,
    change,
    original,
    proof,
):
    if not call.observed_capture_rejections:
        return
    guard = observed_capture_rejection(context, entry, call, change, original.literal)
    if guard is None:
        proof.unknown(
            entry,
            "observed_capture_rejection_unconfirmed",
            "Original-key provenance, dictionary type, reached source guard "
            "or escaping exception is missing or conflicting.",
        )
    record = call.observed_capture_rejections[0]
    checker = context.index.find(record.checker)
    if checker is None:
        proof.unknown(
            entry,
            "observed_capture_rejection_unconfirmed",
            "The observed rejection checker is absent from the source index.",
        )
    proof.note(
        checker,
        "runtime_capture_rejection",
        "Caller traced this original captured primitive into an exact builtin "
        "dictionary and confirmed the source nonempty-dictionary rejection "
        "guard completed and its exception escaped the original call.",
        node=record.raise_span,
        target=record.checker,
    )
    proof.reject(
        entry,
        "observed_capture_guard_rejection",
        change.old_name + " reaches the observed dictionary rejection guard.",
        target=record.checker,
    )


## Apply an observed original-value retention on a returned receiver
## 应用返回接收者保留原始值的观测
#
#  @param context Analysis context containing the source index
#  @param entry Entry function being assessed
#  @param call Caller observations for this assessment
#  @param change Parameter change under assessment
#  @param original Abstract value captured by the original parameter
#  @param proof Proof state receiving evidence or conservative failure
def _apply_attribute_retention_observation(
    context,
    entry,
    call,
    change,
    original,
    proof,
):
    if not call.observed_attribute_retentions:
        return
    transfer = observed_attribute_retention(context, entry, call, change, original.literal)
    if transfer is None:
        proof.unknown(
            entry,
            "observed_attribute_retention_unconfirmed",
            "Construction, original capture retention, normal completion or "
            "source-store evidence is missing or conflicting.",
        )
    record = call.observed_attribute_retentions[0]
    proof.note(
        entry,
        "runtime_instance_attribute_retention",
        "Caller independently confirmed ordinary class construction and the "
        "returned original receiver retaining this same builtin capture dict "
        "and selected primitive after the source store and normal completion.",
        node=record.store_span,
    )
    raise _Stop(ParameterState.HANDLED, "observed_instance_attribute_retention")


## Apply an observed source predicate over the captured container
## 应用针对捕获容器的源码谓词观测
#
#  @param context Analysis context containing the source index
#  @param entry Entry function being assessed
#  @param call Caller observations for this assessment
#  @param change Parameter change under assessment
#  @param proof Proof state receiving evidence or conservative failure
def _apply_container_predicate_observation(
    context,
    entry,
    call,
    change,
    proof,
):
    if not call.observed_container_predicates:
        return
    predicate = observed_container_predicate(context, entry, call, change)
    if predicate is None:
        proof.unknown(
            entry,
            "observed_container_predicate_unconfirmed",
            "Container type, original-element provenance, execution or source "
            "evidence is missing or conflicting.",
        )
    record = call.observed_container_predicates[0]
    checker = context.index.find(record.checker)
    if checker is None:
        proof.unknown(
            entry,
            "observed_container_predicate_unconfirmed",
            "The observed predicate checker is absent from the source index.",
        )
    proof.note(
        checker,
        "runtime_container_predicate",
        "Caller traced the original selected element/presence into this exact "
        "builtin container, observed this source predicate completing, and "
        "confirmed normal completion of the original entry body. "
        "The predicate consumes container presence, not a compatibility verdict.",
        node=record.predicate_span,
    )
    raise _Stop(ParameterState.HANDLED, "observed_container_predicate_consumption")


## Apply an observed normal return that retains the selected mapping key
## 应用保留所选映射键的正常返回观测
#
#  @param context Analysis context containing the source index
#  @param entry Entry function being assessed
#  @param call Caller observations for this assessment
#  @param change Parameter change under assessment
#  @param original Abstract value captured by the original parameter
#  @param proof Proof state receiving evidence or conservative failure
def _apply_normal_return_observation(
    context,
    entry,
    call,
    change,
    original,
    proof,
):
    if not call.observed_normal_returns:
        return
    transfer = observed_mapping_return(context, entry, call, change, original.literal)
    if transfer is None:
        proof.unknown(
            entry,
            "observed_normal_return_unconfirmed",
            "The normal-return observation and source retention fact disagree.",
        )
    proof.note(
        entry,
        "runtime_normal_return",
        "Caller observed normal completion of this original call with the same "
        "captured primitive. PCResolve proves that the selected key survives "
        "the update in the returned fresh mapping. Assumes standard builtin dict "
        "and no external frame introspection.",
        node=call.observed_normal_returns[0].return_span,
    )
    raise _Stop(ParameterState.HANDLED, "observed_mapping_return_consumption")


## Apply an observed keyword validation rejection
## 应用已观测到的关键字校验拒绝
#
#  @param context Analysis context containing the source index
#  @param entry Entry function being assessed
#  @param call Caller observations for this assessment
#  @param change Parameter change under assessment
#  @param original Abstract value captured by the original parameter
#  @param proof Proof state receiving evidence or conservative failure
def _apply_keyword_check_observation(
    context,
    entry,
    call,
    change,
    original,
    proof,
):
    if not call.observed_keyword_checks:
        return
    observation = observed_keyword_check(context, entry, call, change, original.literal)
    if observation is None:
        proof.unknown(
            entry,
            "observed_keyword_check_unconfirmed",
            "The checkpoint does not match this call and source guard.",
        )
    checker = context.index.find(observation.checker)
    if checker is None:
        proof.unknown(
            entry,
            "observed_keyword_check_unconfirmed",
            "The observed keyword checker is absent from the source index.",
        )
    proof.note(
        checker,
        "runtime_keyword_checkpoint",
        "Caller supplied an uncaught original-call trace: the entry and validator "
        "received the selected value, and attribute lookup returned None. "
        "This is runtime evidence, not static path or lookup confirmation.",
        node=observation.raise_span,
        target=observation.checker,
    )
    proof.reject(
        entry,
        "observed_keyword_validation_rejection",
        change.old_name + " reaches the observed source rejection guard.",
        target=observation.checker,
    )


## Parse a textual call expression into a source AST node.
## 将文本调用表达式解析为源码 AST 节点。
#
#  @param call Caller invocation context
#  @return Parsed call node, or None when the input is invalid
def _parse_call(call):
    if isinstance(call.expression, ast.Call):
        return call.expression
    try:
        node = ast.parse(call.expression, mode="eval").body
    except (SyntaxError, TypeError):
        return None
    if isinstance(node, ast.Await):
        node = node.value
    return node if isinstance(node, ast.Call) else None


## Resolve the owning class identity for a selected method entry.
## 解析所选方法入口所属的类身份。
#
#  @param context Analysis context used for source identity resolution
#  @param entry Resolved API entry
#  @return Class identity, or None when the owner is ambiguous
def _class_identity_for_method(context, entry):
    owner, separator, method = entry.identity.qualname.rpartition(".")
    if not separator or not owner or not entry.identity.file_path:
        return None
    indexed = [
        item
        for item in context.index.classes
        if item.module == entry.identity.module
        and item.qualname == owner
        and item.file_path == entry.identity.file_path
    ]
    if len(indexed) == 1:
        return indexed[0]
    try:
        with tokenize.open(entry.identity.file_path) as stream:
            tree = ast.parse(stream.read(), filename=str(entry.identity.file_path))
    except (OSError, SyntaxError, UnicodeError):
        return None
    matches = []

    ## Find the method's lexical class in nested source scopes
    ## 在嵌套源码作用域中查找方法所属的词法类
    #
    #  @param statements Source statements in the current scope
    #  @param scope Enclosing class and function names
    def visit(statements, scope=()):
        for statement in statements:
            if isinstance(statement, ast.ClassDef):
                qualname = ".".join((*scope, statement.name))
                if qualname == owner and any(
                    isinstance(member, (ast.FunctionDef, ast.AsyncFunctionDef))
                    and member.name == method
                    and member.lineno == entry.identity.lineno
                    for member in statement.body
                ):
                    matches.append(
                        FunctionIdentity(
                            entry.identity.module,
                            qualname,
                            entry.identity.file_path,
                            statement.lineno,
                        )
                    )
                visit(statement.body, (*scope, statement.name))
            elif isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
                visit(statement.body, (*scope, statement.name))

    visit(tree.body)
    return matches[0] if len(matches) == 1 else None


## Assess one parameter change at a caller-provided invocation.
## 评估调用方所给调用中的一项参数变更。
#
#  @param source Source path or source text to analyze
#  @param target_api API identity selected for assessment
#  @param change Parameter change being assessed
#  @param call Caller invocation text or parsed call context
#  @param import_roots Optional roots used to resolve project imports
#  @param max_depth Maximum nested source-call depth
#  @param context Reusable analysis context, when already prepared
#  @return Assessment result with evidence and analysis boundaries
def assess_change(
    source,
    target_api,
    change,
    call,
    *,
    import_roots=None,
    max_depth=5,
    context=None,
):
    _validate_depth(max_depth)
    call = call if isinstance(call, CallContext) else CallContext(call)
    node = _parse_call(call)
    text = ast.unparse(node) if node else str(call.expression)
    _, context = _prepare_context(source, import_roots, context)
    entry = None
    proof = None
    fallback_boundaries = []
    state, reason = ParameterState.UNKNOWN, "target_api_unavailable"
    try:
        if context is None:
            raise ResolutionError("No Python sources available.", "target_api_unavailable")
        proof = _Proof(context, max_depth, dict(call.known_targets), dict(call.known_conditions))
        entry = context.resolve_api(target_api)
        if entry is None or entry.is_overload:
            raise ResolutionError(
                "The API does not resolve to one source implementation.", "target_api_unavailable"
            )
        if node is not None:
            proxy_conditions = caller_contextvar_conditions(context, call, node, entry)
            for condition_span, fact in proxy_conditions.items():
                supplied = (
                    proof.condition_override(condition_span)
                    if proof.has_condition_override(condition_span)
                    else None
                )
                if supplied is not None and supplied is not False:
                    proof.unknown(
                        entry,
                        "conflicting_call_facts",
                        "A supplied condition conflicts with the source-backed unbound "
                        "ContextVar proxy fact.",
                        condition_span,
                    )
                proof.set_condition_override(condition_span, False)
                proof.note(entry, fact["reason"], fact["detail"], condition_span, fact["target"])
        if node is None:
            proof.unknown(
                entry, "callsite_not_resolved", "Supply an original call AST or expression."
            )

        # The client expression is not in the library AST. Only finite argument
        # syntax is read; calls/attributes in its argument values are never run.
        # 客户端表达式不属于库AST；这里只读取有限实参语法，不执行实参值中的调用或属性访问。
        frame = _Frame(proof, entry, None, {}, (), {}, context=context)
        positional, keywords = frame.arguments(node)
        context, entry = _apply_caller_facts(
            context, call, node, target_api, change, entry, proof, frame, positional, keywords
        )
        original, values = _bind_selected_argument(entry, change, call, proof, positional, keywords)
        _apply_observations(context, entry, call, change, original, proof)
        proof.run(entry, values, facts=call.known_values)
        handled_reason = proof.result_reason()
        state = ParameterState.HANDLED if handled_reason else ParameterState.IGNORED
        reason = handled_reason or "unused_parameter"
        if state is ParameterState.IGNORED:
            proof.note(
                entry, reason, "Supported executed paths do not use the value or argument presence."
            )
    except _Stop as outcome:
        state, reason = outcome.state, outcome.reason
    except ResolutionError as exc:
        if exc.code in {
            "constructor_analysis_failed",
            "pcresolve_fact_contract_unavailable",
            "entry_binding_facts_unavailable",
            "entry_callable_binding_unconfirmed",
            "constructor_entry_unconfirmed",
        }:
            reason = exc.code
        boundary = AnalysisBoundary(reason, str(exc), target_api)
        if proof is None:
            fallback_boundaries.append(boundary)
        else:
            proof.record_boundary(boundary)

    evidence, boundaries = proof.result_records() if proof is not None else ((), ())
    return ParameterAssessment(
        target_api,
        change,
        text,
        state,
        reason,
        evidence,
        boundaries + tuple(fallback_boundaries),
        entry.identity if entry else None,
        call.callsite,
    )
