## @package vppdetector.assess.calls
#  Call and source-target semantics for assessment frames.
#
#
#  Select receiver and builtin rules before source dispatch. Source calls are resolved, validated
#  and bound before their function body is followed.
#  先检查接收者和内置规则，再解析、校验和绑定源码调用，最后跟进其函数体。



import ast
import copy

from .._analysis_context import AnalysisContext
from .._records import FrozenRecord
from ..facts.adapter import ResolutionError
from ..facts.bindings import source_classmethod_binding
from ..facts.calls import call_span, direct_calls, identity_from_target
from ..facts.calls import target_status as _target_status
from ..facts.creation import source_constructor_binding
from .fresh import FreshMethod, FreshNonMethod, FreshReceiverState, _receiver_hierarchy
from .proofs._fresh_receiver import method_binding as fresh_method_binding
from .proofs._return_attribute_dispatch import returned_attribute_method
from .proofs._wrapper_forwarding import binding as wrapper_forwarding_binding
from .semantics.attributes import attribute_call
from .semantics.builtins import builtin_call
from .semantics.outcomes import NOT_APPLICABLE
from .values import (
    _UNKNOWN,
    _BoundSourceMethod,
    _CallerFile,
    _key_presence,
    _KeySet,
    _Keywords,
    _LocalFunction,
    _Positionals,
    _protected_state,
    _SourceClass,
    _tracked,
    _Value,
)


## Keep target-inference results and their selected context together.
## 将目标推断结果及其所选上下文组合保存。
class InferredTarget(FrozenRecord):
    _record_fields = ("facts", "inferred", "context")
    __match_args__ = ("facts", "inferred", "context")

    ## Store the call facts after bounded target inference.
    ## 保存有界目标推断后的调用事实。
    #
    #  @param facts Producer facts, updated only when inference succeeds
    #  @param inferred Whether the target came from bounded source inference
    #  @param context Context selected for the inferred target
    def __init__(self, facts, inferred, context):
        object.__setattr__(self, "facts", facts)
        object.__setattr__(self, "inferred", inferred)
        object.__setattr__(self, "context", context)


## Represent a resolved call target and the binding facts needed to follow it.
## 表示已解析的调用目标及继续跟踪所需的绑定事实。
class SourceTarget(FrozenRecord):
    _record_fields = (
        "target",
        "exact_keyword_forwarding",
        "instance",
        "instance_parameter",
        "fresh_method",
    )
    __match_args__ = (
        "target",
        "exact_keyword_forwarding",
        "instance",
        "instance_parameter",
        "fresh_method",
    )

    ## Store the successfully resolved source-call contract.
    ## 保存已成功解析的源码调用契约。
    #
    #  @param target Indexed source function selected for the call
    #  @param exact_keyword_forwarding Whether exact keyword-carrier forwarding is proven
    #  @param instance Bound callable instance, when validated
    #  @param instance_parameter Name of its implicit parameter, when validated
    #  @param fresh_method Validated fresh-method binding, when present
    def __init__(
        self, target, exact_keyword_forwarding, instance, instance_parameter, fresh_method
    ):
        object.__setattr__(self, "target", target)
        object.__setattr__(self, "exact_keyword_forwarding", exact_keyword_forwarding)
        object.__setattr__(self, "instance", instance)
        object.__setattr__(self, "instance_parameter", instance_parameter)
        object.__setattr__(self, "fresh_method", fresh_method)


## Interpret calls and resolve source-backed call targets for an assessment frame.
## 为评估帧解释调用并解析有源码依据的调用目标。
class CallOperations:
    ## Locate producer facts matching one exact call expression.
    ## 查找与单个调用表达式精确匹配的生产者事实。
    #
    #  @param node Call AST node being interpreted
    #  @return Matching call facts or None when no exact location is indexed
    def _caller_call_facts(self, node):
        return next(
            (
                call
                for call in direct_calls(self.analysis, self.function.identity)
                if (call.lineno, call.col_offset, call.end_lineno, call.end_col_offset)
                == (node.lineno, node.col_offset, node.end_lineno, node.end_col_offset)
            ),
            None,
        )

    ## Dispatch one call through bounded local and source-backed models.
    ## 通过有界局部模型和源码模型分派单个调用。
    #
    #  @param node Call expression to interpret
    #  @return Abstract result or a conservative analysis stop
    def _call(self, node):
        if self.analysis is None:
            # Client expressions are opaque: no user code, including nested
            # argument calls, is executed or attributed to the library source.
            # 客户端表达式视为不透明语法，不执行其中任何用户代码，
            # 也不把它归到库源码中。
            return _Value()
        result = self._caller_file_read(node)
        if result is not NOT_APPLICABLE:
            return result
        facts = self._caller_call_facts(node)
        result = self._source_class_call(node)
        if result is not NOT_APPLICABLE:
            return result

        # A returned attribute can supply a new source target and its associated context.
        # 返回值上的属性可以提供新的源码目标及其分析上下文。
        inferred = self._infer_returned_attribute_target(node, facts)
        facts = inferred.facts
        inferred_source_target = inferred.inferred
        inferred_context = inferred.context
        result = self._source_iterability(node, facts)
        if result is not NOT_APPLICABLE:
            return result
        result = self._bound_method_call(node)
        if result is not NOT_APPLICABLE:
            return result
        result = self._fresh_getattr_call(node, facts)
        if result is not NOT_APPLICABLE:
            return result
        if isinstance(node.func, ast.Attribute):
            attribute_result = attribute_call(self, node, facts)
            if attribute_result is not NOT_APPLICABLE:
                return attribute_result
        if (
            isinstance(node.func, ast.Name)
            and node.func.id == "isinstance"
            and node.func.id not in self.values
            and len(node.args) == 2
            and not node.keywords
            and facts
            and facts.target is None
            and facts.target_status == "builtin_boundary"
            and self.unshadowed_builtin_name("isinstance")
        ):
            return self.instance_guard(node)
        if self.related(node.func) and not inferred_source_target:
            self.unknown("call_target_unproven", node)

        # Keep evaluated arguments visible to nested calls during dispatch.
        # 分派期间保留已求值的实参，供嵌套调用查询。
        positional, keywords = self.arguments(node)
        self.pending_values[-1] = positional + list(keywords.values())
        builtin_result = builtin_call(self, node, facts, positional, keywords)
        if builtin_result is not NOT_APPLICABLE:
            return builtin_result

        return self._source_call(
            node, facts, positional, keywords, inferred_source_target, inferred_context
        )

    ## Model one bounded read from the caller-provided source file.
    ## 建模一次对调用方提供源码文件的有界读取。
    #
    #  @param node Call expression being interpreted
    #  @return Abstract file content, or NOT_APPLICABLE
    def _caller_file_read(self, node):
        if (
            isinstance(node.func, ast.Attribute)
            and node.func.attr == "read"
            and not node.args
            and not node.keywords
        ):
            receiver = self.expression(node.func.value)
            if isinstance(receiver, _CallerFile):
                if receiver.read_count:
                    return _Value("", source_state=True)
                receiver.read_count += 1
                self.proof.note(
                    self.function,
                    "source_caller_file_read",
                    "The exact caller binds this parameter to a bounded text file opened "
                    "from its execution directory; the file content hash is "
                    + receiver.sha256
                    + ".",
                    node,
                )
                return _Value(receiver.text, source_state=True)
        return NOT_APPLICABLE

    ## Bind a source-backed class constructor call.
    ## 绑定有源码依据的类构造调用。
    #
    #  @param node Call expression being interpreted
    #  @return Abstract result, or NOT_APPLICABLE
    def _source_class_call(self, node):
        if isinstance(node.func, ast.Name):
            callee = self.values.get(node.func.id)
            if isinstance(callee, _SourceClass):
                positional, keywords = self.arguments(node)
                target = callee.constructor
                self.proof.bind(target, positional, keywords, True, node, caller=self.function)
                self.proof.note(
                    self.function,
                    "source_imported_class_constructor_binding",
                    "The imported source class resolves to one plain class constructor; "
                    "its exact signature is used for argument binding.",
                    node,
                    target.identity,
                )
                return _Value()
        return NOT_APPLICABLE

    ## Infer a method target returned through a supported attribute path.
    ## 推断经受支持属性路径返回的方法目标。
    #
    #  @param node Call expression being interpreted
    #  @param facts Producer facts for the call, when available
    #  @return Updated inference facts and selected source context
    def _infer_returned_attribute_target(self, node, facts):
        inferred_source_target = False
        inferred_context = self.context
        if (
            facts is not None
            and facts.target is None
            and facts.target_status == "receiver_unresolved"
            and self.analysis is not None
        ):
            inferred = returned_attribute_method(
                self.context.index, self.function, self.analysis, node
            )
            if inferred is not None:
                try:
                    inferred_context = self.context
                    if inferred_context.index.find(inferred) is None:
                        inferred_context = self.context.assessment_contexts.dispatch(
                            inferred,
                            lambda: AnalysisContext.for_api(
                                self.context.index.source, inferred
                            ),
                        )
                    inferred_entry = inferred_context.resolve_api(inferred)
                except (ResolutionError, OSError, ValueError, TypeError):
                    inferred_entry = None
                if inferred_entry is not None:
                    facts = copy.deepcopy(facts)
                    facts.target = inferred
                    facts.target_status = "resolved"
                    facts.binding_status = "complete"
                    facts.binding_issues = []
                    facts.parameter_bindings = []
                    inferred_source_target = True
                    self.proof.note(
                        self.function,
                        "source_return_attribute_dispatch",
                        "PCResolve binds this receiver to a source helper; every returned "
                        "attribute is statically typed through its owner contract and resolves "
                        "to the same source method implementation.",
                        node,
                        inferred,
                    )
        return InferredTarget(facts, inferred_source_target, inferred_context)

    ## Resolve iteration through a source-backed call result.
    ## 解析经有源码依据的调用结果进行的迭代。
    #
    #  @param node Call expression being interpreted
    #  @param facts Producer facts for the call, when available
    #  @return Abstract iteration result, or NOT_APPLICABLE
    def _source_iterability(self, node, facts):
        iterability_predicate = None
        if facts is not None and facts.target is None:
            iterability_predicate = self.context.adapter.source_call_protocol(
                self.function, node
            )
        if (
            iterability_predicate is not None
            and len(node.args) == 1
            and not node.keywords
            and not isinstance(node.args[0], ast.Starred)
        ):
            value = self.expression(node.args[0])
            if isinstance(value, _Value) and value.iterable is not None:
                self.proof.note(
                    self.function,
                    "source_iterability_predicate",
                    "PCResolve proves this exact call uses a source-defined iterability "
                    "predicate, and the caller argument has a bounded return protocol "
                    "proving its iteration behavior without executing the expression.",
                    node,
                    identity_from_target(facts.target) if facts is not None else None,
                )
                return _Value(value.iterable, _tracked(value), _key_presence(value), consumed=True)
        return NOT_APPLICABLE

    ## Follow a method whose receiver binding is already established.
    ## 跟踪接收者绑定已确定的方法调用。
    #
    #  @param node Call expression being interpreted
    #  @return Abstract result, or NOT_APPLICABLE
    def _bound_method_call(self, node):
        if isinstance(node.func, ast.Name):
            local_method = self.values.get(node.func.id)
            if isinstance(local_method, _BoundSourceMethod):
                target = self.context.index.find(local_method.target)
                if target is None or target.is_overload or target.node.decorator_list:
                    self.unknown("call_target_unproven", node)
                positional, keywords = self.arguments(node)
                try:
                    target_analysis = self.context.adapter.analyze(target.identity)
                except ResolutionError as exc:
                    self.unknown(exc.code, node)
                values = self.proof.bind(
                    target, positional, keywords, True, node, caller=self.function
                )
                self.proof.note(
                    self.function,
                    "fresh_source_setter_binding",
                    "The selected fresh-instance attribute is one plain source "
                    "setter, bound without its implicit receiver.",
                    node,
                    target.identity,
                )
                receiver = FreshReceiverState(
                    True,
                    local_method.decorated_members,
                    local_method.own_attributes,
                    local_method.receiver_class,
                    local_method.hierarchy,
                    local_method.allocation,
                )
                return self.proof.run(
                    target,
                    values,
                    analysis=target_analysis,
                    ancestry=self.ancestry,
                    receiver=receiver,
                )
        return NOT_APPLICABLE

    ## Resolve getattr on a receiver proven fresh on this path.
    ## 解析当前路径上已证明为新建对象的接收者上的 getattr。
    #
    #  @param node Call expression being interpreted
    #  @param facts Producer facts for the call, when available
    #  @return Abstract result, or NOT_APPLICABLE
    def _fresh_getattr_call(self, node, facts):
        if (
            isinstance(node.func, ast.Name)
            and node.func.id == "getattr"
            and self.unshadowed_builtin_name("getattr")
            and facts is not None
            and facts.target is None
            and facts.target_status == "builtin_boundary"
            and len(node.args) == 3
            and not node.keywords
            and isinstance(node.args[0], ast.Name)
            and node.args[0].id == "self"
        ):
            name_value = self.expression(node.args[1])
            default = self.expression(node.args[2])
            if not isinstance(name_value, _Value) or type(name_value.literal) is not str:
                self.unknown("dynamic_attribute_lookup_unproven", node)
            lookup = self.fresh_lookup(name_value.literal)
            if lookup is None:
                self.unknown("dynamic_attribute_lookup_unproven", node)
            if isinstance(lookup, FreshNonMethod) and lookup.kind == "missing":
                self.proof.note(
                    self.function,
                    "fresh_source_missing_member",
                    "The fresh receiver MRO and own-attribute facts contain no "
                    + name_value.literal
                    + ".",
                    node,
                )
                return _Value(
                    default.literal if isinstance(default, _Value) else _UNKNOWN,
                    _tracked(name_value),
                    _key_presence(name_value),
                )
            if isinstance(lookup, FreshMethod):
                return _BoundSourceMethod(
                    lookup.target,
                    _tracked(name_value),
                    _key_presence(name_value),
                    lookup.receiver.exclusions,
                    lookup.receiver.own_attributes,
                    lookup.receiver.receiver_class,
                    lookup.receiver.hierarchy,
                    lookup.receiver.allocation,
                )
            self.unknown("dynamic_attribute_lookup_unproven", node)
        return NOT_APPLICABLE

    ## Resolve and execute a supported source call after builtin rules decline it.
    ## 在内置规则不适用后解析并执行受支持的源码调用。
    #
    #  @param node AST call being interpreted.
    #  @param facts Producer call facts when available.
    #  @param positional Abstract positional argument values.
    #  @param keywords Abstract keyword argument values.
    #  @param inferred_source_target Whether the source target came from bounded inference.
    #  @param inferred_context Analysis context for the inferred target.
    #  @return Abstract call result, including an empty value for an unrelated call.
    #  @exception _Stop If an effect, binding or source body is unproved.
    def _source_call(
        self,
        node,
        facts,
        positional,
        keywords,
        inferred_source_target,
        inferred_context,
    ):
        arguments = [({"position": position}, item) for position, item in enumerate(positional)]
        arguments.extend(({"keyword": name}, item) for name, item in keywords.items())
        ordinary = [
            (argument, item)
            for argument, item in arguments
            if isinstance(item, (_Keywords, _Positionals, _KeySet)) and _tracked(item)
        ]
        local = self.values.get(node.func.id) if isinstance(node.func, ast.Name) else None
        captured = bool(
            isinstance(local, _LocalFunction)
            or facts
            and any(
                source.get("source") is not None
                and source.get("source")
                in {self.function.signature.kwarg, self.function.signature.vararg}
                for binding in facts.capture_bindings
                for source in binding.get("sources", ())
            )
        )
        if (
            not ordinary
            and not any(_tracked(item) for item in positional + list(keywords.values()))
            and not captured
        ):
            if any(_protected_state(item) for item in positional + list(keywords.values())):
                self.unknown("callable_instance_state_effects_unproven", node)
            return _Value()
        confirmed = self.proof.target_for_call(call_span(facts)) if facts else None
        if facts and facts.target is None and confirmed is not None:
            target = self.context.index.find(confirmed)
            if target is None or target.is_overload or target.node.decorator_list:
                self.unknown("conflicting_target_fact", node)
            self.proof.note(
                self.function,
                "confirmed_call_target",
                "Caller supplied this unresolved call target for signature rejection "
                "only; body binding and effects remain unproved.",
                node,
                target.identity,
            )
            self.proof.bind(
                target, positional, keywords, target.is_bound_method, node, caller=self.function
            )
            self.unknown("confirmed_target_body_unproven", node)
        if not facts or not facts.target or captured and not isinstance(local, _LocalFunction):
            self.unknown("call_target_unproven", node)

        return self._follow_source_call(
            node,
            facts,
            positional,
            keywords,
            inferred_source_target,
            inferred_context,
            local,
            ordinary,
            captured,
        )

    ## Bind and interpret a call with a resolved source target.
    ## 绑定并解释已解析源码目标的调用。
    #
    #  @param node Call expression being interpreted
    #  @param facts Producer facts for the call
    #  @param positional Abstract positional arguments
    #  @param keywords Abstract keyword arguments
    #  @param inferred_source_target Whether bounded target inference succeeded
    #  @param inferred_context Source context selected by target inference
    #  @param local Local function state relevant to the call
    #  @param ordinary Tracked ordinary container arguments
    #  @param captured Whether the call forwards captured values
    #  @return Abstract call result
    #  @exception _Stop If target validation or argument binding stops interpretation
    def _follow_source_call(
        self,
        node,
        facts,
        positional,
        keywords,
        inferred_source_target,
        inferred_context,
        local,
        ordinary,
        captured,
    ):
        resolved = self._source_target(
            node, facts, positional, inferred_source_target, inferred_context
        )
        values = self._bind_source_call(
            node,
            facts,
            positional,
            keywords,
            local,
            ordinary,
            captured,
            resolved,
            inferred_source_target,
        )
        return self._run_source_target(
            node,
            facts,
            resolved,
            values,
            inferred_source_target,
            inferred_context,
            ordinary,
            captured,
        )

    ## Follow a source target after binding and evidence checks succeed.
    ## 绑定和证据校验成功后跟进源码目标。
    #
    #  @param node Call expression being interpreted
    #  @param facts Producer facts for the call
    #  @param resolved Validated target and receiver evidence
    #  @param values Abstract parameter values bound to the target
    #  @param inferred_source_target Whether bounded target inference succeeded
    #  @param inferred_context Analysis context selected by target inference
    #  @param ordinary Tracked ordinary container arguments
    #  @param captured Whether the call forwards captured values
    #  @return Abstract call result or a conservative stop
    def _run_source_target(
        self,
        node,
        facts,
        resolved,
        values,
        inferred_source_target,
        inferred_context,
        ordinary,
        captured,
    ):
        analysis = self.analysis
        assert analysis is not None, "source target follow requires a resolved analysis"
        target = resolved.target
        fresh_method = resolved.fresh_method
        captured_keywords = values.get(target.signature.kwarg) if target.signature.kwarg else None
        captured_positionals = (
            values.get(target.signature.vararg) if target.signature.vararg else None
        )

        # Follow the target body only when it receives tracked values or captures.
        # 仅当目标接收被跟踪的值或存在捕获时跟进函数体。
        if captured or ordinary or _tracked(captured_keywords) or _tracked(captured_positionals):
            self.proof.note(
                self.function,
                "immediate_capture_forwarding"
                if captured
                else "ordinary_container_forwarding"
                if ordinary
                else (
                    "forwarded_positional"
                    if _tracked(captured_positionals)
                    else "forwarded_keyword"
                ),
                ast.unparse(node),
                node,
                target.identity,
            )
            try:
                expanded = (
                    inferred_context.adapter.analyze(target.identity)
                    if inferred_source_target
                    else self.context.adapter.expand(
                        self.analysis, facts.id, isolate=True, preserve_lineage=True
                    )
                )
            except ResolutionError as exc:
                self.proof.unknown(self.function, "flow_expansion_failed", str(exc), node)
            context = inferred_context if inferred_source_target else None
            if fresh_method is None:
                result = self.proof.run(
                    target,
                    values,
                    analysis=expanded,
                    ancestry=self.ancestry,
                    analysis_context=context,
                )
            else:
                receiver = FreshReceiverState(
                    True,
                    frozenset(),
                    fresh_method.own_attributes,
                    fresh_method.receiver_class,
                    _receiver_hierarchy(
                        analysis.inputs.get("entry_binding", {}).get("hierarchy", ())
                    ),
                    fresh_method.allocation_effects,
                )
                result = self.proof.run(
                    target,
                    values,
                    analysis=expanded,
                    ancestry=self.ancestry,
                    analysis_context=context,
                    receiver=receiver,
                )
            if captured:
                return result
        else:
            self.proof.handled(
                self.function,
                "accepted_binding",
                "Changed value binds an explicit parameter.",
                node,
                target.identity,
            )
        return _Value()

    ## Bind arguments and captured values to a validated source target.
    ## 将实参及捕获值绑定到已验证的源码目标。
    #
    #  @param node Call expression being interpreted
    #  @param facts Producer facts for the call
    #  @param positional Abstract positional arguments
    #  @param keywords Abstract keyword arguments
    #  @param local Local function state relevant to captures
    #  @param ordinary Tracked ordinary container arguments
    #  @param captured Whether the call forwards captured values
    #  @param resolved Validated source target and binding evidence
    #  @param inferred_source_target Whether bounded target inference succeeded
    #  @return Parameter values bound to the target
    def _bind_source_call(
        self,
        node,
        facts,
        positional,
        keywords,
        local,
        ordinary,
        captured,
        resolved,
        inferred_source_target,
    ):
        target = resolved.target
        captures = self.capture_values(target, facts, local, node) if captured else {}
        if (
            ordinary
            and not inferred_source_target
            and (
                facts.binding_status != "complete"
                or facts.binding_issues
                or any(
                    not any(
                        binding.get("argument") == argument
                        and binding.get("status") == "exact"
                        and binding.get("destination_kind") == "parameter"
                        for binding in facts.parameter_bindings
                    )
                    for argument, _ in ordinary
                )
            )
            and not resolved.exact_keyword_forwarding
        ):
            self.unknown("ordinary_container_binding_unproven", node)
        if resolved.exact_keyword_forwarding:
            self.proof.note(
                self.function,
                "exact_variadic_keyword_forwarding",
                f"PCResolve proves the exact source **{self.function.signature.kwarg} mapping "
                f"is forwarded into {target.identity.qualname}'s **{target.signature.kwarg}.",
                node,
                target.identity,
            )

        values = self.proof.bind(
            target, positional, keywords, target.is_bound_method, node, caller=self.function
        )
        values.update(captures)
        if resolved.instance is not None:
            assert resolved.instance_parameter is not None
            values[resolved.instance_parameter] = resolved.instance
        return values

    ## Resolve a source target only after discharging binding and effect obligations.
    ## 在确认绑定及效果义务后解析源码调用目标。
    #
    #  @param node AST call whose target is being resolved.
    #  @param facts Producer facts for the call.
    #  @param positional Abstract positional argument values.
    #  @param inferred_source_target Whether the source target came from bounded inference.
    #  @param inferred_context Analysis context for the inferred target.
    #  @return Validated SourceTarget carrying the function and receiver binding evidence.
    def _source_target(
        self,
        node,
        facts,
        positional,
        inferred_source_target,
        inferred_context,
    ):
        analysis = self.analysis
        assert analysis is not None, "source target resolution requires analysis"
        status = _target_status(analysis, facts)
        binding_target = self.context.index.find(identity_from_target(facts.target))
        exact_keyword_forwarding = (
            binding_target is not None
            and _exact_keyword_container_forwarding(node, self.function, binding_target, facts)
        )
        confirmed = self.proof.target_for_call(call_span(facts))
        if confirmed is not None:
            confirmed_definition = self.context.index.find(confirmed)
            if (
                confirmed_definition is None
                or confirmed_definition.identity != identity_from_target(facts.target)
            ):
                self.unknown("conflicting_target_fact", node)
            self.proof.note(
                self.function,
                "confirmed_call_target",
                "Caller supplied this call's source implementation.",
                node,
                confirmed,
            )
        instance = None
        instance_parameter = None
        instance_binding = getattr(facts, "callable_instance_evidence", {}).get("binding", {})
        if status == "callable_instance_candidate":
            instance = self.source_callable_binding(facts, instance_binding)
            if instance is not None:
                instance_parameter = instance_binding["implicit_binding"]["parameter"]
                self.proof.note(
                    self.function,
                    "source_callable_instance_binding",
                    "; ".join(instance_binding["assumptions"]),
                    node,
                    identity_from_target(facts.target),
                )
        source_binding = (
            source_classmethod_binding(self.analysis, facts) if self.analysis is not None else None
        )
        if source_binding is not None:
            # Source-snapshot binding is conditional evidence, not a runtime observation.
            # 源码快照中的绑定属于条件性静态证据，不是运行时观测。
            self.proof.note(
                self.function,
                "source_classmethod_binding",
                "; ".join(source_binding.get("assumptions", ())),
                node,
                identity_from_target(facts.target),
            )
        fresh_method = (
            fresh_method_binding(self.analysis, facts, self.context.index)
            if self.analysis is not None
            else None
        )
        if fresh_method is not None:
            self.proof.note(
                self.function,
                "fresh_source_instance_method",
                "; ".join(fresh_method.assumptions),
                node,
                identity_from_target(facts.target),
            )
        constructor = (
            source_constructor_binding(self.analysis, facts) if self.analysis is not None else None
        )
        if (
            constructor is not None
            and constructor["phase"] == "__init__"
            and constructor["body_execution"] == "synchronous"
        ):
            self.proof.note(
                self.function,
                "source_initializer_binding",
                "PCResolve confirms this initializer invocation only; returned instance "
                "state remains unmodeled. " + "; ".join(constructor["assumptions"]),
                node,
                identity_from_target(facts.target),
            )
        self._validate_call_target(
            node,
            facts,
            status,
            confirmed,
            exact_keyword_forwarding,
            instance,
            fresh_method,
            source_binding,
            constructor,
        )

        return self._resolve_target_definition(
            node,
            facts,
            positional,
            inferred_source_target,
            inferred_context,
            exact_keyword_forwarding,
            instance,
            instance_parameter,
            fresh_method,
        )

    ## Reject call targets whose dispatch evidence leaves dynamic behavior unresolved.
    ## 拒绝分派证据仍无法排除动态行为的调用目标。
    #
    #  @param node Call expression being interpreted
    #  @param facts Producer facts for the call
    #  @param status Producer target-resolution status
    #  @param confirmed Caller-supplied source target, when present
    #  @param exact_keyword_forwarding Whether exact keyword forwarding is proven
    #  @param instance Validated callable instance binding, when present
    #  @param fresh_method Validated fresh-method binding, when present
    #  @param source_binding Validated source classmethod binding, when present
    #  @param constructor Validated source constructor binding, when present
    #  @return None, or a conservative analysis stop
    def _validate_call_target(
        self,
        node,
        facts,
        status,
        confirmed,
        exact_keyword_forwarding,
        instance,
        fresh_method,
        source_binding,
        constructor,
    ):
        analysis = self.analysis
        assert analysis is not None, "call target validation requires analysis"
        reasons = {
            boundary.get("reason")
            for boundary in analysis.boundaries
            if boundary.get("call_id") == facts.id
        }

        # Discharge only the dynamic effects covered by independent binding evidence.
        # 仅消除有独立绑定证据支持的动态分析边界。
        dynamic = {reason for reason in reasons if reason and reason.startswith("dynamic_")}
        dynamic.discard("dynamic_argument_expansion")
        if instance is not None:
            dynamic.discard("dynamic_callable_instance_override_possible")
        if source_binding:
            dynamic.discard("dynamic_class_receiver_override_possible")
        if fresh_method is not None:
            dynamic.discard("dynamic_method_override_possible")
        if (
            constructor is not None
            and constructor["phase"] == "__init__"
            and constructor["body_execution"] == "synchronous"
        ):
            dynamic.discard("dynamic_construction")
        if confirmed is not None:
            # A method observation resolves this target only, not decorator
            # effects, metaclass construction, binding or later body behavior.
            # 方法观测只解析该目标，不证明装饰器副作用、元类构造、绑定方式或后续函数体行为。
            dynamic.discard("dynamic_class_receiver_override_possible")
        if (
            status not in {"resolved", "constructor", "staticmethod", "classmethod", "super_method"}
            and instance is None
            and fresh_method is None
            and not exact_keyword_forwarding
        ) or dynamic:
            reason = sorted(dynamic)[0] if dynamic else "call_target_unproven"
            self.unknown(reason, node)
        if status == "classmethod" and confirmed is None and not source_binding:
            self.unknown("class_receiver_unconfirmed", node)

    ## Resolve the source definition and binding state selected for a call.
    ## 解析调用所选的源码定义及绑定状态。
    #
    #  @param node Call expression being interpreted
    #  @param facts Producer facts for the call
    #  @param positional Abstract positional arguments
    #  @param inferred_source_target Whether bounded target inference succeeded
    #  @param inferred_context Source context selected by target inference
    #  @param exact_keyword_forwarding Whether exact keyword forwarding is proven
    #  @param instance Bound callable instance, when available
    #  @param instance_parameter Name of the receiver parameter, when available
    #  @param fresh_method Validated fresh-method binding, when available
    #  @return Resolved target definition and binding details
    def _resolve_target_definition(
        self,
        node,
        facts,
        positional,
        inferred_source_target,
        inferred_context,
        exact_keyword_forwarding,
        instance,
        instance_parameter,
        fresh_method,
    ):
        analysis = self.analysis
        assert analysis is not None, "target definition resolution requires analysis"
        target_index = (
            inferred_context.index if inferred_source_target else self.context.index
        )
        target = target_index.find(identity_from_target(facts.target))
        if target is None:
            self.unknown("call_target_unavailable", node)
        effect_boundaries = {
            boundary.get("reason")
            for boundary in analysis.boundaries
            if boundary.get("call_id") == facts.id
        } & {"identity_decorator_effects_unmodeled", "dynamic_dispatch", "dynamic_callable_binding"}
        if "identity_decorator_effects_unmodeled" in effect_boundaries:
            try:
                wrapped = self.context.adapter.analyze(target.identity)
            except ResolutionError:
                wrapped = None
            if wrapped is not None:
                positional_count = len(positional) + int(bool(target.is_bound_method))
                factory_forwarding = wrapper_forwarding_binding(
                    self.context.index, wrapped, target, positional_count
                )
                if factory_forwarding is not None:
                    self.proof.note(
                        self.function,
                        "source_wrapper_argument_forwarding",
                        "; ".join(factory_forwarding.get("assumptions", ())),
                        node,
                        target.identity,
                    )
                    effect_boundaries.discard("identity_decorator_effects_unmodeled")
        if effect_boundaries:
            self.unknown("callee_effects_unmodeled", node)

        return SourceTarget(
            target, exact_keyword_forwarding, instance, instance_parameter, fresh_method
        )


## Confirm exact forwarding of one caller keyword container to a callee.
## 确认调用方关键字容器被原样转发给被调用方。
#
#  @param node Call expression being checked
#  @param caller Source function containing the call
#  @param target Resolved downstream function
#  @param facts Producer call facts
#  @return Whether the source mapping is forwarded exactly to the target mapping
def _exact_keyword_container_forwarding(node, caller, target, facts):
    source_name = caller.signature.kwarg
    target_name = target.signature.kwarg
    if not source_name or not target_name:
        return False
    expansions = [keyword for keyword in node.keywords if keyword.arg is None]
    if (
        len(expansions) != 1
        or not isinstance(expansions[0].value, ast.Name)
        or expansions[0].value.id != source_name
    ):
        return False
    if any(issue.get("kind") != "dynamic_expansion" for issue in facts.binding_issues):
        return False
    bindings = [
        binding
        for binding in facts.parameter_bindings
        if binding.get("argument") == {"keyword": None}
    ]
    if (
        len(bindings) != 1
        or bindings[0].get("status") != "unresolved"
        or bindings[0].get("binding_kind") != "dynamic_keyword"
    ):
        return False
    sources = [
        argument
        for argument in facts.argument_sources
        if argument.get("argument") == {"keyword": None}
    ]
    if len(sources) != 1 or len(sources[0].get("sources", ())) != 1:
        return False
    source = sources[0]["sources"][0]
    container = sources[0].get("container_binding", {})
    if (
        source.get("kind") != "parameter"
        or source.get("source") != source_name
        or source.get("relation") != "contained"
        or source.get("output_path") != ["*"]
        or container.get("status") != "exact"
        or container.get("shape") != "dict"
        or container.get("contents_unknown") is not False
    ):
        return False
    flows = [flow for flow in facts.parameter_flows if flow.get("argument") == {"keyword": None}]
    return (
        len(flows) == 1
        and flows[0].get("kind") == "parameter"
        and flows[0].get("source") == source_name
        and flows[0].get("relation") == "contained"
        and flows[0].get("output_path") == ["*"]
        and flows[0].get("status") == "flow_found"
    )
