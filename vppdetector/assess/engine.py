## @package vppdetector.assess.engine
#  Assess one changed variadic argument under source-backed call conditions.
#
#
#  Track evidence across bounded calls and isolate speculative branch state. Model finite call
#  binding, guards and container operations. Unsupported effects stop the proof with an explicit
#  boundary.
#  在有界调用间跟踪证据并隔离推测分支，建模有限调用绑定、守卫和容器操作。
#  遇到未建模效果时记录边界并结束证明。



import copy
from contextlib import contextmanager

from .._records import FACTORY_DEFAULT, FrozenRecord, MutableRecord
from ..facts.adapter import ResolutionError
from ..facts.calls import identity_from_target
from ..facts.scope import immediate_body
from ..models import (
    AnalysisBoundary,
    ParameterEvidence,
    ParameterState,
    SourceSpan,
)
from .binding import _Stop
from .binding import bind as bind_arguments
from .frame import _Frame
from .fresh import NO_FRESH_RECEIVER, FreshReceiverState, _receiver_hierarchy
from .proofs._fresh_member_checks import key_condition_applies as fresh_member_key_applies
from .proofs._fresh_member_checks import member_checks as fresh_member_checks
from .proofs._fresh_receiver import method_binding as fresh_method_binding
from .proofs._mapping_key_access import closed_keys as closed_mapping_keys
from .proofs.decorators import decoration_preserved as _decoration_preserved
from .values import (
    _Keywords,
    _tracked,
    _Value,
)


## Detect source uses that can expose a class object to arbitrary code
## 检测源码是否可能将类对象暴露给未建模代码
#
#  @param source_queries Source queries bound to the selected source snapshot
#  @param class_identity Identity of the source class
#  @return Whether available source syntax shows a potentially escaping class reference
def _class_binding_may_escape(source_queries, class_identity):
    return bool(
        class_identity and source_queries.class_binding_may_escape(class_identity)
    )


## Prepared producer analysis and receiver facts for one interpreter frame.
## 单个解释帧已准备的生产者分析及接收者事实。
class _PreparedRun(FrozenRecord):
    _record_fields = ("analysis", "receiver")
    __match_args__ = _record_fields

    ## Store the prepared producer analysis and receiver facts for a frame.
    ## 保存解释帧已准备的生产者分析和接收者事实。
    #
    #  @param analysis Producer facts for the function
    #  @param receiver Verified fresh-receiver state
    def __init__(self, analysis, receiver):
        object.__setattr__(self, "analysis", analysis)
        object.__setattr__(self, "receiver", receiver)


## Record handling evidence and analysis boundaries for one changed argument.
## 记录单个变更实参的处理证据及分析边界。
class _Proof(MutableRecord):
    _record_fields = (
        "context",
        "max_depth",
        "known_targets",
        "known_conditions",
        "evidence",
        "boundaries",
        "handled_reason",
        "consumption_witness",
        "frames",
        "unrelated_unpack_continuation",
        "consumed_values",
    )
    _record_repr_fields = tuple(
        name for name in _record_fields if name not in {"frames", "consumed_values"}
    )
    __match_args__ = _record_fields

    ## Initialize proof state shared by the active assessment path.
    ## 初始化当前评估路径共享的证明状态。
    #
    #  @param context Analysis context owning source and producer facts
    #  @param max_depth Maximum nested source-call depth
    #  @param known_targets Caller-provided known source targets
    #  @param known_conditions Caller-provided known branch conditions
    #  @param evidence Initial evidence records
    #  @param boundaries Initial analysis boundaries
    #  @param handled_reason Existing terminal handled reason
    #  @param consumption_witness Existing consumption witness
    #  @param frames Active interpretation frames
    #  @param unrelated_unpack_continuation Whether an unrelated unpack continues
    #  @param consumed_values Values already proven consumed on this path
    def __init__(
        self,
        context,
        max_depth,
        known_targets=FACTORY_DEFAULT,
        known_conditions=FACTORY_DEFAULT,
        evidence=FACTORY_DEFAULT,
        boundaries=FACTORY_DEFAULT,
        handled_reason=None,
        consumption_witness=None,
        frames=FACTORY_DEFAULT,
        unrelated_unpack_continuation=False,
        consumed_values=FACTORY_DEFAULT,
    ):
        self.context = context
        self.max_depth = max_depth
        self.known_targets = {} if known_targets is FACTORY_DEFAULT else known_targets
        self.known_conditions = {} if known_conditions is FACTORY_DEFAULT else known_conditions
        self.evidence = [] if evidence is FACTORY_DEFAULT else evidence
        self.boundaries = [] if boundaries is FACTORY_DEFAULT else boundaries
        self.handled_reason = handled_reason
        self.consumption_witness = consumption_witness
        self.frames = [] if frames is FACTORY_DEFAULT else frames
        self.unrelated_unpack_continuation = unrelated_unpack_continuation
        self.consumed_values = [] if consumed_values is FACTORY_DEFAULT else consumed_values

    ## Fork proof bookkeeping while retaining shared context and active frame identities.
    ## 复制证明记录，同时共享上下文和当前活动帧的身份。
    #
    #  @param memo Optional deepcopy memo shared with the active frame snapshot
    #  @return Proof with independent mutable collections for a speculative branch
    def fork(self, memo=None):
        # Evidence and frame objects retain their identities; only their lists are isolated.
        # consumed_values may contain nested mutable abstract values and is copied as a graph.
        # 证据和帧对象保留身份，仅复制列表。已消费值可含嵌套可变对象，按对象图复制。
        proof = copy.copy(self)
        proof.known_targets = dict(self.known_targets)
        proof.known_conditions = dict(self.known_conditions)
        proof.evidence = list(self.evidence)
        proof.boundaries = list(self.boundaries)
        proof.frames = list(self.frames)
        proof.consumed_values = copy.deepcopy(self.consumed_values, memo)
        return proof

    ## Fork proof state and the active frames needed for one speculative branch
    ## 为单个推测分支复制证明状态及所需的活动帧
    #
    #  @param current Current frame entering the speculative branch
    #  @return Isolated proof and the branch-local current frame
    def fork_for_branch(self, current):
        memo = {}
        proof = self.fork(memo)
        replacements = {}

        # Fork the current frame and any active frame that aliases a consumed value.
        # 复制当前帧及仍与已消费值存在别名关系的活动帧。
        selected_ids = {id(value) for value in self.consumed_values}
        for active in self.frames:
            if active is current or active.has_consumed_value_alias(
                self.consumed_values, selected_ids=selected_ids
            ):
                replacements[active] = active._copy_branch_state(proof, memo)
        proof.frames = [replacements.get(active, active) for active in self.frames]
        branch = replacements.get(current)
        if branch is None:
            branch = current._copy_branch_state(proof, memo)
        return proof, branch

    ## Capture the current branch-evidence boundary owned by this proof.
    ## 记录当前证明拥有的分支证据边界。
    #
    #  @return Evidence and analysis-boundary list offsets
    def branch_evidence_checkpoint(self):
        return len(self.evidence), len(self.boundaries)

    ## Merge only the branch-local evidence appended after a shared checkpoint.
    ## 仅合并共享边界之后追加的分支局部证据。
    #
    #  @param branch Forked proof whose branch outcome was accepted
    #  @param checkpoint Offsets returned by branch_evidence_checkpoint
    def merge_branch_evidence(self, branch, checkpoint):
        evidence_start, boundaries_start = checkpoint
        self.evidence.extend(branch.evidence[evidence_start:])
        self.boundaries.extend(branch.boundaries[boundaries_start:])

    ## Record an abstract value consumed on this proof path.
    ## 记录当前证明路径上已消费的抽象值。
    #
    #  @param value Abstract value whose consumption affects later boundaries
    def record_consumed_value(self, value):
        self.consumed_values.append(value)

    ## Mark that an unrelated unpack may terminate before later statements.
    ## 标记无关解包可能在后续语句前终止。
    def mark_unrelated_unpack_continuation(self):
        self.unrelated_unpack_continuation = True

    ## Append one validated result-ledger record.
    ## 向证明结果账本追加一条已构造记录。
    #
    #  @param evidence Evidence record to retain in encounter order
    def record_evidence(self, evidence):
        self.evidence.append(evidence)

    ## Append one unresolved analysis boundary.
    ## 追加一条未解决的分析边界。
    #
    #  @param boundary Boundary record explaining the unresolved result
    def record_boundary(self, boundary):
        self.boundaries.append(boundary)

    ## Resolve a caller-confirmed target for one exact call span.
    ## 按精确调用位置读取调用方确认的目标。
    #
    #  @param span Source span identifying the call
    #  @return Confirmed function identity, or None if unavailable
    def target_for_call(self, span):
        return self.known_targets.get(span)

    ## Check whether the caller supplied an override for one condition.
    ## 检查调用方是否为指定条件提供了覆盖值。
    #
    #  @param span Source span identifying the condition
    #  @return Whether this proof contains a supplied condition value
    def has_condition_override(self, span):
        return span in self.known_conditions

    ## Read a caller-supplied condition override.
    ## 读取调用方提供的条件覆盖值。
    #
    #  @param span Source span identifying the condition
    #  @return The exact boolean override; the caller must check presence first
    def condition_override(self, span):
        return self.known_conditions[span]

    ## Set a source-proven condition override for this analysis.
    ## 设置本次分析已由源码证明的条件覆盖值。
    #
    #  @param span Source span identifying the condition
    #  @param value Proven truth value
    def set_condition_override(self, span, value):
        self.known_conditions[span] = value

    ## Scope the source context used during a nested proof run
    ## 限定嵌套证明运行期间使用的源码上下文
    #
    #  @param context Source context selected for the nested entry
    #  @return Context manager that restores the previous context on exit
    @contextmanager
    def context_scope(self, context):
        previous = self.context
        self.context = context
        try:
            yield
        finally:
            self.context = previous

    ## Select the context owning facts for this proof's entry
    ## 选择本证明入口事实所属的源码上下文
    #
    #  @param context Source context selected for the resolved entry
    def select_context(self, context):
        self.context = context

    ## Check whether this proof has established a supported consumption.
    ## 检查本证明是否已确认受支持的消费行为。
    #
    #  @return True when a consumption witness is present, otherwise False
    def has_consumption_witness(self):
        return self.consumption_witness is not None

    ## Return immutable snapshots of the result ledgers.
    ## 返回结果账本的不可变快照。
    #
    #  @return Evidence and analysis boundaries in encounter order
    def result_records(self):
        return tuple(self.evidence), tuple(self.boundaries)

    ## Return the established handled reason, if any.
    ## 返回已确认的处理原因；若无则返回 None。
    #
    #  @return Handling reason or None
    def result_reason(self):
        return self.handled_reason

    ## Record evidence supporting one analysis outcome
    ## 记录支持某个分析结论的证据
    #
    #  @param function Indexed source function under analysis
    #  @param reason Machine-readable evidence reason
    #  @param detail Human-readable description of the evidence
    #  @param node Optional source AST node locating the evidence
    #  @param target Optional source target associated with the evidence
    def note(
        self,
        function,
        reason,
        detail,
        node=None,
        target=None,
    ):
        if isinstance(node, SourceSpan):
            span = node
        elif node is None or function.identity.file_path is None:
            span = None
        else:
            located_node = node
            if located_node.end_lineno is None or located_node.end_col_offset is None:
                span = None
            else:
                span = SourceSpan(
                    function.identity.file_path,
                    located_node.lineno,
                    located_node.col_offset,
                    located_node.end_lineno,
                    located_node.end_col_offset,
                )
        self.record_evidence(ParameterEvidence(function.identity, reason, detail, span, target))

    ## Stop the proof with an explicit analysis boundary
    ## 以明确的分析边界终止证明
    #
    #  @param function Indexed source function under analysis
    #  @param reason Machine-readable analysis boundary reason
    #  @param detail Human-readable explanation of the boundary
    #  @param node Source AST node locating the boundary, when available
    def unknown(
        self,
        function,
        reason,
        detail,
        node=None,
    ):
        self.note(function, reason, detail, node)
        self.record_boundary(
            AnalysisBoundary(reason, detail, function.identity, self.evidence[-1].callsite)
        )

        # Selected boundaries can preserve prior consumption if no frame can still use it.
        # 部分边界可保留既有消费结论，前提是活动帧无法继续使用该值。
        frames = list(self.frames)
        if (
            reason
            in (
                "mapping_effect_unproven",
                "call_target_unproven",
                "ordinary_container_binding_unproven",
                "unpacking_binding_unproven",
            )
            and self.consumption_witness is not None
            and not any(frame.has_nested_expression() for frame in frames)
            and not any(
                frame.has_live_selected_value(self.consumed_values) for frame in frames
            )
            and self.consumed_values
        ):
            self.note(
                function,
                "proven_consumption_before_boundary",
                "An earlier supported operation used the selected argument; "
                "later effects and call success remain unresolved.",
                node,
            )
            raise _Stop(ParameterState.HANDLED, "proven_consumption_before_boundary")
        raise _Stop(ParameterState.UNKNOWN, reason)

    ## Record evidence that the selected argument is consumed
    ## 记录选定实参已被消费的证据
    #
    #  @param function Indexed source function under analysis
    #  @param reason Machine-readable consumption reason
    #  @param detail Human-readable description of the consumption
    #  @param node Optional source AST node locating the consumption
    #  @param target Optional source target associated with the consumption
    def handled(
        self,
        function,
        reason,
        detail,
        node=None,
        target=None,
    ):
        self.note(function, reason, detail, node, target)
        self.handled_reason = reason
        if reason in ("consumed_presence", "consumed_value"):
            self.consumption_witness = self.evidence[-1]

    ## Bind abstract call arguments to one selected function signature.
    ## 将抽象调用实参绑定到所选函数签名。
    #
    #  @param function Indexed function receiving the call
    #  @param positional Abstract positional arguments
    #  @param keywords Abstract keyword arguments
    #  @param bound Whether the function is bound to a receiver
    #  @param node Call AST node, when available
    #  @param caller Indexed caller function, when available
    #  @param change Parameter change being assessed, when available
    #  @return Binding outcome
    def bind(
        self,
        function,
        positional,
        keywords,
        bound,
        node=None,
        *,
        caller=None,
        change=None,
    ):
        return bind_arguments(
            self, function, positional, keywords, bound, node, caller=caller, change=change
        )

    ## Record source evidence that the changed argument is rejected
    ## 记录变更实参被源码拒绝的证据
    #
    #  @param function Indexed source function under analysis
    #  @param reason Machine-readable rejection reason
    #  @param detail Human-readable explanation of the rejection
    #  @param node Optional source AST node locating the rejection
    #  @param target Optional rejection target; defaults to the current function
    def reject(
        self,
        function,
        reason,
        detail,
        node=None,
        target=None,
    ):
        if self.unrelated_unpack_continuation:
            self.unknown(
                function,
                "rejection_after_unconfirmed_unpack",
                "An earlier unrelated unpack may terminate after a proven use; "
                "this later rejection is not definitely reached.",
                node,
            )
        self.note(function, reason, detail, node, target or function.identity)
        raise _Stop(ParameterState.REJECTED, reason)

    ## Consume one exact body/binding proof, not callable identity alone
    ## 仅消费完整的函数体及绑定证明，不凭可调用对象身份作结论
    #
    #  @param function Indexed source function under analysis
    #  @param analysis PCResolve analysis result being validated or consumed
    #  @param positional_count Optional number of positional arguments supplied
    #  @return Whether an exact supported decoration proof preserves the body and binding
    def decoration_preserved(
        self,
        function,
        analysis,
        positional_count=None,
    ):
        return _decoration_preserved(
            self, self.context.index, function, analysis, positional_count
        )

    ## Run the bounded proof for one source function and call context
    ## 针对一个源码函数和调用上下文执行有界证明
    #
    #  @param function Indexed source function under analysis
    #  @param values Abstract values propagated through the analysis
    #  @param analysis Optional producer analysis; resolved from the context when omitted
    #  @param ancestry Source function identities already on the forwarding path
    #  @param facts Call-specific facts to supply to the new frame
    #  @param analysis_context Optional source context used while running this proof
    #  @param receiver Verified fresh-receiver facts propagated to the new frame
    #  @return Abstract result of interpreting the function body
    def run(
        self,
        function,
        values,
        *,
        analysis=None,
        ancestry=(),
        facts=(),
        analysis_context=None,
        receiver=NO_FRESH_RECEIVER,
    ):
        if analysis_context is None or analysis_context is self.context:
            return self._run(
                function,
                values,
                analysis=analysis,
                ancestry=ancestry,
                facts=facts,
                receiver=receiver,
            )
        with self.context_scope(analysis_context):
            return self._run(
                function,
                values,
                analysis=analysis,
                ancestry=ancestry,
                facts=facts,
                receiver=receiver,
            )

    ## Prepare producer facts and receiver state before interpreting a function
    ## 在解释函数前准备生产者事实及接收者状态
    #
    #  @param function Indexed source function under analysis
    #  @param values Abstract values propagated through the analysis
    #  @param analysis Optional producer analysis; resolved from the context when omitted
    #  @param ancestry Source function identities already on the forwarding path
    #  @param receiver Verified fresh-receiver facts propagated to the new frame
    #  @return Prepared analysis and receiver state
    #  @exception _Stop If recursion, depth or unsupported execution blocks interpretation
    def _prepare_run(
        self,
        function,
        values,
        analysis,
        ancestry,
        receiver,
    ):
        if function.identity in ancestry:
            self.unknown(function, "recursive_forwarding", "Recursive variadic forwarding.")
        if len(ancestry) >= self.max_depth:
            self.unknown(function, "depth_limit", "Argument propagation depth exhausted.")
        if not immediate_body(function.node):
            self.unknown(
                function, "deferred_execution", "Async/generator execution is not modeled."
            )
        try:
            analysis = analysis or self.context.adapter.analyze(
                function.query_class or function.query_alias or function.identity
            )
        except ResolutionError as exc:
            self.unknown(function, exc.code, str(exc))

        owner_name = function.identity.qualname.rpartition(".")[0]
        owner_class = next(
            (
                item
                for item in self.context.index.classes
                if item.module == function.identity.module and item.qualname == owner_name
            ),
            None,
        )
        if (
            owner_class is not None
            and function.identity.qualname.endswith(".__init__")
            and analysis.inputs.get("entry_binding", {}).get("phase") == "__init__"
            and _class_binding_may_escape(self.context.source_queries, owner_class)
        ):
            self.unknown(
                function,
                "source_class_binding_may_escape",
                "Source code can expose this class object to an unmodeled callable; its "
                "class members may change before the assessed constructor call.",
            )

        # Combine fresh receiver attributes only when their facts name the same allocation.
        # 仅当接收者事实指向同一分配位置时复用新建对象的属性事实
        if (
            not receiver.fresh
            and function.query_class is not None
            and analysis.inputs.get("entry_binding", {}).get("phase") == "__init__"
        ):
            receiver_facts = []
            for call in analysis.calls:
                fact = fresh_method_binding(analysis, call, self.context.index)
                if fact is not None:
                    receiver_facts.append(fact)
            if receiver_facts:
                binding = receiver_facts[0]
                if all(binding.same_allocation(fact) for fact in receiver_facts):
                    receiver = FreshReceiverState(
                        True,
                        receiver.exclusions,
                        frozenset(
                            name for fact in receiver_facts for name in fact.own_attributes
                        ),
                        receiver_facts[0].receiver_class,
                        _receiver_hierarchy(
                            analysis.inputs.get("entry_binding", {}).get("hierarchy", ())
                        ),
                        binding.allocation_effects,
                    )
        if (
            function.query_class is not None
            and analysis.inputs.get("entry_binding", {}).get("phase") == "__new__"
        ):
            self.unknown(
                function, "dynamic_construction", "Later constructor phases are unmodeled."
            )

        # Apply body results to the original call only when its decoration preserves the entry.
        # 装饰器未证明保留入口行为时，不将函数体结论用于原调用
        if function.node.decorator_list and not self.decoration_preserved(
            function, analysis, getattr(values, "positional_count", None)
        ):
            for summary in analysis.functions:
                if identity_from_target(summary["function"]) != function.identity:
                    continue
                for fact in summary.get("decorator_effects", ()):
                    for boundary in fact.get("boundaries", ()):
                        helper = boundary.get("source_target")
                        if (
                            boundary.get("source_available") is False
                            and isinstance(helper, str)
                            and boundary.get("reason") == "decorator_call_unresolved"
                        ):
                            self.boundaries.append(
                                AnalysisBoundary(
                                    "decorator_source_unavailable",
                                    f"Decorator helper {helper} has no source in this snapshot.",
                                    function.identity,
                                )
                            )
            self.unknown(function, "decorated_entry", "Entry/body decoration is not proven.")
        return _PreparedRun(analysis, receiver)

    ## Interpret one function with the supplied abstract state and path facts.
    ## 使用给定抽象状态和路径事实解释一个函数。
    #
    #  @param function Indexed source function to interpret
    #  @param values Abstract local values for the new frame
    #  @param analysis Producer facts, when already available
    #  @param ancestry Function identities already followed
    #  @param facts Caller and path facts available to the function
    #  @param receiver Verified fresh-receiver state for the new frame
    #  @return Proof outcome for the interpreted path
    def _run(
        self,
        function,
        values,
        *,
        analysis=None,
        ancestry=(),
        facts=(),
        receiver=NO_FRESH_RECEIVER,
    ):
        # Stop propagation on recursion, exhausted depth or deferred execution.
        # 递归、深度耗尽和延迟执行均超出当前传播范围
        prepared = self._prepare_run(
            function,
            values,
            analysis,
            ancestry,
            receiver,
        )
        analysis = prepared.analysis
        receiver = prepared.receiver

        member_check_facts = fresh_member_checks(self.context.index, analysis, function)
        for check in member_check_facts[:1]:
            checked_mapping = values.get(check["mapping_parameter"])
            if (
                not isinstance(checked_mapping, _Keywords)
                or checked_mapping.source_state
                or not checked_mapping.items
            ):
                continue
            if (
                check.get("status") == "requires_single_exact_mapping_item"
                and len(checked_mapping.items) != 1
            ):
                continue
            for key, selected_value in checked_mapping.items.items():
                if type(key) is not str or not _tracked(selected_value):
                    continue
                applicability = [
                    fresh_member_key_applies(candidate, key, function)
                    for candidate in member_check_facts
                ]
                if (
                    not applicability
                    or any(item is None for item in applicability)
                    or len(set(applicability)) != 1
                    or applicability[0] is not True
                ):
                    continue
                template = check["attribute_template"]
                attribute = template["prefix"] + key + template["suffix"]
                if attribute.startswith("__"):
                    continue
                present = [
                    attribute in set(candidate["member_names"]) | set(candidate["own_attributes"])
                    for candidate in member_check_facts
                ]
                if not any(present):
                    self.reject(
                        function,
                        "source_missing_property",
                        "A tracked mapping key selects a missing attribute on the "
                        "unexposed source receiver: " + attribute,
                    )
                stores = [
                    candidate["value_stores"].get(attribute) for candidate in member_check_facts
                ]
                if (
                    all(present)
                    and all(store is not None for store in stores)
                    and len({repr(store.get("target")) for store in stores}) == 1
                ):
                    store = stores[0]
                    self.handled(
                        function,
                        "consumed_value",
                        "The tracked mapping value is stored by the bounded source "
                        "setter " + attribute + ".",
                        target=identity_from_target(store["target"]),
                    )
                    return _Value()

        mapping = (
            values.get(function.signature.kwarg) if function.signature.kwarg is not None else None
        )
        if (
            isinstance(mapping, _Keywords)
            and not mapping.source_state
            and _tracked(mapping)
            and not any(
                _tracked(value)
                for name, value in values.items()
                if name != function.signature.kwarg
            )
        ):
            keys = closed_mapping_keys(analysis, function)
            selected = {key for key, value in mapping.items.items() if _tracked(value)}
            if keys is not None and selected.isdisjoint(keys):
                self.note(
                    function,
                    "unread_mapping_element",
                    "PCResolve bounds all capture accesses to fixed keys: "
                    + ", ".join(sorted(keys))
                    + ". The selected element is unread. "
                    "Assumes no external frame introspection; execution and call success "
                    "are not established.",
                )
                return _Value()

        # Register the frame during interpretation so nested calls can see its aliases.
        # 解释函数体时登记活动帧，使嵌套调用可见其别名。
        frame = _Frame(
            self,
            function,
            analysis,
            values,
            ancestry + (function.identity,),
            dict(facts),
            context=self.context,
            receiver=receiver,
        )
        self.frames.append(frame)
        try:
            frame.statements(function.node.body)
        finally:
            self.frames.pop()
        return frame.result
