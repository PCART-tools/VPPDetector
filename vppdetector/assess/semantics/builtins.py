## @package vppdetector.assess.semantics.builtins
#  Bounded builtin protocol operations before ordinary source-call dispatch.
#
#
#  Try supported callability, length, truth and container operations in rule order and defer
#  unmatched calls.
#  依照规则顺序处理支持的可调用性、长度、真值及容器操作，将未匹配调用交给后续分派。



import ast

from ...facts.builtin_protocols import (
    container_length_protocol,
    exact_callability_protocol,
    scalar_truth_protocol,
)
from ...facts.containers import copy_protocol_target
from ..values import (
    _BoundSourceMethod,
    _key_presence,
    _KeySet,
    _Keywords,
    _Positionals,
    _tracked,
    _Value,
)
from .outcomes import NOT_APPLICABLE


## Apply builtin rules in order; unknown inputs stop through frame.unknown.
## 按顺序应用内置规则；未知输入通过帧产生保守结果。
#
#  @param frame Call frame providing abstract values and proof operations.
#  @param node Call AST node being interpreted.
#  @param facts Producer call facts, when available.
#  @param positional Abstract positional argument values.
#  @param keywords Abstract keyword argument values.
#  @return Interpreted result, or NOT_APPLICABLE when no rule matches.
def builtin_call(
    frame,
    node,
    facts,
    positional,
    keywords,
):
    for rule in (_callability, _length, _truth, _copy, _key_conversion):
        result = rule(frame, node, facts, positional, keywords)
        if result is not NOT_APPLICABLE:
            return result
    return NOT_APPLICABLE


## Model callable() for source-proven exact built-in inputs.
## 对有源码证明的精确内置值建模 callable()。
#
#  @param frame Current assessment frame
#  @param node Call expression being interpreted
#  @param facts Producer call facts
#  @param positional Evaluated positional arguments
#  @param keywords Evaluated keyword arguments
#  @return Abstract callability, or NOT_APPLICABLE when the protocol does not match
def _callability(frame, node, facts, positional, keywords):
    callability = (
        exact_callability_protocol(frame.analysis, facts)
        if facts and frame.analysis is not None
        else None
    )
    if callability is not None and len(positional) == 1 and not keywords:
        value = positional[0]
        if isinstance(value, _BoundSourceMethod):
            return _Value(True, value.tracked, value.key_presence, consumed=True)
        if (
            isinstance(value, (_Keywords, _Positionals, _KeySet))
            or isinstance(value, _Value)
            and type(value.literal) in (type(None), bool, int, float, str, bytes)
        ):
            frame.proof.note(
                frame.function,
                "builtin_exact_callability",
                "This exact builtin input type has no call protocol.",
                node,
            )

            # Exact carrier type is independent of its selected payload
            # or element presence. Only a selected object itself is read.
            # 载体的精确类型与选中负载及元素是否存在相互独立；这里只读取被选中的对象本身。
            selected_object = (
                isinstance(value, _Value)
                and value.tracked
                and not value.consumed
                and not value.key_presence
                and not value.derived
            )

            # Calling builtin ``callable`` on an exact builtin value can
            # consume its value while the result still depends on whether
            # that selected value came from a tracked keyword. Keep those
            # facts separate: downstream ``if not callable(value)`` guards
            # must remain tied to the original keyword presence.
            # 对精确内建值调用callable可消费该值，但结论仍取决于所选值是否来自被跟踪关键字；
            # 两类事实必须分开，后续守卫仍关联原关键字是否出现。
            return _Value(False, selected_object, _key_presence(value), consumed=selected_object)
        frame.unknown("callability_input_unproven", node)
    return NOT_APPLICABLE


## Model length for a proven exact built-in container or string.
## 对已证明的精确内置容器或字符串建模长度。
#
#  @param frame Current assessment frame
#  @param node Call expression being interpreted
#  @param facts Producer call facts
#  @param positional Evaluated positional arguments
#  @param keywords Evaluated keyword arguments
#  @return Abstract length, or NOT_APPLICABLE when the protocol does not match
def _length(frame, node, facts, positional, keywords):
    length_protocol = (
        container_length_protocol(frame.analysis, facts)
        if facts and frame.analysis is not None
        else None
    )

    # The fact identifies the length protocol. The abstract operand must still meet its condition.
    # 事实给出长度协议，抽象操作数仍须满足该协议的条件。
    if length_protocol is not None and len(positional) == 1 and not keywords:
        value = positional[0]
        if isinstance(value, (_Keywords, _Positionals, _KeySet)):
            length = len(value.items)
        elif isinstance(value, _Value) and type(value.literal) in (str, bytes):
            length = len(value.literal)
        else:
            frame.unknown("length_input_unproven", node)
        frame.proof.note(
            frame.function,
            "builtin_container_length",
            "Exact builtin input discharges the source length obligation.",
            node,
        )
        return _Value(
            length,
            _tracked(value),
            isinstance(value, (_Keywords, _KeySet)) and _tracked(value),
            consumed=True,
        )
    return NOT_APPLICABLE


## Model truth conversion for a proven exact scalar.
## 对已证明的精确标量建模真假转换。
#
#  @param frame Current assessment frame
#  @param node Call expression being interpreted
#  @param facts Producer call facts
#  @param positional Evaluated positional arguments
#  @param keywords Evaluated keyword arguments
#  @return Abstract truth, or NOT_APPLICABLE when the protocol does not match
def _truth(frame, node, facts, positional, keywords):
    truth_protocol = (
        scalar_truth_protocol(frame.analysis, facts)
        if facts and frame.analysis is not None
        else None
    )
    if truth_protocol is not None and len(positional) == 1 and not keywords:
        value = positional[0]
        if isinstance(value, _Value) and type(value.literal) in (
            type(None),
            bool,
            int,
            float,
            str,
            bytes,
        ):
            truth = frame.truth(value)
            frame.proof.note(
                frame.function, "builtin_scalar_truth", f"Exact scalar conversion: {truth}.", node
            )
            return _Value(truth, _tracked(value), _key_presence(value), consumed=True)
    return NOT_APPLICABLE


## Model a source-proven built-in container copy.
## 对有源码证明的内置容器复制建模。
#
#  @param frame Current assessment frame
#  @param node Call expression being interpreted
#  @param facts Producer call facts
#  @param positional Evaluated positional arguments
#  @param keywords Evaluated keyword arguments
#  @return Copied abstract container, or NOT_APPLICABLE when unsupported
def _copy(frame, node, facts, positional, keywords):
    if facts and frame.analysis is not None and len(facts.result_sources) == 1:
        protocol = copy_protocol_target(
            frame.function, frame.analysis, facts, facts.result_sources[0]
        )
        if protocol is not None and isinstance(node.func, ast.Name):
            value = positional[0]
            copied = None
            if protocol.qualname == "dict" and isinstance(value, _Keywords):
                copied = _Keywords(dict(value.items), value.carrier, value.source_state)
            elif protocol.qualname in ("tuple", "list") and isinstance(value, _Positionals):
                copied = _Positionals(
                    value.items, value.carrier, protocol.qualname, value.source_state
                )
            if copied is not None:
                # Copy current modeled contents, retaining selected values and element order.
                # 复制当前建模的内容，并保留选定值和元素顺序。
                frame.proof.note(
                    frame.function, "builtin_container_copy", ast.unparse(node), node, protocol
                )
                return copied

    return NOT_APPLICABLE


## Model supported conversions between tracked mapping keys and containers.
## 对跟踪的映射键与容器间受支持的转换建模。
#
#  @param frame Current assessment frame
#  @param node Call expression being interpreted
#  @param facts Producer call facts
#  @param positional Evaluated positional arguments
#  @param keywords Evaluated keyword arguments
#  @return Converted abstract container, or NOT_APPLICABLE when the rule does not match
def _key_conversion(frame, node, facts, positional, keywords):
    if (
        isinstance(node.func, ast.Name)
        and node.func.id in ("set", "list")
        and facts
        and facts.target is None
        and facts.target_status == "python_protocol"
        and frame.unshadowed_builtin_name(node.func.id)
        and len(positional) == 1
        and not keywords
    ):
        value = positional[0]
        if node.func.id == "set" and isinstance(value, _Keywords):
            return _KeySet({key: _tracked(item) for key, item in value.items.items()})
        if node.func.id == "set" and isinstance(value, _KeySet):
            return _KeySet(dict(value.items))
        if node.func.id == "list" and isinstance(value, _KeySet):
            if len(value.items) > 1:
                frame.unknown("key_iteration_order_unproven", node)
            return _Positionals(
                tuple(_Value(key, tracked) for key, tracked in value.items.items()), kind="list"
            )
        frame.unknown("key_comparison_unproven", node)
    return NOT_APPLICABLE
