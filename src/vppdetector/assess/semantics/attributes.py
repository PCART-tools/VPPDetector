## @package vppdetector.assess.semantics.attributes
#  Receiver operation models used before source-call dispatch.
#
#
#  Evaluate the receiver and route supported calls to sequence, string or mapping handlers.
#  求值接收者，将受支持的调用交给序列、字符串或映射处理器。



import ast

from ...facts.containers import mapping_protocol
from ..values import _UNKNOWN, _Keywords, _Positionals, _tracked, _Value
from .outcomes import NOT_APPLICABLE


## Model receiver operations in precedence order before source-call dispatch.
## 在源码调用分派前按优先级建模接收者操作。
#
#  @param frame Call frame providing abstract values and proof operations
#  @param node Call AST node with an attribute callee
#  @param facts Producer call facts, when available
#  @return Interpreted result, or NOT_APPLICABLE when no receiver rule matches
def attribute_call(frame, node, facts):
    if not isinstance(node.func, ast.Attribute):
        return NOT_APPLICABLE
    receiver = frame.expression(node.func.value)
    if isinstance(receiver, _Positionals):
        return _sequence_call(frame, node, facts, receiver)
    if (
        isinstance(receiver, _Value)
        and type(receiver.literal) is str
        and node.func.attr in ("startswith", "endswith")
    ):
        return _string_call(frame, node, facts, receiver)
    if isinstance(receiver, _Keywords):
        return _mapping_call(frame, node, facts, receiver)
    return NOT_APPLICABLE


## Interpret a supported operation on a locally modeled sequence.
## 解释局部建模序列上的受支持操作。
#
#  @param frame Current assessment frame
#  @param node Attribute call expression
#  @param facts Producer call facts, when available
#  @param receiver Modeled positional container receiving the call
#  @return Abstract call result, or NOT_APPLICABLE when unsupported
def _sequence_call(
    frame,
    node,
    facts,
    receiver,
):
    if not isinstance(node.func, ast.Attribute):
        return NOT_APPLICABLE
    if (
        node.func.attr == "append"
        and isinstance(node.func.value, ast.Name)
        and frame.values.get(node.func.value.id) is receiver
        and receiver.kind == "list"
        and not receiver.source_state
        and len(node.args) == 1
        and not isinstance(node.args[0], ast.Starred)
        and not node.keywords
        and facts is not None
        and facts.target is None
        and facts.target_status == "local_container_protocol"
        and facts.analysis_status == "analyzed"
        and facts.binding_status == "complete"
        and not facts.binding_issues
        and not facts.target_candidates
        and facts.receiver_sources
        and all(isinstance(item, dict) for item in facts.receiver_sources)
        and not any(
            name != node.func.value.id and value is receiver for name, value in frame.values.items()
        )
    ):
        positional, keywords = frame.arguments(node)
        if len(positional) != 1 or keywords:
            frame.unknown("sequence_effect_unproven", node)
        name = node.func.value.id
        frame.set_local(name, _Positionals(
            receiver.items + (positional[0],),
            receiver.carrier,
            receiver.kind,
            receiver.source_state,
        ))
        frame.proof.note(
            frame.function,
            "bounded_local_list_append",
            "PCResolve identifies this exact append as a complete local "
            "container protocol call, and the receiver is a unique fresh "
            "source-local list.",
            node,
        )
        return _Value(None)
    frame.unknown("sequence_effect_unproven", node)
    return NOT_APPLICABLE


## Interpret supported string prefix and suffix checks.
## 解释受支持的字符串前缀和后缀检查。
#
#  @param frame Current assessment frame
#  @param node Attribute call expression
#  @param facts Producer call facts, when available
#  @param receiver Modeled string value receiving the call
#  @return Abstract call result, or NOT_APPLICABLE when unsupported
def _string_call(
    frame,
    node,
    facts,
    receiver,
):
    if not isinstance(node.func, ast.Attribute):
        return NOT_APPLICABLE
    positional, keywords = frame.arguments(node)
    tracked = _tracked(receiver) or any(
        _tracked(item) for item in positional + list(keywords.values())
    )
    if (
        len(positional) == 1
        and not keywords
        and isinstance(positional[0], _Value)
        and type(positional[0].literal) is str
    ):
        return _Value(
            getattr(str, node.func.attr)(receiver.literal, positional[0].literal),
            tracked,
        )
    return _Value(tracked=tracked)
    return NOT_APPLICABLE


## Interpret bounded mutations on a modeled keyword mapping.
## 解释建模关键字映射上的有界修改操作。
#
#  @param frame Current assessment frame
#  @param node Attribute call expression
#  @param facts Producer call facts, when available
#  @param receiver Modeled keyword mapping receiving the call
#  @return Abstract call result, or NOT_APPLICABLE when unsupported
def _mapping_call(
    frame,
    node,
    facts,
    receiver,
):
    if not isinstance(node.func, ast.Attribute):
        return NOT_APPLICABLE
    if node.func.attr == "clear":
        if (
            not facts
            or frame.analysis is None
            or receiver.source_state
            or not mapping_protocol(frame.function, frame.analysis, facts, "clear")
        ):
            frame.unknown("mapping_effect_unproven", node)
        receiver.items.clear()
        return _Value(None)

    # Prove the exact mapping operation before modeling its return or possible insertion.
    # 先核实映射操作的实际语义，再建模返回值或可能发生的插入。
    if node.func.attr == "setdefault":
        positional, keywords = frame.arguments(node)
        key = (
            positional[0].literal if positional and isinstance(positional[0], _Value) else _UNKNOWN
        )
        if (
            not facts
            or frame.analysis is None
            or receiver.source_state
            or len(positional) not in (1, 2)
            or keywords
            or type(key) is not str
            or not mapping_protocol(frame.function, frame.analysis, facts, "setdefault", key)
        ):
            frame.unknown("mapping_effect_unproven", node)
        result = receiver.items.get(key, positional[1] if len(positional) == 2 else _Value(None))
        receiver.items[key] = result
        frame.proof.note(
            frame.function,
            "bounded_mapping_setdefault",
            "PCResolve proves this exact builtin dict.setdefault mutates the "
            "source kwargs mapping on normal return; the known caller values "
            "remain in the modeled mapping.",
            node,
        )
        return result
    if node.func.attr == "get":
        positional, keywords = frame.arguments(node)
        key = (
            positional[0].literal if positional and isinstance(positional[0], _Value) else _UNKNOWN
        )
        if (
            not facts
            or frame.analysis is None
            or len(positional) not in (1, 2)
            or keywords
            or type(key) is not str
            or not mapping_protocol(frame.function, frame.analysis, facts, "get", key)
        ):
            frame.unknown("mapping_effect_unproven", node)
        return receiver.items.get(key, positional[1] if len(positional) == 2 else _Value(None))

    if node.func.attr == "copy" and facts:
        if (
            facts.target_status == "local_container_protocol"
            and not node.args
            and not node.keywords
            and any(
                effect.get("operation") == "copy"
                and effect.get("status") == "bounded"
                and effect.get("identity") == "shallow_copy"
                and effect.get("completion") == "normal_return"
                for effect in facts.effects
            )
        ):
            return _Keywords(dict(receiver.items), receiver.carrier)
        frame.unknown("mapping_effect_unproven", node)
    if node.func.attr == "pop" and facts and facts.target_status == "local_container_protocol":
        positional, keywords = frame.arguments(node)
        key = (
            positional[0].literal if positional and isinstance(positional[0], _Value) else _UNKNOWN
        )
        if (
            len(positional) not in (1, 2)
            or keywords
            or type(key) is not str
            or not any(
                effect.get("status") == "bounded"
                and effect.get("operation") == "pop"
                and effect.get("state_after") in {"absent", "conditional"}
                and effect.get("element_path") == [key]
                for effect in facts.effects
            )
        ):
            frame.unknown("mapping_effect_unproven", node)
        if key not in receiver.items and len(positional) == 1:
            frame.unknown("call_binding_unproven", node)
        result = receiver.items.pop(key, positional[1] if len(positional) == 2 else _Value())
        if _tracked(result):
            frame.proof.note(frame.function, "removed_key", key, node)
            if len(positional) == 1:
                frame.proof.handled(
                    frame.function,
                    "consumed_presence",
                    "Required pop uses key presence.",
                    node,
                )
        return result

    # An unsupported method on a tracked carrier leaves its effects unresolved.
    # 被跟踪容器调用未支持的方法时，保留其效果无法确定的结论。
    if receiver.carrier:
        frame.unknown("mapping_effect_unproven", node)
    return NOT_APPLICABLE
