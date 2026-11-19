## @package vppdetector.assess.proofs._decorator_exceptions
#  Read exception translation in supported decorator proofs.
#
#
#  Match exception handling and translation to the enclosing decorator proof and source witness.
#  将异常处理及转换与所属装饰器证明和源码见证匹配。



import ast

from pcresolve.effect_facts import builtin_exception_translation

from ...facts.calls import identity_from_target

_FIELDS = ("lineno", "col_offset", "end_lineno", "end_col_offset")


## Check whether an exception record matches the requested source location
## 检查异常记录是否匹配请求的源码位置
#
#  @param record Producer record whose fields are validated
#  @param identity Source-level identity used for lookup
#  @param node AST node whose coordinates are compared
#  @return Whether the record's file and coordinates match the source node
def _matches(record, identity, node):
    return (
        isinstance(record, dict)
        and record.get("file_path") == str(identity.file_path)
        and all(
            type(record.get(key)) is int and record[key] == getattr(node, key) for key in _FIELDS
        )
    )


## Validate the reached raise and any exception-only handler/source premise
## 验证到达的异常抛出及异常处理路径的源码前提
#
#  @param index Source index for the selected snapshot
#  @param fact Producer fact being validated or interpreted
#  @param effect Producer exception effect containing the raise and translation evidence
#  @return Whether the raise and any exception translation match the source evidence
def exception_raise_binding(
    index,
    fact,
    effect,
):
    identity = identity_from_target(effect.get("function"))
    function = index.find(identity) if identity is not None else None
    if function is None:
        return False
    nodes = list(ast.walk(function.node))
    raises = [
        node
        for node in nodes
        if isinstance(node, ast.Raise) and _matches(effect.get("evidence"), identity, node)
    ]
    if len(raises) != 1:
        return False
    raised = raises[0]
    if (
        not isinstance(raised.exc, ast.Call)
        or not isinstance(raised.exc.func, ast.Name)
        or raised.exc.func.id != effect.get("target")
    ):
        return False

    # Find the source handler that encloses the raise before checking translation evidence.
    # 校验异常转换证据之前，先找到源码中包围抛出语句的处理器。
    parents = {child: node for node in nodes for child in ast.iter_child_nodes(node)}
    current_node = raised
    handler = None
    while current_node in parents:
        current_node = parents[current_node]
        if isinstance(current_node, ast.ExceptHandler):
            handler = current_node
            break
    translation = effect.get("exception_translation")
    if translation is None:
        return handler is None and (
            raised.cause is None
            or isinstance(raised.cause, ast.Constant)
            and raised.cause.value is None
        )
    if not isinstance(translation, dict) or handler is None:
        return False
    source_try = parents.get(handler)
    translate = builtin_exception_translation
    shape = translate(handler)
    if (
        shape is None
        or not isinstance(source_try, ast.Try)
        or source_try.orelse
        or source_try.finalbody
        or not 1 <= len(source_try.handlers) <= 4
        or any(translation.get(key) != value for key, value in shape.items())
        or translation.get("raised_type") != effect.get("target")
        or translation.get("completion") != "exceptional_exit_only"
        or translation.get("runtime_exception_observed") is not False
        or "builtin_exception_handler_semantics" not in fact.get("assumptions", ())
        or not _matches(translation.get("handler"), identity, handler)
        or not _matches(translation.get("try"), identity, source_try)
        or not isinstance(effect.get("conditions"), (list, tuple))
    ):
        return False
    return any(
        isinstance(condition, dict)
        and condition.get("caught_types") == shape["caught_types"]
        and _matches(condition.get("exception_handler"), identity, handler)
        for condition in effect["conditions"]
    )
