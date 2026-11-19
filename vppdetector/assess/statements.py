## @package vppdetector.assess.statements
#  Statement-level rules for the finite argument binding model.
#
#
#  Route supported statements to their handlers and record a boundary for unsupported control
#  flow.
#  将受支持语句分派给各自处理器，并为未建模控制流记录边界。



import ast
import builtins

from ..facts.calls import direct_calls
from .proofs._cached_imports import cached_import_binding
from .proofs._context_manager_propagation import rethrows_with_body
from .semantics.assignments import assign
from .semantics.conditions import conditional
from .values import _UNKNOWN, _key_presence, _LocalFunction, _tracked, _Value


## Record an abstract return and any tracked value it consumes.
## 记录抽象返回值及其中消费的跟踪值。
#
#  @param frame Current assessment frame
#  @param statement Return statement to interpret
def return_statement(frame, statement):
    result = frame.expression(statement.value) if statement.value else _Value(None)
    frame.record_return(result)
    if _tracked(result):
        frame.proof.handled(
            frame.function, "consumed_value", "Value participates in return.", statement
        )


## Bind a local import only when its cached initialization is proven.
## 仅在已证明初始化缓存时绑定局部导入。
#
#  @param frame Current assessment frame
#  @param statement Import statement to interpret
def import_statement(frame, statement):
    if not isinstance(statement, ast.ImportFrom):
        frame.unknown("local_import_execution_unconfirmed", statement)
    binding = cached_import_binding(frame.analysis, frame.function, statement)
    if binding is None:
        frame.unknown("local_import_execution_unconfirmed", statement)
    for value in binding["bindings"]:
        name = value["name"]
        frame.bind_local(name, _Value())
    frame.proof.note(
        frame.function,
        "source_cached_import_binding",
        "Source initialization already imported this module. Continuation assumes the recorded "
        "import cache and namespace bindings remain unchanged: "
        + "; ".join(binding["assumptions"]),
        statement,
    )


## Interpret a proven one-item mapping loop and restore temporary bindings.
## 解释已证明的单项映射循环并恢复临时绑定。
#
#  @param frame Current assessment frame
#  @param statement For statement to interpret
def mapping_loop(frame, statement):
    mapping = frame.mapping_items(statement)
    if mapping is None or not isinstance(statement.target, (ast.Tuple, ast.List)):
        frame.unknown("unsupported_control_flow", statement)
        return
    target_items = statement.target.elts
    if (
        len(target_items) != 2
        or not isinstance(target_items[0], ast.Name)
        or not isinstance(target_items[1], ast.Name)
    ):
        frame.unknown("unsupported_control_flow", statement)
    key_name, value_name = target_items[0].id, target_items[1].id
    key, item = next(iter(mapping.items.items()))
    tracked = _tracked(item)
    if not tracked:
        frame.unknown("untracked_mapping_iteration", statement)

    # Restore temporary loop bindings even when the modeled body terminates the proof.
    # 即使建模的循环体终止证明，也要恢复临时绑定。
    previous = {name: frame.values.get(name, _UNKNOWN) for name in (key_name, value_name)}
    frame.set_local(key_name, _Value(
        key, tracked=tracked, key_presence=_key_presence(item) or tracked
    ))
    frame.set_local(value_name, item)
    frame.proof.note(
        frame.function,
        "bounded_builtin_mapping_iteration",
        "PCResolve binds the exact direct mapping receiver; the captured built-in keyword "
        "dictionary has one statically known item.",
        statement,
    )
    try:
        frame.statements(statement.body)
    finally:
        for name, value in previous.items():
            if value is _UNKNOWN:
                frame.remove_local(name)
            else:
                frame.set_local(name, value)


## Interpret a context-manager body when exception propagation is proven.
## 在异常传播得到证明时解释上下文管理器的语句体。
#
#  @param frame Current assessment frame
#  @param statement With statement to interpret
def with_statement(frame, statement):
    fact = rethrows_with_body(
        frame.context.index, frame.analysis, frame.function, statement
    )
    if fact is None:
        frame.unknown("unsupported_control_flow", statement)
        return
    frame.proof.note(
        frame.function,
        "source_context_manager_rethrows",
        "PCResolve binds the source context-manager call; its standard contextlib generator has "
        "one yield under try/finally and no exception handler or cleanup return. The selected "
        "body is analyzed with its exception preserved. Assumptions: "
        + "; ".join(fact["assumptions"]),
        statement,
        target=fact["manager"],
    )
    frame.statements(statement.body)


## Continue past an assertion only when its test is proven true and unrelated.
## 仅在断言条件已证明为真且与跟踪值无关时继续。
#
#  @param frame Current assessment frame
#  @param statement Assert statement to interpret
def assert_statement(frame, statement):
    condition = frame.expression(statement.test)
    if frame.truth(condition) is not True or _tracked(condition):
        frame.unknown("assertion_execution_unconfirmed", statement)
    # A proved true, unrelated test has the same continuation with assertions
    # enabled or disabled. Its message is never evaluated.
    # 已证明为真的无关断言在启用或停用时走相同的后续路径，也不会求值其消息。
    frame.proof.note(
        frame.function,
        "static_assertion_continuation",
        "The assertion test is statically true; its message is skipped.",
        statement.test,
    )


## Prove rejection from a supported guarded exception construction.
## 根据受支持的守卫异常构造证明拒绝。
#
#  @param frame Current assessment frame
#  @param statement Raise statement to interpret
def rejection_raise(frame, statement):
    call = statement.exc
    if (
        not frame.rejection_guard
        or statement.cause is not None
        or not isinstance(call, ast.Call)
        or not isinstance(call.func, ast.Name)
        or call.keywords
        or not frame.unshadowed_builtin_name(call.func.id)
    ):
        frame.unknown("unsupported_control_flow", statement)
    exception = getattr(builtins, call.func.id, None)
    edge = next(
        (
            edge
            for edge in direct_calls(frame.analysis, frame.function.identity)
            if (edge.lineno, edge.col_offset, edge.end_lineno, edge.end_col_offset)
            == (call.lineno, call.col_offset, call.end_lineno, call.end_col_offset)
        ),
        None,
    )
    if (
        not isinstance(exception, type)
        or not issubclass(exception, Exception)
        or edge is None
        or edge.target is not None
        or edge.target_status != "builtin_boundary"
    ):
        frame.unknown("exception_construction_unproven", statement)

    # Do not execute a custom message formatter or turn an unrelated error
    # into permission, even under an established rejection guard.
    # 即使已有拒绝守卫，也不能执行自定义消息格式化，或把无关错误视为实参被拒绝。

    if exception is AttributeError and frame.rejection_guard and len(call.args) == 1:
        frame.proof.note(
            frame.function,
            "rejection_message_not_required",
            "The selected unsupported-key guard already proves rejection; message formatting "
            "can only preserve or replace that failure.",
            statement,
        )
    else:
        arguments = [frame.expression(item) for item in call.args]
        if any(not isinstance(item, _Value) or item.literal is _UNKNOWN for item in arguments):
            frame.unknown("exception_construction_unproven", statement)
    frame.proof.reject(frame.function, "proven_guard_rejection", ast.unparse(statement), statement)


## Bind a local definition after checking its evaluated components.
## 检查定义时求值的组成部分后绑定局部定义。
#
#  @param frame Current assessment frame
#  @param statement Function or class definition to interpret
def definition_statement(
    frame,
    statement,
):
    # A definition does not execute its body; captured calls are checked below.
    # 定义时不执行函数体，捕获调用在后续步骤中检查。
    if statement.decorator_list or any(
        frame.related(item)
        or isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef))
        and any(isinstance(child, ast.Call) for child in ast.walk(item))
        for item in ast.iter_child_nodes(statement)
        if not isinstance(item, ast.stmt)
    ):
        frame.unknown("definition_effects_unmodeled", statement)
    frame.set_local(statement.name, (
        _LocalFunction(statement)
        if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef))
        else _Value(tracked=frame.related(statement))
    ))


## Record consumption discovered while interpreting an expression statement.
## 解释表达式语句时记录发现的消费值。
#
#  @param frame Current assessment frame
#  @param statement Expression statement to interpret
def expression_statement(frame, statement):
    result = frame.expression(statement.value)
    if frame.proof.has_consumption_witness() and isinstance(result, _Value):
        if result.tracked and not result.consumed:
            frame.proof.record_consumed_value(result)


## Interpret one statement; recursive bodies use the same frame policy.
## 解释一条语句；递归语句体沿用相同的帧策略。
#
#  @param frame Frame containing the current abstract path state.
#  @param statement Statement AST node to interpret.
#  @param continuation Statements following this node in the current body.
#  @return None after applying the statement effect; unsupported statements
#          record an analysis boundary on the frame.
def handle(frame, statement, continuation):
    if isinstance(statement, ast.Return):
        return_statement(frame, statement)
    elif isinstance(statement, (ast.Assign, ast.AnnAssign)):
        assign(frame, statement)
    elif isinstance(statement, ast.Expr):
        expression_statement(frame, statement)
    elif isinstance(statement, (ast.Import, ast.ImportFrom)):
        import_statement(frame, statement)
    elif isinstance(statement, ast.If):
        conditional(frame, statement, continuation)
    elif isinstance(statement, ast.For):
        mapping_loop(frame, statement)
    elif isinstance(statement, ast.With):
        with_statement(frame, statement)
    elif isinstance(statement, ast.Assert):
        assert_statement(frame, statement)
    elif isinstance(statement, ast.Raise):
        rejection_raise(frame, statement)
    elif isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        definition_statement(frame, statement)
    elif not isinstance(statement, ast.Pass):
        frame.unknown("unsupported_control_flow", statement)
