## @package vppdetector.assess.semantics.conditions
#  Conditional statement semantics for a bounded assessment frame.
#
#
#  Choose known branches and check whether every modeled continuation rejects when the condition
#  is unresolved.
#  选择已知分支，在条件未解析时检查建模的后续分支是否均拒绝实参。



import ast

from ...models import SourceSpan
from ..values import _key_presence, _tracked, _Value


## Select a proved branch or conservatively handle an unresolved condition.
## 选择已证明的分支，或保守处理未解析的条件。
#
#  @param frame Statement frame whose path state is forked or continued.
#  @param statement Conditional AST statement.
#  @param continuation Statements that execute after the conditional.
#
def conditional(frame, statement, continuation):
    condition = frame.expression(statement.test)
    truth = frame.truth(condition)
    span = SourceSpan(
        frame.function.identity.file_path,
        statement.test.lineno,
        statement.test.col_offset,
        statement.test.end_lineno or statement.test.lineno,
        statement.test.end_col_offset or statement.test.col_offset,
    )

    # Apply caller facts only to predicates independent of the selected argument.
    # 只将调用方事实用于与选定实参无关的谓词。
    if (frame.proof.has_condition_override(span)
            and not frame.related(statement.test)):
        supplied = frame.proof.condition_override(span)
        if truth is not None and truth is not supplied:
            frame.unknown('conflicting_call_facts', statement.test)
        truth = supplied
        frame.proof.note(frame.function, 'supplied_condition_fact',
                        'Caller supplied the global predicate outcome: '
                        + str(supplied), statement.test)

    if truth is None:
        if frame.normal_path_guard(statement):
            return
        frame._reject_if_all_branches_reject(
            statement, continuation
        )
        abrupt = any(
            isinstance(item, (ast.Return, ast.Raise, ast.Break, ast.Continue))
            for branch in (*statement.body, *statement.orelse)
            for item in ast.walk(branch)
        )
        if frame.related(statement) or abrupt:
            frame.unknown("unresolved_condition", statement.test)

        # Only non-terminating, unrelated branches may be skipped.
        # 只有无关且不会提前结束执行的分支可以跳过。
        for item in ast.walk(statement):
            if isinstance(item, ast.Name) and isinstance(item.ctx, ast.Store):
                frame.set_local(item.id, _Value())
                frame.invalidate_facts(item.id)
        return

    if _tracked(condition):
        frame.proof.handled(
            frame.function,
            "consumed_presence",
            "Parameter controls a guard.",
            statement.test,
        )
    frame.proof.note(
        frame.function,
        "selected_branch",
        f"{ast.unparse(statement.test)}: {truth}",
        statement.test,
    )
    # This narrow rejection concerns captured key acceptance, not
    # arbitrary value constraints or errors in the other branch.
    # 此处拒绝结论仅针对捕获关键字是否被接受，不推断任意值约束，也不外推另一分支的错误。
    with frame.rejection_guard_scope(bool(truth and _key_presence(condition))):
        frame.statements(statement.body if truth else statement.orelse)
