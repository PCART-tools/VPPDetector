## @package vppdetector.assess.semantics.assignments
#  Assignment effects in the bounded parameter assessment interpreter.
#
#
#  Route assignment targets by shape and update local values, aliases and facts invalidated by
#  the write.
#  按形态处理赋值目标，更新局部值、别名及被写入操作使其失效的事实。



import ast

from ..proofs._static_attribute_retention import retained_store as static_retained_store
from ..values import (
    _Keywords,
    _LocalFunction,
    _Positionals,
    _protected_state,
    _tracked,
    _Value,
)


## Update one frame while retaining provenance and invalidating stale facts.
## 更新一个帧，同时保留来源信息并清除过期事实。
#
#  @param frame Statement frame whose bindings and facts are updated.
#  @param statement Assignment AST node to interpret.
#
def assign(frame, statement):
    result = frame.expression(statement.value) if statement.value else _Value()
    targets = (
        statement.targets if isinstance(statement, ast.Assign) else (statement.target,)
    )
    for target in targets:
        if isinstance(target, (ast.Tuple, ast.List)):
            names = [child.id for child in ast.walk(target)
                     if isinstance(child, ast.Name)]
            receiver_name = (frame.function.node.args.posonlyargs
                + frame.function.node.args.args)

            # This unpack can be ignored only when it writes unrelated, known instance attributes.
            # 仅当解包写入的是无关且已知的实例属性时，才可跳过这一步。
            unrelated_receiver_attribute_unpack = (
                isinstance(result, _Positionals)
                and len(target.elts) == len(result.items)
                and frame.receiver.fresh and receiver_name
                and not frame.related(statement) and not _tracked(result)
                and all(isinstance(child, ast.Attribute)
                    and isinstance(child.value, ast.Name)
                    and child.value.id == receiver_name[0].arg
                    and child.attr in frame.receiver.own_attributes
                    and child.attr not in frame.receiver.exclusions
                    for child in target.elts)
            )
            if unrelated_receiver_attribute_unpack:
                continue
            plain = all(isinstance(child, (ast.Tuple, ast.List, ast.Name,
                                          ast.Store, ast.Load))
                        for child in ast.walk(target))
            if (not isinstance(result, _Positionals) and plain
                    and frame.proof.has_consumption_witness()
                    and not frame.related(statement) and not _tracked(result)
                    and not _protected_state(result)):
                for name in names:
                    if isinstance(frame.values.get(name), _LocalFunction):
                        frame.unknown('local_callable_rebinding', statement)
                    frame.bind_local(name, _Value())
                frame.proof.mark_unrelated_unpack_continuation()
                frame.proof.note(frame.function, 'unrelated_unpack_after_consumption',
                                'The selected argument was already used. If this '
                                'unrelated unpack fails, that use remains; otherwise '
                                'the continuation is checked with unknown locals.',
                                statement)
                continue
            for name, item in frame.finite_unpack(target, result):
                if isinstance(frame.values.get(name), _LocalFunction):
                    frame.unknown('local_callable_rebinding', statement)
                frame.bind_local(name, item)
            continue
        if not isinstance(target, ast.Name):
            capture = frame.function.signature.kwarg
            mapping_store = (
                isinstance(result, _Keywords) and result.carrier
                and not result.source_state
                and capture is not None and result is frame.values.get(capture)
            )
            positional = (frame.function.node.args.posonlyargs
                          + frame.function.node.args.args)
            if (frame.receiver.fresh and isinstance(result, _Value)
                    and _tracked(result)
                    and isinstance(target, ast.Attribute)
                    and isinstance(target.value, ast.Name)
                    and positional and target.value.id == positional[0].arg
                    and target.attr in {'__class__', '__dict__'}):
                frame.unknown('fresh_receiver_special_attribute_mutation_unproven',
                             statement)
            if (frame.receiver.fresh and isinstance(result, _Value)
                    and _tracked(result)
                    and isinstance(target, ast.Attribute)
                    and isinstance(target.value, ast.Name)
                    and positional and target.value.id == positional[0].arg
                    and target.attr not in frame.receiver.exclusions):
                frame.proof.record_consumed_value(result)
                frame.proof.handled(
                    frame.function, 'consumed_value',
                    'The fresh source setter stores the selected value on its '
                    'bound receiver.', statement,
                )
                continue

            # Use constructor evidence to prove that a tracked store survives to normal return.
            # 利用构造器证据确认被跟踪的写入保留至正常返回。
            if _tracked(result) and (isinstance(result, _Value) or mapping_store):
                retention = static_retained_store(
                    frame.analysis, frame.function, statement, target,
                    mapping_capture=capture if mapping_store else None,
                    source_queries=frame.context.source_queries,
                )
                if retention is not None:
                    assumptions = retention.get("assumptions")
                    if (not isinstance(assumptions, (list, tuple))
                            or not all(isinstance(item, str) for item in assumptions)):
                        frame.unknown("retention_assumptions_unproven", statement)
                    frame.proof.handled(
                        frame.function, "retained_instance_attribute",
                        "PCResolve proves an ordinary fresh-instance store of the "
                        "selected value, without later overwrite or receiver escape "
                        "before normal constructor return. "
                        + "; ".join(assumptions), statement,
                    )
                    continue

            root = target
            while isinstance(root, (ast.Attribute, ast.Subscript)):
                root = root.value
            if isinstance(root, ast.Name) and _protected_state(
                frame.values.get(root.id)
            ):
                frame.unknown("callable_instance_state_write_unproven", statement)
            if frame.related(statement) or _tracked(result):
                frame.unknown("unsupported_assignment", statement)
            path = ast.unparse(target)
            frame.invalidate_facts(path, descendants=True)
            continue
        if isinstance(frame.values.get(target.id), _LocalFunction):
            frame.unknown("local_callable_rebinding", statement)
        if isinstance(result, _Value) and result.tracked and result.consumed:
            frame.proof.record_consumed_value(result)
            frame.proof.handled(
                frame.function, "consumed_value",
                "The selected value was consumed by a supported exact operation.",
                statement,
            )
        frame.bind_local(target.id, result)
