"""Read source exception translations inside an otherwise closed decorator proof."""

from __future__ import annotations

import ast

from pcresolve.effect_facts import builtin_exception_translation

from ._program_facts import identity_from_target

_FIELDS = ('lineno', 'col_offset', 'end_lineno', 'end_col_offset')


def _matches(record, identity, node):
    return (isinstance(record, dict) and record.get('file_path') == str(identity.file_path)
            and all(type(record.get(key)) is int and record[key] == getattr(node, key)
                    for key in _FIELDS))


def exception_raise_binding(context, fact, effect):
    """Validate the reached raise and any exception-only handler/source premise."""
    identity = identity_from_target(effect.get('function'))
    function = context.index.find(identity) if identity is not None else None
    if function is None:
        return False
    nodes = list(ast.walk(function.node))
    raised = [node for node in nodes if isinstance(node, ast.Raise)
              and _matches(effect.get('evidence'), identity, node)]
    if len(raised) != 1:
        return False
    raised = raised[0]
    if (not isinstance(raised.exc, ast.Call) or not isinstance(raised.exc.func, ast.Name)
            or raised.exc.func.id != effect.get('target')):
        return False
    parents = {child: node for node in nodes for child in ast.iter_child_nodes(node)}
    current = raised
    handler = None
    while current in parents:
        current = parents[current]
        if isinstance(current, ast.ExceptHandler):
            handler = current
            break
    translation = effect.get('exception_translation')
    if translation is None:
        return (handler is None and (raised.cause is None
                or isinstance(raised.cause, ast.Constant) and raised.cause.value is None))
    if not isinstance(translation, dict) or handler is None:
        return False
    source_try = parents.get(handler)
    shape = builtin_exception_translation(handler)
    if (shape is None or not isinstance(source_try, ast.Try)
            or source_try.orelse or source_try.finalbody
            or not 1 <= len(source_try.handlers) <= 4
            or any(translation.get(key) != value for key, value in shape.items())
            or translation.get('raised_type') != effect.get('target')
            or translation.get('completion') != 'exceptional_exit_only'
            or translation.get('runtime_exception_observed') is not False
            or 'builtin_exception_handler_semantics' not in fact.get('assumptions', ())
            or not _matches(translation.get('handler'), identity, handler)
            or not _matches(translation.get('try'), identity, source_try)
            or not isinstance(effect.get('conditions'), (list, tuple))):
        return False
    return any(isinstance(condition, dict)
               and condition.get('caught_types') == shape['caught_types']
               and _matches(condition.get('exception_handler'), identity, handler)
               for condition in effect['conditions'])
