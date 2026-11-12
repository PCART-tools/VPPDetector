## @package vppdetector._context_manager_propagation
#  Validate bounded generator context-manager propagation.
#  校验有界的生成器上下文管理器异常传播路径。

"""Validate a narrow source proof that a generator context manager rethrows."""

from __future__ import annotations

import ast
import hashlib

from ._program_facts import identity_from_target


## Convert source coordinates into a validated source span
## 将源码坐标转换为经过校验的源码范围
#
#  @param node AST node or source expression being analyzed
#  @return Result of the `_span` operation
def _span(node):
    return (node.lineno, node.col_offset, node.end_lineno, node.end_col_offset)


## Validate a source fact that a bounded generator manager restores state and rethrows
## 校验有界生成器管理器恢复状态并重新抛出的源码事实
#
#  @param context Reusable analysis context for the selected source snapshot
#  @param analysis PCResolve analysis result being validated or consumed
#  @param caller Source identity of the calling function
#  @param statement Value named `statement` supplied by the enclosing analysis
#  @return Validated manager identity and assumptions, or None when evidence is incomplete
def rethrows_with_body(context, analysis, caller, statement):
    if (not isinstance(statement, ast.With) or len(statement.items) != 1
            or statement.items[0].optional_vars is not None):
        return None
    manager = statement.items[0].context_expr
    if not isinstance(manager, ast.Call):
        return None

    with_id = '%s:%s:%s:%s:%s' % (
        caller.identity.file_path, statement.lineno, statement.col_offset,
        statement.end_lineno, statement.end_col_offset)
    summaries = [item for item in analysis.functions
                 if item.get('function', {}).get('module') == caller.identity.module
                 and item.get('function', {}).get('qualname') == caller.identity.qualname
                 and item.get('function', {}).get('file_path') == str(caller.identity.file_path)]
    records = [record for summary in summaries for record in summary.get('context_managers', ())
               if record.get('with_id') == with_id and record.get('item_index') == 0]
    if len(records) != 1:
        return None
    record = records[0]
    if (record.get('basis') != 'source_snapshot'
            or record.get('runtime_target_confirmed') is not False
            or record.get('context_expression', {}).get('source_text') != ast.unparse(manager)
            or 'source_snapshot_bindings_hold' not in record.get('assumptions', ())):
        return None
    effect = record.get('bounded_temporary_receiver_effects')
    if (not isinstance(effect, dict)
            or effect.get('kind') != 'bounded_temporary_receiver_attributes'
            or effect.get('restored_on_all_exits') is not True
            or effect.get('body_exception_behavior') != 'propagates_if_cleanup_completes'
            or effect.get('runtime_protocol_confirmed') is not False
            or not isinstance(effect.get('attributes'), (list, tuple))
            or not effect['attributes']
            or any(not isinstance(name, str) or not name.isidentifier()
                   for name in effect['attributes'])
            or not isinstance(effect.get('assumptions'), (list, tuple))
            or not {'standard_library_contextmanager_protocol',
                    'source_snapshot_bindings_hold',
                    'no_external_monkeypatch_or_import_hook'}.issubset(
                        set(effect['assumptions']))):
        return None
    manager_identity = identity_from_target(effect.get('manager'))
    # A bounded effect models __enter__ directly, so its record has no enter target.
    # 有界效果直接建模__enter__，因此记录中不会包含enter目标。
    if manager_identity is None or manager_identity.file_path is None:
        return None
    helper = context.index.find(manager_identity)
    if helper is None or not isinstance(helper.node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return None
    source_hashes = analysis.inputs.get('sha256', {})
    supporting_hashes = analysis.inputs.get('supporting_source_sha256', {})
    if not isinstance(source_hashes, dict) or not isinstance(supporting_hashes, dict):
        return None
    available_hashes = {**source_hashes, **supporting_hashes}
    fact_hashes = effect.get('source_hashes')
    if (not isinstance(fact_hashes, dict) or not fact_hashes
            or any(available_hashes.get(path) != digest
                   for path, digest in fact_hashes.items())):
        return None
    path = str(manager_identity.file_path)
    if path not in available_hashes:
        return None
    try:
        text = manager_identity.file_path.read_text(encoding='utf-8-sig')
    except (OSError, UnicodeError):
        return None
    normalized = text.replace('\r\n', '\n').replace('\r', '\n').encode('utf-8')
    digest = hashlib.sha256(normalized).hexdigest()
    if available_hashes[path] != digest or fact_hashes.get(path) != digest:
        return None
    evidence = effect.get('evidence')
    invocation = evidence.get('invocation') if isinstance(evidence, dict) else None
    if (not isinstance(invocation, dict)
            or invocation.get('file_path') != str(caller.identity.file_path)
            or _span(statement.items[0].context_expr) != (
                invocation.get('lineno'), invocation.get('col_offset'),
                invocation.get('end_lineno'), invocation.get('end_col_offset'))):
        return None
    transient_attributes = set(effect['attributes'])
    receiver_parameter = effect.get('receiver_parameter')
    for node in ast.walk(ast.Module(body=statement.body, type_ignores=[])):
        if isinstance(node, ast.Attribute) and node.attr in transient_attributes:
            return None
        if (isinstance(node, ast.Attribute) and node.attr == '__dict__'
                and isinstance(node.value, ast.Name)
                and node.value.id == receiver_parameter):
            return None
        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                and node.func.id in ('getattr', 'hasattr', 'setattr', 'delattr')
                and len(node.args) >= 2 and isinstance(node.args[1], ast.Constant)
                and node.args[1].value in transient_attributes):
            return None

    return {
        'with_id': with_id,
        'manager': manager_identity,
        'source_hash': digest,
        'attributes': tuple(sorted(transient_attributes)),
        'assumptions': tuple(effect['assumptions']),
    }
