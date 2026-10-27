## @package vppdetector._context_manager_propagation
#  Validate bounded generator context-manager propagation.
#  校验有界的生成器上下文管理器异常传播路径。

"""Validate a narrow source proof that a generator context manager rethrows."""

from __future__ import annotations

import ast
import hashlib

from .models import FunctionIdentity


## Convert source coordinates into a validated source span
## 将源码坐标转换为经过校验的源码范围
#
#  @param node AST node or source expression being analyzed.
#  @return Result of the `_span` operation.
def _span(node):
    return (node.lineno, node.col_offset, node.end_lineno, node.end_col_offset)


## Check whether a statement tree contains an exception handler
## 检查语句树中是否包含异常处理器
#
#  @param node AST node or source expression being analyzed.
#  @return Result of the `_contains_except` operation.
def _contains_except(node):
    return any(isinstance(child, ast.ExceptHandler) for child in ast.walk(node))


## Prove this exact ``with`` uses a transparent contextlib generator
## 证明该with语句使用透明的contextlib生成器上下文管理器
#
#  @param context Reusable analysis context for the selected source snapshot.
#  @param analysis PCResolve analysis result being validated or consumed.
#  @param caller Source identity of the calling function.
#  @param statement Value named `statement` supplied by the enclosing analysis.
#  @return Result of the `rethrows_with_body` operation.
def rethrows_with_body(context, analysis, caller, statement):
    if (not isinstance(statement, ast.With) or len(statement.items) != 1
            or statement.items[0].optional_vars is not None):
        return None
    manager = statement.items[0].context_expr
    if (not isinstance(manager, ast.Call)
            or len(manager.args) != 1 or not isinstance(manager.args[0], ast.Name)
            or not manager.args[0].id == 'self'
            or not isinstance(manager.func, ast.Attribute)
            or manager.func.attr != '_setattr_cm'
            or not isinstance(manager.func.value, ast.Name)
            or manager.func.value.id != 'cbook'
            or len(manager.keywords) != 1
            or manager.keywords[0].arg != 'eventson'
            or not isinstance(manager.keywords[0].value, ast.Constant)
            or manager.keywords[0].value.value is not False):
        return None

    # The transient eventson assignment must not influence the guarded body.
    # 临时eventson赋值不能影响受守卫控制的函数体。
    if any(isinstance(node, ast.Attribute) and node.attr == 'eventson'
           for node in ast.walk(ast.Module(body=statement.body, type_ignores=[]))):
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

    calls = [edge for edge in analysis.calls
             if str(edge.caller.file_path) == str(caller.identity.file_path)
             and edge.lineno == manager.lineno and edge.col_offset == manager.col_offset
             and edge.end_lineno == manager.end_lineno
             and edge.end_col_offset == manager.end_col_offset
             and edge.callee_name == 'cbook._setattr_cm']
    if len(calls) != 1:
        return None
    imports = [source for source in calls[0].receiver_sources
               if source.get('kind') == 'import' and source.get('source') == 'matplotlib.cbook'
               and source.get('relation') == 'direct' and source.get('import_modified') is False]
    if len(imports) != 1:
        return None

    helper = context.index.resolve_imported(FunctionIdentity('matplotlib.cbook', '_setattr_cm'))
    if helper is None or helper.node.decorator_list == []:
        return None
    decorator = helper.node.decorator_list
    if (len(decorator) != 1 or not isinstance(decorator[0], ast.Attribute)
            or decorator[0].attr != 'contextmanager'
            or not isinstance(decorator[0].value, ast.Name)):
        return None
    alias = decorator[0].value.id
    if context.index.imports.get(helper.identity.module, {}).get(alias) != 'contextlib':
        return None

    # PCResolve's namespace proof excludes rebinding/monkeypatching of the
    # imported stdlib decorator throughout the indexed source package.
    # PCResolve的命名空间证明确认整个索引源码包内没有重绑定或猴子补丁修改该标准库装饰器。
    try:
        from pcresolve._contextmanager_namespace import _namespace
        if not _namespace(context.adapter._analyzer):
            return None
    except (ImportError, AttributeError, ValueError):
        return None

    source_hashes = analysis.inputs.get('sha256', {})
    path = str(helper.identity.file_path)
    if path not in source_hashes:
        return None
    try:
        text = helper.identity.file_path.read_text(encoding='utf-8-sig')
    except (OSError, UnicodeError):
        return None
    normalized = text.replace('\r\n', '\n').replace('\r', '\n').encode('utf-8')
    digest = hashlib.sha256(normalized).hexdigest()
    if source_hashes[path] != digest:
        return None

    yields = [node for node in ast.walk(helper.node) if isinstance(node, ast.Yield)]
    tries = [node for node in ast.walk(helper.node) if isinstance(node, ast.Try)
             and any(yield_node in ast.walk(node) for yield_node in yields)]
    if (len(yields) != 1 or len(tries) != 1 or not tries[0].finalbody
            or tries[0].handlers or tries[0].orelse
            or _contains_except(helper.node)
            or any(isinstance(node, (ast.Return, ast.Raise)) for node in tries[0].finalbody)):
        return None

    # A try/finally rethrows an exception injected at yield unless an except
    # handler or a return in cleanup suppresses it. Neither is present.
    # yield处注入的异常会由try/finally重新抛出，除非except处理器或清理阶段的return将其抑制；当前两者均不存在。
    return {
        'with_id': with_id,
        'manager': FunctionIdentity('matplotlib.cbook', '_setattr_cm'),
        'source_hash': source_hashes[path],
        'assumptions': ('source_snapshot_bindings_hold', 'standard_contextlib_contextmanager',
                        'no_external_monkeypatch_or_import_hook'),
    }
