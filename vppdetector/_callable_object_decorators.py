## @package vppdetector._callable_object_decorators
#  Source proofs for supported callable-object decorators.
#  为受支持的可调用对象装饰器提供源码证明。

"""Small source proofs for callable-object decorators that preserve functions."""

from __future__ import annotations

import ast
import copy
import hashlib
from pathlib import Path

from ._program_facts import identity_from_target


## Compare a source node with an expected syntax fragment
## 比较源码节点与预期语法片段
#
#  @param node AST node or source expression being analyzed.
#  @param source Library source directory, file, or source context.
#  @return Result of the `_same` operation.
def _same(node, source):
    try:
        expected = ast.parse(source).body
    except SyntaxError:
        return False
    return ast.dump(ast.Module(body=[node], type_ignores=[]), include_attributes=False) == ast.dump(
        ast.Module(body=expected, type_ignores=[]), include_attributes=False
    )


## Resolve one source AST node of the requested type
## 解析指定类型的源码AST节点
#
#  @param context Reusable analysis context for the selected source snapshot.
#  @param identity Source-level identity used for lookup.
#  @param node_type AST node class required for the lookup.
#  @return Result of the `_source_node` operation.
def _source_node(context, identity, node_type):
    candidates = [
        item for item in context.index.functions
        if item.identity.module == identity.module
        and item.identity.qualname == identity.qualname
        and (identity.file_path is None or item.identity.file_path == identity.file_path)
        and (not identity.lineno or item.identity.lineno == identity.lineno)
        and isinstance(item.node, node_type)
    ]
    return candidates[0] if len(candidates) == 1 else None


## Prove a source callable-object decorator preserves a function object
## 证明源码可调用对象装饰器保留函数对象身份
#
#  @param context Reusable analysis context for the selected source snapshot.
#  @param analysis PCResolve analysis result being validated or consumed.
#  @param function Indexed source function under analysis.
#  @param fact Producer fact being validated or interpreted.
#  @return Validated identity-preserving decorator fact, or None when evidence is incomplete.
def source_callable_object_decorator_binding(context, analysis, function, fact):
    decorators = function.node.decorator_list
    if (len(decorators) != 1 or not isinstance(decorators[0], ast.Attribute)
            or not isinstance(decorators[0].value, ast.Name)):
        return None
    decorator = decorators[0]
    alias, decorator_name = decorator.value.id, decorator.attr
    imports = context.index.imports.get(function.identity.module, {})
    module = imports.get(alias)
    if not isinstance(module, str) or not module:
        return None

    expression = fact.get('expression')
    if (identity_from_target(fact.get('function')) != function.identity
            or fact.get('identity_status') not in ('preserved', 'unknown')
            or fact.get('basis') != 'source_snapshot'
            or fact.get('completion') != 'normal_return'
            or fact.get('runtime_target_confirmed') is not False
            or not isinstance(expression, dict)
            or expression.get('file_path') != str(function.identity.file_path)
            or any(expression.get(key) != getattr(decorator, key) for key in (
                'lineno', 'col_offset', 'end_lineno', 'end_col_offset'))):
        return None

    hashes = analysis.inputs.get('sha256', {})
    fact_hashes = fact.get('source_hashes')
    if (not isinstance(hashes, dict) or not isinstance(fact_hashes, dict)
            or not fact_hashes
            or any(hashes.get(path) != digest for path, digest in fact_hashes.items())):
        return None
    module_paths = {identity.file_path for identity in context.index.classes
                    if identity.module == module and identity.file_path is not None}
    if not module_paths:
        return None
    helper_path = next((path for path in module_paths if str(path) in hashes), None)
    if helper_path is None or str(function.identity.file_path) not in hashes:
        return None
    raw_target = fact.get('target')
    target = identity_from_target(raw_target) if raw_target is not None else None
    if target is not None and (target.file_path is None
            or target.file_path.resolve() != helper_path.resolve()):
        return None

    try:
        for path, digest in hashes.items():
            actual = hashlib.sha256(
                Path(path).read_text(encoding='utf-8-sig').encode('utf-8')).hexdigest()
            if actual != digest:
                return None
        owner_tree = ast.parse(function.identity.file_path.read_text(encoding='utf-8-sig'))
        helper_tree = ast.parse(helper_path.read_text(encoding='utf-8-sig'))
    except (OSError, UnicodeError, SyntaxError, RecursionError):
        return None

    def top_level_binding(name):
        return [node for node in owner_tree.body if name in _bound_names(node)]

    import_bindings = [node for node in owner_tree.body
                       if isinstance(node, (ast.Import, ast.ImportFrom))
                       and alias in _bound_names(node)]
    if len(import_bindings) != 1 or top_level_binding(alias) != import_bindings:
        return None

    assignments = []
    for statement in helper_tree.body:
        if not isinstance(statement, ast.Assign):
            continue
        targets = [node for target_node in statement.targets
                   for node in ast.walk(target_node) if isinstance(node, ast.Name)]
        if any(node.id == decorator_name for node in targets):
            assignments.append(statement)
    if len(assignments) != 1:
        return None
    assignment = assignments[0]
    value = assignment.value
    if (not isinstance(value, ast.Call) or not isinstance(value.func, ast.Name)
            or value.args or value.keywords):
        return None
    class_name = value.func.id
    if any(decorator_name in _bound_names(node) for node in helper_tree.body
           if node is not assignment):
        return None

    classes = [node for node in helper_tree.body
               if isinstance(node, ast.ClassDef) and node.name == class_name]
    if len(classes) != 1:
        return None
    decorator_class = classes[0]
    if (decorator_class.decorator_list or len(decorator_class.bases) != 1
            or not isinstance(decorator_class.bases[0], ast.Name)):
        return None
    if any(class_name in _bound_names(node) for node in helper_tree.body
           if node is not assignment and node is not decorator_class):
        return None
    base_name = decorator_class.bases[0].id
    bases = [node for node in helper_tree.body
             if isinstance(node, ast.ClassDef) and node.name == base_name]
    if len(bases) != 1:
        return None
    base_class = bases[0]

    def call_method(cls):
        methods = [node for node in cls.body
                   if isinstance(node, ast.FunctionDef) and node.name == '__call__']
        return methods[0] if len(methods) == 1 and not methods[0].decorator_list else None

    def normalized(method):
        arguments = method.args.posonlyargs + method.args.args
        if (len(arguments) != 2 or method.args.kwonlyargs or method.args.vararg
                or method.args.kwarg or method.args.defaults or method.args.kw_defaults):
            return None
        names = {arguments[0].arg: 'self', arguments[1].arg: 'value'}

        class Rename(ast.NodeTransformer):
            def visit_Name(self, node):
                if node.id in names:
                    node.id = names[node.id]
                return node

            def visit_arg(self, node):
                if node.arg in names:
                    node.arg = names[node.arg]
                return node

        normalized_method = Rename().visit(ast.fix_missing_locations(ast.Module(
            body=[copy.deepcopy(method)], type_ignores=[])))
        return normalized_method.body[0]

    child_call, base_call = call_method(decorator_class), call_method(base_class)
    if child_call is None or base_call is None:
        return None
    inspect_aliases = [name for name, imported in context.index.imports.get(module, {}).items()
                       if imported == 'inspect']
    if len(inspect_aliases) != 1:
        return None
    inspect_alias = inspect_aliases[0]
    expected_base = ast.parse(f'''def __call__(self, value):
    if value.__doc__:
        value.__doc__ = {inspect_alias}.cleandoc(value.__doc__) % self.params
    return value
''').body[0]
    expected_child = ast.parse('''def __call__(self, value):
    super().__call__(value)
    if isinstance(value, type) and value.__init__ != object.__init__:
        self(value.__init__)
    return value
''').body[0]
    if (ast.dump(normalized(base_call), include_attributes=False)
            != ast.dump(expected_base, include_attributes=False)
            or ast.dump(normalized(child_call), include_attributes=False)
            != ast.dump(expected_child, include_attributes=False)):
        return None
    inspect_imports = [node for node in helper_tree.body if isinstance(node, ast.Import)
                       and any(item.name == 'inspect'
                               and (item.asname or item.name) == inspect_alias
                               for item in node.names)]
    if (any(name in _bound_names(node) for node in helper_tree.body
            for name in ('super', 'isinstance', 'type', 'object'))
            or len(inspect_imports) != 1
            or any(inspect_alias in _bound_names(node) for node in helper_tree.body
                   if node not in inspect_imports)):
        return None

    return {
        'assumptions': ('source_snapshot_bindings_hold',
                        'standard_builtin_namespace_preserved',
                        'standard_library_inspect_binding',
                        'no_external_monkeypatch_or_import_hook',
                        'module_initialization_completed_before_query'),
        'source_hashes': fact_hashes,
        'decorator_target': fact.get('target'),
        'returned_object': 'original_function',
        'mutated_function_attribute': '__doc__',
    }


## Collect names bound by a source expression
## 收集源码表达式绑定的名称
#
#  @param node AST node or source expression being analyzed.
#  @return Result of the `_bound_names` operation.
def _bound_names(node):
    names = set()
    if isinstance(node, ast.Assign):
        targets = node.targets
    elif isinstance(node, (ast.AnnAssign, ast.NamedExpr)):
        targets = [node.target]
    elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        return {node.name}
    elif isinstance(node, ast.Import):
        return {alias.asname or alias.name.partition(".")[0] for alias in node.names}
    elif isinstance(node, ast.ImportFrom):
        return {alias.asname or alias.name for alias in node.names}
    else:
        return names
    for target in targets:
        names.update(child.id for child in ast.walk(target) if isinstance(child, ast.Name))
    return names
