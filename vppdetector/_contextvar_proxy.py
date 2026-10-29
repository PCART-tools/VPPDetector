## @package vppdetector._contextvar_proxy
#  Resolve false predicates for source-backed ContextVar proxies.
#  解析源码定义的ContextVar代理对象为假的条件事实。

"""Recognize an unbound ContextVar proxy without naming a framework."""

from __future__ import annotations

import ast
import hashlib
import io
import importlib.machinery
import tokenize
from pathlib import Path

from .models import FunctionIdentity, SourceSpan
from .source import module_name_for_path

_FIELDS = ('lineno', 'col_offset', 'end_lineno', 'end_col_offset')


## Read one source module from the indexed dependency snapshot
## 从已索引依赖快照中读取一个源码模块
#
#  @param context Reusable analysis context for the selected source snapshot.
#  @param module Dotted source module identity.
#  @return Unique module path and parsed tree, or `(None, None)`.
def _module_tree(context, module):
    paths = [path for path in context.index.files
             if module_name_for_path(path, context.index.source.import_roots) == module]
    if not paths:
        parts = module.split('.')
        for root in context.index.source.import_roots:
            candidates = (Path(root).joinpath(*parts).with_suffix('.py'),
                          Path(root).joinpath(*parts, '__init__.py'))
            paths.extend(path for path in candidates if path.is_file())
    paths = list(dict.fromkeys(path.resolve() for path in paths))
    if len(paths) != 1:
        return None, None
    try:
        with tokenize.open(paths[0]) as stream:
            return paths[0], ast.parse(stream.read(), filename=str(paths[0]))
    except (OSError, UnicodeError, SyntaxError, RecursionError):
        return None, None


## Resolve one unambiguous top-level source assignment
## 解析唯一的模块级源码赋值
#
#  @param tree Parsed module source.
#  @param name Module-level name being resolved.
#  @return Assignment value or `None` when the name is missing or rebound.
def _assignment(tree, name):
    matches = []
    for statement in tree.body:
        targets = (statement.targets if isinstance(statement, ast.Assign)
                   else [statement.target] if isinstance(statement, ast.AnnAssign) else [])
        if any(isinstance(target, ast.Name) and target.id == name for target in targets):
            matches.append(statement.value)
    return matches[0] if len(matches) == 1 else None


## Locate one direct module assignment and its source range
## 定位唯一的模块级赋值及其源码范围
#
#  @param tree Parsed module source.
#  @param name Module-level name being resolved.
#  @return Unique assignment statement, or `None` when ambiguous.
def _assignment_statement(tree, name):
    matches = []
    for statement in tree.body:
        targets = (statement.targets if isinstance(statement, ast.Assign)
                   else [statement.target] if isinstance(statement, ast.AnnAssign) else [])
        if any(isinstance(target, ast.Name) and target.id == name for target in targets):
            matches.append(statement)
    return matches[0] if len(matches) == 1 else None


## Validate raw source hashes captured by a bounded package scan
## 校验有界包扫描时记录的原始源码摘要
#
#  @param source_hashes Absolute source paths mapped to SHA-256 digests.
#  @return True only while every source file still matches its captured digest.
def _raw_source_hashes_match(source_hashes):
    if not isinstance(source_hashes, dict) or not source_hashes:
        return False
    try:
        return all(isinstance(path, str) and isinstance(digest, str)
                   and len(digest) == 64
                   and hashlib.sha256(Path(path).read_bytes()).hexdigest() == digest
                   for path, digest in source_hashes.items())
    except OSError:
        return False


## Count static module bindings unless dynamic namespace writes are present
## 在不存在动态命名空间写入时统计模块级静态绑定数量
#
#  @param tree Parsed module source.
#  @param name Module-level name being checked.
#  @return Binding count, or `None` when dynamic writes prevent proof.
def _module_binding_count(tree, name):
    bindings = []
    pending = list(tree.body)
    while pending:
        current = pending.pop()
        if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            if current.name == name:
                bindings.append(current)
            if any(isinstance(item, ast.Global) and name in item.names
                   for item in ast.walk(current)):
                return None
            continue
        if isinstance(current, ast.Lambda):
            continue
        if isinstance(current, ast.Import):
            bindings.extend(alias for alias in current.names
                            if (alias.asname or alias.name.split('.')[0]) == name)
        elif isinstance(current, ast.ImportFrom):
            bindings.extend(alias for alias in current.names
                            if alias.name != '*' and (alias.asname or alias.name) == name)
        elif (isinstance(current, ast.Name) and current.id == name
              and isinstance(current.ctx, (ast.Store, ast.Del))):
            bindings.append(current)
        if (isinstance(current, ast.Call) and isinstance(current.func, ast.Name)
                and current.func.id in ('exec', 'eval', 'globals')):
            return None
        pending.extend(ast.iter_child_nodes(current))
    return len(bindings)


## Check whether package initialization can set a context variable
## 检查包初始化及其可解析调用链是否会设置ContextVar
#
#  @param context Reusable analysis context for the selected source snapshot.
#  @param packages Top-level package names whose initialization is analyzed.
#  @return True when a reachable `.set` call is found or source is incomplete.
def _package_sets_contextvar(context, packages, contextvar_identity=None):
    modules = {}
    source_hashes = {}

    # Parse each source file from the exact bytes captured for its proof digest.
    def read_module(path):
        resolved = Path(path).resolve()
        try:
            raw = resolved.read_bytes()
            encoding, _ = tokenize.detect_encoding(io.BytesIO(raw).readline)
            text = raw.decode(encoding).replace('\r\n', '\n').replace('\r', '\n')
            tree = ast.parse(text, filename=str(resolved))
        except (OSError, UnicodeError, SyntaxError, LookupError,
                RecursionError, tokenize.TokenError):
            return None
        source_hashes[str(resolved)] = hashlib.sha256(raw).hexdigest()
        return tree

    for package in packages:
        found_package = False
        for root in context.index.source.import_roots:
            package_root = Path(root).joinpath(*package.split('.'))
            paths = list(package_root.rglob('*.py')) if package_root.is_dir() else []
            package_module = Path(root).joinpath(*package.split('.')).with_suffix('.py')
            if package_module.is_file():
                paths.append(package_module)
            found_package |= bool(paths)
            for path in paths:
                resolved = path.resolve()
                module = module_name_for_path(resolved, context.index.source.import_roots)
                if not module:
                    return True
                tree = read_module(resolved)
                if tree is None:
                    return True
                previous = modules.get(module)
                if previous is not None and previous[0] != resolved:
                    return True
                modules[module] = (resolved, tree)
        if not found_package:
            return True

    # Include already indexed source dependencies so imported initializers can
    # be followed even when they live outside the proxy's top-level package.
    for path in context.index.files:
        resolved = Path(path).resolve()
        module = module_name_for_path(resolved, context.index.source.import_roots)
        if not module:
            return True
        previous = modules.get(module)
        if previous is not None:
            if previous[0] != resolved:
                return True
            continue
        tree = read_module(resolved)
        if tree is None:
            return True
        modules[module] = (resolved, tree)

    functions = {}
    classes = {}
    imports = {}

    def add_module(module, path, tree):
        modules[module] = (path, tree)
        imports[module] = _module_imports(context, module, path, tree)
        for item in tree.body:
            if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                functions[(module, item.name)] = item
                if isinstance(item, ast.ClassDef):
                    classes[(module, item.name)] = item

    for module, (path, tree) in modules.items():
        imports[module] = _module_imports(context, module, path, tree)
        for item in tree.body:
            if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                functions[(module, item.name)] = item
                if isinstance(item, ast.ClassDef):
                    classes[(module, item.name)] = item

    def load_target_module(target):
        if not isinstance(target, str):
            return False
        parts = target.split('.')
        for end in range(len(parts), 0, -1):
            module = '.'.join(parts[:end])
            if module in modules:
                return True
            paths = []
            for root in context.index.source.import_roots:
                stem = Path(root).joinpath(*module.split('.'))
                paths.extend(path.resolve() for path in
                    (stem.with_suffix('.py'), stem / '__init__.py') if path.is_file())
            paths = list(dict.fromkeys(paths))
            if not paths:
                continue
            if len(paths) != 1 or len(modules) >= 256:
                return False
            tree = read_module(paths[0])
            if tree is None:
                return False
            add_module(module, paths[0], tree)
            return True
        return False

    def module_is_available(target):
        parts = target.split('.')
        for root in context.index.source.import_roots:
            base = Path(root)
            for end in range(1, len(parts) + 1):
                stem = base.joinpath(*parts[:end])
                if (stem.with_suffix('.py').is_file()
                        or (stem / '__init__.py').is_file()):
                    return True
                if any(stem.with_suffix(suffix).is_file()
                       for suffix in importlib.machinery.EXTENSION_SUFFIXES):
                    return True
        return False

    def import_error_is_caught(module, call):
        source = modules.get(module)
        if source is None:
            return False
        parents = {child: parent for parent in ast.walk(source[1])
                   for child in ast.iter_child_nodes(parent)}
        current = call
        while current in parents:
            current = parents[current]
            if isinstance(current, ast.Try) and any(
                    call in list(ast.walk(item)) for item in current.body):
                return any(isinstance(handler.type, ast.Name)
                           and handler.type.id == 'ImportError'
                           or isinstance(handler.type, ast.Tuple)
                           and any(isinstance(item, ast.Name)
                                   and item.id == 'ImportError'
                                   for item in handler.type.elts)
                           for handler in current.handlers)
        return False

    reached = set()

    def imported_target(module, expression):
        if isinstance(expression, ast.Name):
            return imports[module].get(expression.id, module + '.' + expression.id)
        if isinstance(expression, ast.Attribute):
            parent = imported_target(module, expression.value)
            return parent + '.' + expression.attr if isinstance(parent, str) else None
        return None

    def local_function(module, name):
        return functions.get((module, name))

    def function_target(target):
        if not isinstance(target, str):
            return None
        parts = target.split('.')
        for end in range(len(parts), 0, -1):
            module = '.'.join(parts[:end])
            if module not in modules:
                continue
            qualname = parts[end:]
            if len(qualname) == 1:
                function = functions.get((module, qualname[0]))
                if function is not None:
                    return function
                class_node = classes.get((module, qualname[0]))
                if class_node is not None:
                    initializers = [item for item in class_node.body
                        if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))
                        and item.name == '__init__']
                    return initializers[0] if len(initializers) == 1 else None
            if len(qualname) == 2:
                class_node = classes.get((module, qualname[0]))
                if class_node is not None and qualname[1] == '__init__':
                    methods = [item for item in class_node.body
                               if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))
                               and item.name == '__init__']
                    return methods[0] if len(methods) == 1 else None
            return None
        return None

    def class_target(target):
        if not isinstance(target, str):
            return None
        parts = target.split('.')
        for end in range(len(parts), 0, -1):
            module = '.'.join(parts[:end])
            if module not in modules:
                load_target_module(module)
            if (module in modules and len(parts) == end + 1
                    and (module, parts[end]) in classes):
                return module, classes[(module, parts[end])]
        return None

    def constructor_is_inert(module, class_node, visited=None):
        visited = set() if visited is None else visited
        key = (module, class_node.name)
        if key in visited or class_node.decorator_list or any(
                item.arg == 'metaclass' for item in class_node.keywords):
            return False
        visited.add(key)
        methods = {item.name for item in class_node.body
                   if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))}
        if '__init__' in methods or '__new__' in methods:
            return False
        builtin_bases = {'bool', 'bytes', 'dict', 'float', 'frozenset', 'int', 'list',
                         'object', 'set', 'str', 'tuple'}
        for base in class_node.bases:
            target = imported_target(module, base)
            if (isinstance(base, ast.Name) and base.id in builtin_bases
                    and base.id not in imports[module]):
                continue
            resolved = class_target(target)
            if resolved is None or not constructor_is_inert(*resolved, visited):
                return False
        return True

    def literal_container(node):
        if isinstance(node, (ast.Constant, ast.NameConstant)):
            return True
        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            return all(literal_container(item) for item in node.elts)
        if isinstance(node, ast.Dict):
            return all(key is not None and literal_container(key)
                       and literal_container(value)
                       for key, value in zip(node.keys, node.values))
        return False

    def source_module(target):
        if not isinstance(target, str):
            return None
        parts = target.split('.')
        for end in range(len(parts), 0, -1):
            module = '.'.join(parts[:end])
            if module in modules:
                return module
        return None

    def references_contextvar(module, node):
        if contextvar_identity is None:
            return False
        for item in ast.walk(node):
            if isinstance(item, ast.Name):
                if (module, item.id) == contextvar_identity:
                    return True
                if imports[module].get(item.id) == '.'.join(contextvar_identity):
                    return True
            elif isinstance(item, ast.Attribute):
                target = imported_target(module, item)
                if target == '.'.join(contextvar_identity):
                    return True
        return False

    def reads_known_mapping(module, call):
        if (not isinstance(call.func, ast.Attribute)
                or call.func.attr not in {'get', 'items', 'keys', 'values'}):
            return False
        if (isinstance(call.func.value, ast.Call)
                and isinstance(call.func.value.func, ast.Name)
                and call.func.value.func.id in {'globals', 'locals'}
                and call.func.value.func.id not in imports[module]):
            return True
        if not isinstance(call.func.value, ast.Name):
            return False
        source = modules.get(module)
        if source is None:
            return False
        value = _assignment(source[1], call.func.value.id)
        return isinstance(value, ast.Dict)

    def scan(node, module, execute_definitions=False, contextvar_active=False):
        pending = [(node, module, execute_definitions, contextvar_active)]
        while pending:
            current, current_module, execute_current_definitions, active_contextvar = pending.pop()
            if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef)):
                expressions = (current.decorator_list + current.args.defaults
                               + [item for item in current.args.kw_defaults if item is not None])
                if execute_current_definitions:
                    arguments = (current.args.posonlyargs + current.args.args
                                 + current.args.kwonlyargs
                                 + ([current.args.vararg]
                                    if current.args.vararg is not None else [])
                                 + ([current.args.kwarg] if current.args.kwarg is not None else []))
                    expressions.extend(item.annotation for item in arguments
                                       if item.annotation is not None)
                    if current.returns is not None:
                        expressions.append(current.returns)
                pending.extend((item, current_module, execute_current_definitions,
                                active_contextvar)
                               for item in expressions)
                continue
            if isinstance(current, ast.Lambda):
                pending.extend((item, current_module, execute_current_definitions,
                                active_contextvar)
                    for item in current.args.defaults
                    + [item for item in current.args.kw_defaults if item is not None])
                continue
            if isinstance(current, ast.ClassDef):
                pending.extend((item, current_module, execute_current_definitions,
                                active_contextvar)
                    for item in current.decorator_list + current.bases + current.body)
                pending.extend((keyword.value, current_module, execute_current_definitions,
                                active_contextvar)
                               for keyword in current.keywords)
                continue
            if (isinstance(current, ast.Call) and isinstance(current.func, ast.Attribute)
                    and current.func.attr in {'reset', 'set'}):
                if (active_contextvar or contextvar_identity is None
                        or references_contextvar(current_module, current.func.value)):
                    return True
                pending.extend((item, current_module, execute_current_definitions,
                                active_contextvar)
                               for item in ast.iter_child_nodes(current))
                continue
            if isinstance(current, ast.Call):
                target = imported_target(current_module, current.func)
                function = function_target(target)
                if (function is None and isinstance(current.func, ast.Name)
                        and current.func.id == '__import__'
                        and current.func.id not in imports[current_module]
                        and current.args and isinstance(current.args[0], ast.Constant)
                        and isinstance(current.args[0].value, str)):
                    imported_module = current.args[0].value
                    if not load_target_module(imported_module):
                        if (not module_is_available(imported_module)
                                and import_error_is_caught(current_module, current)):
                            pending.extend((item, current_module,
                                            execute_current_definitions,
                                            active_contextvar)
                                           for item in ast.iter_child_nodes(current))
                            continue
                        return True
                    imported_tree = modules[imported_module][1]
                    if scan(imported_tree, imported_module, True, active_contextvar):
                        return True
                    pending.extend((item, current_module, execute_current_definitions,
                                    active_contextvar)
                                   for item in ast.iter_child_nodes(current))
                    continue
                if (function is None and isinstance(current.func, ast.Name)
                        and target == current_module + '.' + current.func.id):
                    function = local_function(current_module, current.func.id)
                if function is None and load_target_module(target):
                    function = function_target(target)
                if function is None:
                    class_match = class_target(target)
                    arguments = current.args + [item.value for item in current.keywords]
                    if (class_match is not None
                            and constructor_is_inert(*class_match)
                            and all(literal_container(item) for item in arguments)):
                        pending.extend((item, current_module, execute_current_definitions,
                                        active_contextvar)
                                       for item in ast.iter_child_nodes(current))
                        continue
                if (function is None and (
                        any(references_contextvar(current_module, argument)
                            for argument in current.args)
                        or any(references_contextvar(current_module, keyword.value)
                               for keyword in current.keywords))):
                    return True
                if function is None and target != 'contextvars.ContextVar':
                    if reads_known_mapping(current_module, current):
                        pending.extend((item, current_module, execute_current_definitions,
                                        active_contextvar)
                                       for item in ast.iter_child_nodes(current))
                        continue
                    if (isinstance(current.func, ast.Name)
                            and current.func.id in {'classmethod', 'globals',
                                                    'isinstance', 'issubclass',
                                                    'locals', 'property', 'staticmethod'}
                            and current.func.id not in imports[current_module]):
                        pending.extend((item, current_module, execute_current_definitions,
                                        active_contextvar)
                                       for item in ast.iter_child_nodes(current))
                        continue
                    if (isinstance(current.func, ast.Attribute)
                            and current.func.attr == '__setattr__'
                            and isinstance(current.func.value, ast.Name)
                            and current.func.value.id == 'object'
                            and 'object' not in imports[current_module]):
                        pending.extend((item, current_module, execute_current_definitions,
                                        active_contextvar)
                                       for item in ast.iter_child_nodes(current))
                        continue
                    if (isinstance(current.func, ast.Name)
                                and current.func.id in {'eval', 'exec', '__import__'}
                                and current.func.id not in imports[current_module]):
                        return True
                    pending.extend((item, current_module, execute_current_definitions,
                                    active_contextvar)
                                   for item in ast.iter_child_nodes(current))
                    continue
                if function is not None:
                    target_module = source_module(target) or current_module
                    function_contextvar = (active_contextvar
                        or references_contextvar(current_module, current)
                        or references_contextvar(target_module, function))
                    key = (target, id(function), function_contextvar)
                    if key not in reached:
                        reached.add(key)
                        pending.extend((item, target_module, execute_current_definitions,
                                        function_contextvar)
                                       for item in function.body)
                        continue
            pending.extend((item, current_module, execute_current_definitions,
                            active_contextvar)
                           for item in ast.iter_child_nodes(current))
        return False

    for module, (_, tree) in tuple(modules.items()):
        if scan(tree, module, execute_definitions=True):
            return True
    return {'state': 'no_contextvar_write', 'source_hashes': source_hashes,
            'assumptions': ['source_snapshot_bindings_hold',
                            'no_external_monkeypatch_or_import_hook',
                            'all_relevant_import_source_is_available']}


## Resolve import aliases from the indexed module syntax
## 从已索引模块语法解析导入别名
#
#  @param context Reusable analysis context for the selected source snapshot.
#  @param module Dotted source module identity.
#  @param path Source file for the module.
#  @param tree Parsed module source.
#  @return Local names mapped to their canonical imported targets.
def _module_imports(context, module, path, tree):
    result = dict(context.index.imports.get(module, {}))
    from pcresolve.import_facts import resolve_relative_module

    for statement in tree.body:
        if isinstance(statement, ast.Import):
            for alias in statement.names:
                result[alias.asname or alias.name.split('.')[0]] = alias.name
        elif isinstance(statement, ast.ImportFrom):
            parent = resolve_relative_module(module, path.name == '__init__.py',
                                             statement.module, statement.level)
            for alias in statement.names:
                if alias.name != '*':
                    result[alias.asname or alias.name] = parent + '.' + alias.name
    return result


## Query a source class member through PCResolve
## 通过PCResolve查询源码类成员
#
#  @param context Reusable analysis context for the selected source snapshot.
#  @param module Source module containing the class.
#  @param qualname Fully qualified source class name.
#  @param member Class member whose binding is queried.
#  @param file_path Exact source file for the class identity.
#  @return PCResolve binding fact, or `None` when unavailable.
def _source_member_fact(context, module, qualname, member, file_path):
    try:
        return context.adapter.source_class_member_binding(module, qualname, member, file_path)
    except (OSError, UnicodeError, ValueError):
        return None


## Confirm a class member remains bound to its indexed source definition
## 确认类成员仍绑定到索引的源码定义
#
#  @param context Reusable analysis context for the selected source snapshot.
#  @param module Source module containing the class.
#  @param qualname Fully qualified source class name.
#  @param member Class member whose binding is queried.
#  @param file_path Exact source file for the class identity.
#  @return Fresh stable-binding fact, or None when the binding is unstable.
def _stable_source_member(context, module, qualname, member, file_path):
    fact = _source_member_fact(context, module, qualname, member, file_path)
    if (isinstance(fact, dict)
            and fact.get('schema_version') == 'source-class-member-binding-0.1'
            and fact.get('kind') == 'source_class_member_binding'
            and fact.get('status') == 'stable'
            and fact.get('class', {}).get('module') == module
            and fact.get('class', {}).get('qualname') == qualname
            and fact.get('member') == member
            and isinstance(fact.get('member_span'), dict)
            and all(type(fact['member_span'].get(key)) is int
                    for key in ('lineno', 'col_offset', 'end_lineno', 'end_col_offset'))
            and isinstance(fact.get('source_hashes'), dict)
            and fact.get('source_hashes')):
        return fact
    return None


## Detect early exits in a method's executable body
## 检查方法实际执行体中是否存在提前退出
#
#  @param statements Executable statements from one bounded source path.
#  @return True when a return or raise can bypass a required initialization.
def _has_execution_exit(statements):
    pending = list(statements)
    while pending:
        node = pending.pop()
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef,
                             ast.ClassDef, ast.Lambda)):
            continue
        if isinstance(node, (ast.Return, ast.Raise)):
            return True
        pending.extend(ast.iter_child_nodes(node))
    return False


## Prove that a proxy's bool descriptor returns its false fallback when unbound
## 证明代理对象未绑定时的bool描述符会返回false回退值
#
#  @param context Reusable analysis context for the selected source snapshot.
#  @param proxy_module Module containing the imported proxy class.
#  @param proxy_class Proxy class identity.
#  @param proxy_tree Parsed source for the proxy class module.
#  @return Source facts only for the validated false-fallback protocol.
def _proxy_bool_is_unbound_false(context, proxy_module, proxy_class, proxy_tree):
    proxy_path, proxy_tree = _module_tree(context, proxy_module)
    if proxy_path is None or proxy_tree is None:
        return False
    classes = [item for item in ast.walk(proxy_tree) if isinstance(item, ast.ClassDef)
               and item.lineno == proxy_class.lineno and item.name == proxy_class.qualname]
    if len(classes) != 1 or classes[0].keywords:
        return False
    class_node = classes[0]
    proxy_init_fact = _stable_source_member(
        context, proxy_module, proxy_class.qualname, '__init__', proxy_path)
    bool_fact = _source_member_fact(
        context, proxy_module, proxy_class.qualname, '__bool__', proxy_path)
    if (not proxy_init_fact
            or not isinstance(bool_fact, dict)
            or bool_fact.get('status') != 'stable'
            or bool_fact.get('member_kind') != 'assignment'
            or not isinstance(bool_fact.get('member_expression'), str)
            or not bool_fact.get('source_hashes')):
        return False
    try:
        bool_value = ast.parse(bool_fact['member_expression'], mode='eval').body
    except SyntaxError:
        return False
    if not isinstance(bool_value, ast.Call):
        return False
    descriptor = bool_value
    imports = _module_imports(context, proxy_module, proxy_path, proxy_tree)
    if any(_module_binding_count(proxy_tree, name) != 0
           for name in ('bool', 'isinstance', 'LookupError', 'RuntimeError', 'object')):
        return False
    descriptor_name = (descriptor.func.id if isinstance(descriptor.func, ast.Name) else None)
    descriptor_classes = [item for item in ast.walk(proxy_tree)
                          if isinstance(item, ast.ClassDef)
                          and item.name == descriptor_name]
    descriptor_class = descriptor_classes[0] if len(descriptor_classes) == 1 else None
    descriptor_init_fact = None
    descriptor_get_fact = None
    if descriptor_class is not None:
        if descriptor_class.keywords:
            return False
        descriptor_init_fact = _stable_source_member(
            context, proxy_module, descriptor_name, '__init__', proxy_path)
        descriptor_get_fact = _stable_source_member(
            context, proxy_module, descriptor_name, '__get__', proxy_path)
        if not descriptor_init_fact or not descriptor_get_fact:
            return False
    fallback = next((item.value for item in descriptor.keywords
                     if item.arg == 'fallback'), None)
    if (descriptor_name is None or descriptor_class is None
            or not descriptor.args or not isinstance(descriptor.args[0], ast.Name)
            or descriptor.args[0].id != 'bool'
            or not isinstance(fallback, ast.Lambda)
            or not isinstance(fallback.body, ast.Constant) or fallback.body.value is not False):
        return False
    init_methods = [item for item in descriptor_class.body
                    if isinstance(item, ast.FunctionDef) and item.name == '__init__']
    if (len(init_methods) != 1 or init_methods[0].decorator_list
            or _has_execution_exit(init_methods[0].body)):
        return False
    fallback_writes = [item for item in ast.walk(init_methods[0])
        if isinstance(item, (ast.Assign, ast.AnnAssign))
        and any(isinstance(target, ast.Attribute) and target.attr == 'fallback'
                and isinstance(target.value, ast.Name) and target.value.id == 'self'
                for target in (item.targets if isinstance(item, ast.Assign) else [item.target]))]
    if (len(fallback_writes) != 1
            or not isinstance(fallback_writes[0].value, ast.Name)
            or fallback_writes[0].value.id != 'fallback'):
        return False

    fallback_fact = (context.adapter.source_method_exception_fallback(
        proxy_module, descriptor_name, '__get__', proxy_path, 'RuntimeError')
        if descriptor_class is not None else None)
    instance_name = (fallback_fact.get('receiver_parameter')
                     if isinstance(fallback_fact, dict) else None)
    lookup_method_name = (fallback_fact.get('lookup_member')
                          if isinstance(fallback_fact, dict) else None)
    expected_protected_call = (ast.dump(ast.parse(
        f'{instance_name}._get_current_object()', mode='eval').body,
        include_attributes=False) if instance_name else None)
    expected_fallback = ast.dump(ast.parse(
        f'self.fallback({instance_name})', mode='eval').body,
        include_attributes=False) if instance_name else None
    expected_bound_fallback = ast.dump(ast.parse(
        f'self.fallback.__get__({instance_name}, owner)', mode='eval').body,
        include_attributes=False) if instance_name else None
    if (not isinstance(fallback_fact, dict)
            or fallback_fact.get('class', {}).get('module') != proxy_module
            or fallback_fact.get('class', {}).get('qualname') != descriptor_name
            or fallback_fact.get('protected_call') != expected_protected_call
            or not isinstance(fallback_fact.get('protected_span'), dict)
            or fallback_fact.get('fallback_expression') not in
               (expected_fallback, expected_bound_fallback)):
        return False
    proxy_init = next((item for item in class_node.body
                       if isinstance(item, ast.FunctionDef) and item.name == '__init__'), None)
    if (not isinstance(instance_name, str) or not isinstance(lookup_method_name, str)
            or proxy_init is None):
        return False
    contextvar_aliases = {name for name, target in imports.items()
                          if target == 'contextvars.ContextVar'}
    if (len(contextvar_aliases) != 1
            or _module_binding_count(proxy_tree, next(iter(contextvar_aliases))) != 1):
        return False
    local_name = proxy_init.args.args[1].arg if len(proxy_init.args.args) > 1 else None
    if local_name is None:
        return False
    contextvar_branches = [branch for branch in ast.walk(proxy_init)
        if isinstance(branch, ast.If) and isinstance(branch.test, ast.Call)
        and isinstance(branch.test.func, ast.Name) and branch.test.func.id == 'isinstance'
        and len(branch.test.args) == 2 and isinstance(branch.test.args[0], ast.Name)
        and branch.test.args[0].id == local_name
        and isinstance(branch.test.args[1], ast.Name)
        and branch.test.args[1].id in contextvar_aliases]
    dispatch_index = next((index for index, statement in enumerate(proxy_init.body)
                           if any(item is contextvar_branches[0]
                                  for item in ast.walk(statement))), None) \
        if len(contextvar_branches) == 1 else None
    getters = ([item for item in contextvar_branches[0].body
                if isinstance(item, ast.FunctionDef)]
               if len(contextvar_branches) == 1 else [])
    if (len(contextvar_branches) != 1 or dispatch_index is None
            or any(_has_execution_exit([statement])
                   for statement in proxy_init.body[:dispatch_index])
            or len(getters) != 1
            or _has_execution_exit(contextvar_branches[0].body)):
        return False
    getter = getters[0]
    getter_tries = [item for item in getter.body if isinstance(item, ast.Try)]
    if len(getter_tries) != 1 or len(getter_tries[0].handlers) != 1:
        return False
    getter_try = getter_tries[0]
    handler = getter_try.handlers[0]
    read = (getter_try.body[0].value if len(getter_try.body) == 1
            and isinstance(getter_try.body[0], ast.Assign)
            and len(getter_try.body[0].targets) == 1
            and isinstance(getter_try.body[0].targets[0], ast.Name) else None)
    has_normal_return = (len(getter.body) == 2 and isinstance(getter.body[1], ast.Return))
    read = (isinstance(read, ast.Call) and isinstance(read.func, ast.Attribute)
        and read.func.attr == 'get' and isinstance(read.func.value, ast.Name)
        and read.func.value.id == local_name and not read.args and not read.keywords
        and not getter_try.orelse and not getter_try.finalbody)
    translated = (isinstance(handler.type, ast.Name) and handler.type.id == 'LookupError'
        and len(handler.body) == 1 and isinstance(handler.body[0], ast.Raise)
        and isinstance(handler.body[0].exc, ast.Call)
        and isinstance(handler.body[0].exc.func, ast.Name)
        and handler.body[0].exc.func.id == 'RuntimeError')
    assigned_getter = any(isinstance(item, ast.Call)
        and isinstance(item.func, ast.Attribute) and item.func.attr in ('setattr', '__setattr__')
        and len(item.args) >= 3 and isinstance(item.args[0], ast.Name)
        and item.args[0].id == 'self'
        and isinstance(item.args[1], ast.Constant)
        and item.args[1].value == lookup_method_name
        and isinstance(item.args[2], ast.Name) and item.args[2].id == getter.name
        for item in ast.walk(proxy_init)) or any(
        isinstance(item, ast.Assign)
        and any(isinstance(target, ast.Attribute) and target.attr == lookup_method_name
                and isinstance(target.value, ast.Name) and target.value.id == 'self'
                for target in item.targets)
        and isinstance(item.value, ast.Name) and item.value.id == getter.name
        for item in ast.walk(proxy_init))
    getter_writes = [item for item in ast.walk(proxy_init)
        if (isinstance(item, ast.Assign) and any(isinstance(target, ast.Attribute)
                and target.attr == lookup_method_name and isinstance(target.value, ast.Name)
                and target.value.id == 'self' for target in item.targets))
        or (isinstance(item, ast.Call) and isinstance(item.func, ast.Attribute)
            and item.func.attr in ('setattr', '__setattr__') and len(item.args) >= 2
            and isinstance(item.args[0], ast.Name) and item.args[0].id == 'self'
            and isinstance(item.args[1], ast.Constant)
            and item.args[1].value == lookup_method_name)]
    if (read and has_normal_return and translated and assigned_getter
            and len(getter_writes) == 1
            and getter in list(ast.walk(contextvar_branches[0]))):
        return {'bool_member': bool_fact,
                'proxy_init_member': proxy_init_fact,
                'descriptor_init_member': descriptor_init_fact,
                'descriptor_get_member': descriptor_get_fact,
                'descriptor_fallback': fallback_fact}
    return None


## Find false conditions for unbound ContextVar proxies at a caller callsite
## 查找调用点处未绑定ContextVar代理对象对应的false条件
#
#  @param context Reusable analysis context for the selected source snapshot.
#  @param call Original call or its call-specific evidence.
#  @param node Exact parsed client call.
#  @param entry Resolved source entry for the requested API.
#  @return Condition spans proven false, or an empty mapping.
def caller_contextvar_conditions(context, call, node, entry):
    if call.callsite is None:
        return {}
    fact = context.adapter.caller_inputs(call.callsite)
    if (not isinstance(fact, dict)
            or fact.get('kind') != 'source_callsite_inputs'
            or fact.get('schema_version') != 'caller-inputs-0.1'
            or fact.get('status') != 'source_bound'
            or fact.get('scope') != 'argument_reads_on_normal_module_prefix'
            or fact.get('runtime_values_observed') is not False):
        return {}
    assumptions = fact.get('assumptions')
    if (not isinstance(assumptions, list)
            or 'no_external_module_global_mutation' not in assumptions
            or not isinstance(fact.get('boundaries'), list)
            or any(not isinstance(item, dict) or item.get('reason')
                   == 'caller_prefix_call_effect_unconfirmed'
                   for item in fact.get('boundaries', []))):
        return {}
    fields = _FIELDS
    callsite_path = str(call.callsite.file_path)
    expected_callsite = {'file_path': callsite_path, **{
        name: getattr(call.callsite, name) for name in fields}}
    source_hashes = fact.get('source_hashes')
    if (fact.get('call_evidence') != expected_callsite
            or fact.get('call_syntax') != ast.dump(node, include_attributes=False)
            or not isinstance(source_hashes, dict)
            or not isinstance(source_hashes.get(callsite_path), str)
            or len(source_hashes[callsite_path]) != 64):
        return {}

    # 调用点事实必须仍对应实际源码内容
    try:
        for path, digest in source_hashes.items():
            if (not isinstance(path, str) or not isinstance(digest, str)
                    or hashlib.sha256(Path(path).read_text(encoding='utf-8-sig').encode('utf-8')).hexdigest() != digest):
                return {}
    except (OSError, UnicodeError):
        return {}
    contexts = fact.get('context_managers')
    if contexts is None:
        contexts = []
    if (not isinstance(contexts, list)
            or any(not isinstance(item, dict) or item.get('kind') != 'context_manager'
                   or item.get('call_evidence') != expected_callsite
                   or not isinstance(item.get('manager'), dict)
                   or item['manager'].get('target') != 'builtins.open'
                   for item in contexts)):
        return {}

    aliases = context.index.imports.get(entry.identity.module, {})
    api_path, api_tree = _module_tree(context, entry.identity.module)
    if api_path is None or api_tree is None:
        return {}
    conditions = {}
    parameters = {item.arg for item in (entry.node.args.posonlyargs
                  + entry.node.args.args + entry.node.args.kwonlyargs)}
    parameters.update(item.arg for item in (entry.node.args.vararg, entry.node.args.kwarg)
                      if item is not None)
    pending, branches = list(entry.node.body), []
    while pending:
        statement = pending.pop()
        if isinstance(statement, ast.If):
            branches.append(statement)
        if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef,
                                 ast.Lambda)):
            continue
        pending.extend(ast.iter_child_nodes(statement))
    for branch in branches:
        if not isinstance(branch, ast.If) or not isinstance(branch.test, ast.Name):
            continue
        if (branch.test.id in parameters
                or any(isinstance(item, ast.Name) and item.id == branch.test.id
                       and isinstance(item.ctx, ast.Store)
                       for item in ast.walk(entry.node))):
            continue
        if _module_binding_count(api_tree, branch.test.id) != 1:
            continue
        target = aliases.get(branch.test.id)
        if not isinstance(target, str) or '.' not in target:
            continue
        global_module, global_name = target.rsplit('.', 1)
        global_path, global_tree = _module_tree(context, global_module)
        if global_tree is None:
            continue
        proxy_value = _assignment(global_tree, global_name)
        if not isinstance(proxy_value, ast.Call) or not isinstance(proxy_value.func, ast.Name):
            continue
        global_imports = _module_imports(context, global_module, global_path, global_tree)
        proxy_target = global_imports.get(proxy_value.func.id)
        if not isinstance(proxy_target, str) or '.' not in proxy_target:
            continue
        proxy_module, proxy_qualname = proxy_target.rsplit('.', 1)
        proxy_path, proxy_tree = _module_tree(context, proxy_module)
        proxy_classes = ([item for item in ast.walk(proxy_tree)
                          if isinstance(item, ast.ClassDef) and item.name == proxy_qualname]
                         if proxy_tree is not None else [])
        proxy_proof = None
        if proxy_path is not None and proxy_tree is not None and len(proxy_classes) == 1:
            proxy_proof = _proxy_bool_is_unbound_false(
                context, proxy_module,
                FunctionIdentity(proxy_module, proxy_qualname, proxy_path,
                                 proxy_classes[0].lineno), proxy_tree)
        if (proxy_path is None or len(proxy_classes) != 1
                or _module_binding_count(global_tree, global_name) != 1
                or _module_binding_count(global_tree, proxy_value.func.id) != 1
                or _module_binding_count(proxy_tree, proxy_qualname) != 1
                or not isinstance(proxy_proof, dict)):
            continue
        bool_fact = proxy_proof['bool_member']
        fallback_fact = proxy_proof['descriptor_fallback']
        if not proxy_value.args or not isinstance(proxy_value.args[0], ast.Name):
            continue
        contextvar_assignment = _assignment(global_tree, proxy_value.args[0].id)
        contextvar_target = (global_imports.get(contextvar_assignment.func.id)
            if isinstance(contextvar_assignment, ast.Call)
            and isinstance(contextvar_assignment.func, ast.Name) else None)
        if (contextvar_target != 'contextvars.ContextVar'
                or contextvar_assignment is None
                or _module_binding_count(global_tree, proxy_value.args[0].id) != 1
                or _module_binding_count(global_tree, contextvar_assignment.func.id) != 1
                or len(contextvar_assignment.args) != 1
                or contextvar_assignment.keywords):
            continue
        packages = {global_module.split('.')[0], proxy_module.split('.')[0]}
        import_cache = context._contextvar_package_cache
        import_cache_key = (tuple(sorted(packages)), (global_module, proxy_value.args[0].id))
        if import_cache_key not in import_cache:
            import_effect = _package_sets_contextvar(
                context, packages, (global_module, proxy_value.args[0].id))
            import_cache[import_cache_key] = import_effect
        else:
            import_effect = import_cache[import_cache_key]
        if (not isinstance(import_effect, dict)
                or import_effect.get('state') != 'no_contextvar_write'
                or not _raw_source_hashes_match(import_effect.get('source_hashes'))):
            continue
        global_binding = _assignment_statement(global_tree, global_name)
        contextvar_name = proxy_value.args[0].id
        contextvar_binding = _assignment_statement(global_tree, contextvar_name)
        if global_binding is None or contextvar_binding is None:
            continue
        condition_span = SourceSpan(entry.identity.file_path, branch.test.lineno,
            branch.test.col_offset, branch.test.end_lineno, branch.test.end_col_offset)
        conditions[condition_span] = {
            'reason': 'source_contextvar_proxy_unbound',
            'detail': 'PCResolve source-bound the exact module-level call prefix; no earlier '
                      'call effect or non-open context manager can bind this ContextVar, and '
                      'no reachable import-time .set call was found in the proxy packages under '
                      'the recorded source assumptions. The ContextVar has no default and '
                      'the source-backed bool protocol returns False when it is unbound.',
            'target': FunctionIdentity(proxy_module, proxy_qualname, proxy_path,
                                       proxy_classes[0].lineno),
            'source_proof': {
                'callsite': {'span': expected_callsite,
                             'source_hashes': source_hashes},
                'contextvar': {
                    'module': global_module, 'name': contextvar_name,
                    'source_span': {'lineno': contextvar_binding.lineno,
                                    'col_offset': contextvar_binding.col_offset,
                                    'end_lineno': contextvar_binding.end_lineno,
                                    'end_col_offset': contextvar_binding.end_col_offset},
                    'source_hashes': import_effect['source_hashes'],
                },
                'proxy_global': {
                    'module': global_module, 'name': global_name,
                    'source_span': {'lineno': global_binding.lineno,
                                    'col_offset': global_binding.col_offset,
                                    'end_lineno': global_binding.end_lineno,
                                    'end_col_offset': global_binding.end_col_offset},
                },
                'bool_member': {'member_span': bool_fact['member_span'],
                                'source_hashes': bool_fact['source_hashes'],
                                'assumptions': bool_fact.get('assumptions', [])},
                'proxy_init_member': {
                    'member_span': proxy_proof['proxy_init_member']['member_span'],
                    'source_hashes': proxy_proof['proxy_init_member']['source_hashes'],
                    'assumptions': proxy_proof['proxy_init_member'].get('assumptions', []),
                },
                'descriptor_init_member': {
                    'member_span': proxy_proof['descriptor_init_member']['member_span'],
                    'source_hashes': proxy_proof['descriptor_init_member']['source_hashes'],
                    'assumptions': proxy_proof['descriptor_init_member'].get('assumptions', []),
                },
                'descriptor_get_member': {
                    'member_span': proxy_proof['descriptor_get_member']['member_span'],
                    'source_hashes': proxy_proof['descriptor_get_member']['source_hashes'],
                    'assumptions': proxy_proof['descriptor_get_member'].get('assumptions', []),
                },
                'descriptor_fallback': {
                    'protected_span': fallback_fact['protected_span'],
                    'fallback_span': fallback_fact['source_span'],
                    'source_hashes': fallback_fact['source_hashes'],
                    'assumptions': fallback_fact.get('assumptions', []),
                },
                'import_initialization': import_effect,
                'assumptions': sorted(set(
                    fact_assumption
                    for proof_fact in (fact, bool_fact, proxy_proof['proxy_init_member'],
                                       proxy_proof['descriptor_init_member'],
                                       proxy_proof['descriptor_get_member'], fallback_fact)
                    for fact_assumption in proof_fact.get('assumptions', []))
                    | set(import_effect.get('assumptions', []))),
            },
        }
    return conditions
