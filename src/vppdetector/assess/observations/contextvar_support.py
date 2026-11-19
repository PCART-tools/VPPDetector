## @package vppdetector.assess.observations.contextvar_support
#  Read source evidence shared by ContextVar observation proofs.
#
#
#  Resolve module trees, extract source assignments and import names, and verify source file
#  hashes used by ContextVar proofs.
#  解析模块语法树，提取源码赋值和导入名称，并校验 ContextVar 证明所用文件的摘要。



import ast
import hashlib
import tokenize
from pathlib import Path

from ...source import module_name_for_path


## Load the parsed source tree for one indexed module.
## 加载一个已索引模块的解析后源码树。
#
#  @param context Analysis context providing source access
#  @param module Indexed module identity
#  @return (path, module AST), or (None, None) when the module is absent,
#          ambiguous, or cannot be parsed
def _module_tree(context, module):
    paths = [
        path
        for path in context.index.files
        if module_name_for_path(path, context.index.source.import_roots) == module
    ]
    if not paths:
        parts = module.split(".")
        for root in context.index.source.import_roots:
            candidates = (
                Path(root).joinpath(*parts).with_suffix(".py"),
                Path(root).joinpath(*parts, "__init__.py"),
            )
            paths.extend(path for path in candidates if path.is_file())

    # Deduplicate paths before deciding whether the module is unambiguous.
    # 先对路径去重，再判断模块是否能够唯一定位。
    paths = list(dict.fromkeys(path.resolve() for path in paths))
    if len(paths) != 1:
        return None, None
    try:
        with tokenize.open(paths[0]) as stream:
            return paths[0], ast.parse(stream.read(), filename=str(paths[0]))
    except (OSError, UnicodeError, SyntaxError, RecursionError):
        return None, None


## Find the assigned value for a module-level name.
## 查找模块级名称的赋值表达式。
#
#  @param tree Module AST to inspect
#  @param name Binding name to find
#  @return Value expression AST, or None when no single value is found
def _assignment(tree, name):
    matches = []
    for statement in tree.body:
        targets = (
            statement.targets
            if isinstance(statement, ast.Assign)
            else [statement.target]
            if isinstance(statement, ast.AnnAssign)
            else []
        )
        if any(isinstance(target, ast.Name) and target.id == name for target in targets):
            value = statement.value if isinstance(statement, (ast.Assign, ast.AnnAssign)) else None
            if value is not None:
                matches.append(value)
    return matches[0] if len(matches) == 1 else None


## Resolve the single statement that binds a module-level name.
## 解析绑定模块级名称的唯一语句。
#
#  @param tree Module AST to inspect
#  @param name Binding name to find
#  @return Binding statement, or None when absent or ambiguous
def _assignment_statement(tree, name):
    matches = []
    for statement in tree.body:
        targets = (
            statement.targets
            if isinstance(statement, ast.Assign)
            else [statement.target]
            if isinstance(statement, ast.AnnAssign)
            else []
        )
        if any(isinstance(target, ast.Name) and target.id == name for target in targets):
            matches.append(statement)
    return matches[0] if len(matches) == 1 else None


## Verify recorded SHA-256 digests against source file contents.
## 根据源码文件内容验证记录的 SHA-256 摘要。
#
#  @param source_hashes Dictionary mapping source paths to hexadecimal digests
#  @return True when the dictionary is nonempty and every digest matches its file
def _raw_source_hashes_match(source_hashes):
    if not isinstance(source_hashes, dict) or not source_hashes:
        return False
    try:
        return all(
            isinstance(path, str)
            and isinstance(digest, str)
            and len(digest) == 64
            and hashlib.sha256(Path(path).read_bytes()).hexdigest() == digest
            for path, digest in source_hashes.items()
        )
    except OSError:
        return False


## Count module-scope bindings for one name.
## 统计一个名称在模块作用域中的绑定次数。
#
#  @param tree Module AST to inspect
#  @param name Binding name to count
#  @return Number of matching bindings, or None when dynamic or global writes
#          make the module-scope count uncertain
def _module_binding_count(tree, name):
    bindings = []
    pending = list(tree.body)
    while pending:
        current = pending.pop()
        if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            if current.name == name:
                bindings.append(current)
            if any(
                isinstance(item, ast.Global) and name in item.names for item in ast.walk(current)
            ):
                return None
            continue
        if isinstance(current, ast.Lambda):
            continue
        if isinstance(current, ast.Import):
            bindings.extend(
                alias
                for alias in current.names
                if (alias.asname or alias.name.split(".")[0]) == name
            )
        elif isinstance(current, ast.ImportFrom):
            bindings.extend(
                alias
                for alias in current.names
                if alias.name != "*" and (alias.asname or alias.name) == name
            )
        elif (
            isinstance(current, ast.Name)
            and current.id == name
            and isinstance(current.ctx, (ast.Store, ast.Del))
        ):
            bindings.append(current)
        if (
            isinstance(current, ast.Call)
            and isinstance(current.func, ast.Name)
            and current.func.id in ("exec", "eval", "globals")
        ):
            return None
        pending.extend(ast.iter_child_nodes(current))
    return len(bindings)


## Resolve imports declared by one module from producer facts.
## 根据生产端事实解析模块声明的导入。
#
#  @param context Analysis context providing import facts
#  @param module Indexed module identity
#  @param path Source path for the module
#  @param tree Parsed module AST
#  @return Import-name to fully qualified module/member bindings
def _module_imports(
    context,
    module,
    path,
    tree,
):
    result = dict(context.index.imports.get(module, {}))
    from pcresolve.import_facts import resolve_relative_module

    resolve_import = resolve_relative_module
    for statement in tree.body:
        if isinstance(statement, ast.Import):
            for alias in statement.names:
                result[alias.asname or alias.name.split(".")[0]] = alias.name
        elif isinstance(statement, ast.ImportFrom):
            parent = resolve_import(
                module, path.name == "__init__.py", statement.module, statement.level
            )
            for alias in statement.names:
                if alias.name != "*":
                    result[alias.asname or alias.name] = parent + "." + alias.name
    return result


## Resolve a producer fact for a named source member.
## 解析指定源码成员的生产端事实。
#
#  @param context Analysis context providing source facts
#  @param module Module identity containing the member
#  @param qualname Qualified name of the owning scope
#  @param member Member name to resolve
#  @param file_path Source file containing the member
#  @return Matching member fact, or None when unavailable or ambiguous
def _source_member_fact(
    context,
    module,
    qualname,
    member,
    file_path,
):
    try:
        return context.adapter.source_class_member_binding(module, qualname, member, file_path)
    except (OSError, UnicodeError, ValueError):
        return None


## Validate and return the stable producer fact for a source member.
## 校验并返回源码成员的稳定生产端事实。
#
#  @param context Analysis context providing source facts
#  @param module Module identity containing the member
#  @param qualname Qualified name of the owning scope
#  @param member Member name to resolve
#  @param file_path Source file containing the member
#  @return Validated producer fact, or None when its identity or source
#          metadata is incomplete or inconsistent
def _stable_source_member(
    context,
    module,
    qualname,
    member,
    file_path,
):
    fact = _source_member_fact(context, module, qualname, member, file_path)
    if (
        isinstance(fact, dict)
        and fact.get("schema_version") == "source-class-member-binding-0.1"
        and fact.get("kind") == "source_class_member_binding"
        and fact.get("status") == "stable"
        and fact.get("class", {}).get("module") == module
        and fact.get("class", {}).get("qualname") == qualname
        and fact.get("member") == member
        and isinstance(fact.get("member_span"), dict)
        and all(
            type(fact["member_span"].get(key)) is int
            for key in ("lineno", "col_offset", "end_lineno", "end_col_offset")
        )
        and isinstance(fact.get("source_hashes"), dict)
        and fact.get("source_hashes")
    ):
        return fact
    return None


## Check whether a statement sequence contains a supported execution exit.
## 检查语句序列是否包含受支持的执行退出点。
#
#  @param statements Statements in the source path
#  @return True when a return or raise node occurs outside a nested scope
def _has_execution_exit(statements):
    pending = list(statements)
    while pending:
        node = pending.pop()
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
            continue
        if isinstance(node, (ast.Return, ast.Raise)):
            return True
        pending.extend(ast.iter_child_nodes(node))
    return False
