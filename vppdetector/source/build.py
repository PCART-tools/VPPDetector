## @package vppdetector.source.build
#  Build source indexes from immutable source snapshots.
#
#
#  Prepare source-reading services, select entry files, walk the relevant import closure and
#  assemble the final index.
#  准备源码读取服务，选择入口文件，遍历相关导入闭包并装配最终索引。



import ast
import tokenize
from collections import deque
from functools import lru_cache
from pathlib import Path

from .._records import FACTORY_DEFAULT, FrozenRecord, MutableRecord
from ..models import AnalysisBoundary, SourceContext
from .discovery import (
    _module_files,
    _package_initializers,
    _python_files,
    _within_source,
    module_name_for_path,
    normalized_import_roots,
)
from .index import SourceIndex, _FunctionCollector

## Index source functions, classes, imports and analysis boundaries.
## 索引源码函数、类、导入信息及分析边界。


## Retain breadth-first import order without traversing expression payloads
## 按广度优先顺序读取导入，同时跳过表达式子树
#
#  @param tree AST subtree to inspect
#  @return Iterator of import statement nodes in breadth-first order
def _import_statements(tree):
    pending = deque([tree])
    while pending:
        node = pending.popleft()
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            yield node
        elif not isinstance(node, ast.expr):
            pending.extend(ast.iter_child_nodes(node))


## Build the module-level import environment used by forwarding analysis.
## 构造转发分析所需的模块级导入环境。
#
#  @param tree Parsed source tree whose imports are inspected
#  @param module Module name associated with the source file
#  @param import_facts PCResolve import-fact resolver
#  @param resolve_relative_module PCResolve relative-import resolver
#  @param statement_scope_facts PCResolve lexical binding resolver
#  @param is_package Whether the current module is a package
#  @return Unrebound imported target metadata indexed by Python binding
def _module_import_environment(
    tree,
    module,
    is_package,
    import_facts,
    resolve_relative_module,
    statement_scope_facts,
):
    aliases = {}
    dependency_roots = {}
    imported_qualnames = {}
    imported_attribute_prefixes = {}
    counts = {}
    rebound = set()
    for statement in tree.body:
        facts = import_facts(statement)
        if not facts:
            rebound.update(statement_scope_facts([statement]).bound)
            continue
        for fact in facts:
            binding = fact.python_binding
            counts[binding] = counts.get(binding, 0) + 1
            if fact.kind == "import":
                aliases[binding] = fact.name if fact.asname else binding
                dependency_roots[binding] = fact.name
                imported_qualnames[binding] = ""
                imported_attribute_prefixes[binding] = (
                    () if fact.asname else tuple(fact.name.split("."))[1:]
                )
            else:
                prefix = resolve_relative_module(module, is_package, fact.module, fact.level)
                aliases[binding] = prefix + "." + fact.name
                dependency_roots[binding] = prefix
                imported_qualnames[binding] = fact.name
                imported_attribute_prefixes[binding] = ()

    # A rebound or multiply imported name cannot identify a definite external target.
    # 被重新绑定或存在多次导入的名称不能作为确定的外部目标
    aliases = {
        name: target
        for name, target in aliases.items()
        if name not in rebound and counts[name] == 1
    }
    return {
        name: (
            dependency_roots[name],
            imported_qualnames[name],
            imported_attribute_prefixes[name],
        )
        for name in aliases
    }


## Index lexical parents, local functions and class bases in one module.
## 为单个模块建立词法父级、本地函数和类基类索引。
#
#  @param tree Parsed module AST
#  @return Parent links, local function names, class bases and class names
def _module_scope_environment(tree):
    parents = {}
    for parent in ast.walk(tree):
        for child in ast.iter_child_nodes(parent):
            parents[child] = parent

    local_functions = {}
    class_bases = {}
    class_qualnames = set()
    for candidate in ast.walk(tree):
        parent_names = []
        current = parents.get(candidate)
        while current is not None:
            if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                parent_names.append(current.name)
            current = parents.get(current)
        parent_qualname = ".".join(reversed(parent_names))
        if isinstance(candidate, (ast.FunctionDef, ast.AsyncFunctionDef)):
            qualified = ".".join(part for part in (parent_qualname, candidate.name) if part)
            local_functions.setdefault(parent_qualname, {}).setdefault(candidate.name, set()).add(
                qualified
            )
        elif isinstance(candidate, ast.ClassDef):
            qualified = ".".join(part for part in (parent_qualname, candidate.name) if part)
            class_qualnames.add(qualified)
            class_bases[qualified] = tuple(
                base.id for base in candidate.bases if isinstance(base, ast.Name)
            )
    return parents, local_functions, class_bases, class_qualnames


## Resolve imported aliases visible in one function's lexical scope.
## 解析一个函数词法作用域中可见的导入别名。
#
#  @param scope Function or lambda scope whose aliases are collected
#  @param imported_targets Unrebound module-level targets
#  @param statement_scope_facts PCResolve lexical binding resolver
#  @param cache Per-module alias cache keyed by scope identity
#  @return Imported targets visible under their local names
def _scope_import_aliases(scope, imported_targets, statement_scope_facts, cache):
    cached = cache.get(id(scope))
    if cached is not None:
        return cached
    local_names = set(statement_scope_facts(scope.body).bound)
    arguments = scope.args
    local_names.update(
        argument.arg for argument in (arguments.posonlyargs + arguments.args + arguments.kwonlyargs)
    )
    if arguments.vararg:
        local_names.add(arguments.vararg.arg)
    if arguments.kwarg:
        local_names.add(arguments.kwarg.arg)

    # Local bindings shadow module aliases. Unambiguous local imports can supply new aliases.
    # 局部绑定会遮蔽模块别名，能唯一解析的局部导入可提供新别名。
    result = {name: target for name, target in imported_targets.items() if name not in local_names}
    assigned_targets = {}
    invalid_targets = set()
    for candidate in ast.walk(scope):
        if candidate is not scope and isinstance(
            candidate, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)
        ):
            continue
        if isinstance(candidate, ast.Assign):
            targets = candidate.targets
            value = candidate.value
        elif isinstance(candidate, ast.AnnAssign):
            targets = (candidate.target,)
            value = candidate.value
        else:
            continue
        for target in targets:
            if not isinstance(target, ast.Name):
                continue
            if isinstance(value, ast.Name) and value.id in imported_targets:
                assigned_targets.setdefault(target.id, set()).add(imported_targets[value.id])
            else:
                invalid_targets.add(target.id)
    for name, assigned_imports in assigned_targets.items():
        if len(assigned_imports) == 1 and name not in invalid_targets:
            result[name] = next(iter(assigned_imports))
    cache[id(scope)] = result
    return result


## Find external modules reached by direct variadic forwarding.
## 查找通过直接可变参数转发可达的外部模块。
#
#  @param tree Parsed source tree whose calls are inspected
#  @param imported_targets Unrebound module-level targets by Python binding
#  @param target_qualnames Optional target qualified names limiting the search
#  @param statement_scope_facts PCResolve lexical binding resolver
#  @return Imported module and callable names reached by direct variadic forwarding
def _forwarded_import_modules(tree, imported_targets, target_qualnames, statement_scope_facts):
    modules = set()
    if target_qualnames is not None:
        for dependency, imported_qualname, _ in imported_targets.values():
            for target_qualname in target_qualnames:
                if target_qualname == imported_qualname:
                    forwarded_qualname = imported_qualname
                elif target_qualname.startswith(imported_qualname + "."):
                    forwarded_qualname = target_qualname
                else:
                    continue
                modules.add((dependency, forwarded_qualname))
    parents, local_functions, class_bases, class_qualnames = _module_scope_environment(tree)

    scope_alias_cache = {}

    # When a target is specified, inspect direct forwarding only in reachable local bodies.
    # 指定目标时限定本地函数和构造器的可达范围，再检查其中的直接转发
    reachable = None if target_qualnames is None else set(target_qualnames)
    if reachable is not None:
        for class_name in class_qualnames.intersection(reachable):
            initializer = class_name + ".__init__"
            reachable.add(initializer)
            for base_name in class_bases.get(class_name, ()):
                base_qualname = ".".join(
                    part for part in (class_name.rpartition(".")[0], base_name) if part
                )
                base_methods = local_functions.get(base_qualname, {}).get("__init__", ())
                reachable.update(base_methods)
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        scope = parents.get(node)
        while scope is not None and not isinstance(
            scope, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)
        ):
            scope = parents.get(scope)
        if scope is None:
            continue
        scope_names = []
        current = scope
        while current is not None:
            if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                scope_names.append(current.name)
            current = parents.get(current)
        scope_qualname = ".".join(reversed(scope_names))
        if reachable is not None and scope_qualname not in reachable:
            continue
        arguments = scope.args
        vararg = arguments.vararg.arg if arguments.vararg else None
        kwarg = arguments.kwarg.arg if arguments.kwarg else None
        forwards = (
            any(
                keyword.arg is None
                and isinstance(keyword.value, ast.Name)
                and keyword.value.id == kwarg
                for keyword in node.keywords
            )
            if kwarg
            else False
        )
        if vararg:
            forwards = forwards or any(
                isinstance(argument, ast.Starred)
                and isinstance(argument.value, ast.Name)
                and argument.value.id == vararg
                for argument in node.args
            )
        if not forwards:
            continue

        if (
            isinstance(node.func, ast.Attribute)
            and node.func.attr == "__init__"
            and isinstance(node.func.value, ast.Call)
            and isinstance(node.func.value.func, ast.Name)
            and node.func.value.func.id == "super"
            and reachable is not None
        ):
            class_name = scope_qualname.rpartition(".")[0]
            for base_name in class_bases.get(class_name, ()):
                base_qualname = ".".join(
                    part for part in (class_name.rpartition(".")[0], base_name) if part
                )
                base_methods = local_functions.get(base_qualname, {}).get("__init__", ())
                reachable.update(base_methods)
            continue

        attributes = []
        function = node.func
        while isinstance(function, ast.Attribute):
            attributes.append(function.attr)
            function = function.value
        if not isinstance(function, ast.Name):
            continue
        attributes.reverse()
        scope_aliases = (
            _scope_import_aliases(scope, imported_targets, statement_scope_facts, scope_alias_cache)
            if isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef))
            else imported_targets
        )
        imported_target = scope_aliases.get(function.id)
        if imported_target is None:
            parent_qualname = scope_qualname.rpartition(".")[0]
            local_targets = local_functions.get(parent_qualname, {}).get(function.id, set())
            if len(local_targets) == 1 and reachable is not None:
                reachable.update(local_targets)
            continue
        dependency, imported_qualname, attribute_prefix = imported_target
        if attribute_prefix:
            if tuple(attributes[: len(attribute_prefix)]) != attribute_prefix:
                continue
            attributes = attributes[len(attribute_prefix) :]
        forwarded_qualname = ".".join(part for part in (imported_qualname, *attributes) if part)
        if not forwarded_qualname:
            continue
        if dependency and all(part.isidentifier() for part in dependency.split(".")):
            modules.add((dependency, forwarded_qualname))
    return tuple(sorted(modules))


## Match an imported module to a statically forwarded module path
## 判断导入模块是否位于静态可见的变参转发路径上
#
#  @param module Imported module name being considered
#  @param forwarded_modules Module names and callable paths receiving forwarded arguments
#  @return Whether the import is relevant to a forwarded callable
def _is_forwarded_module(module, forwarded_modules):
    for candidate, qualnames in forwarded_modules.items():
        if module == candidate:
            return True
        if candidate.startswith(module + "."):
            return True
        if module.startswith(candidate + "."):
            relative = module[len(candidate) + 1 :]
            if any(name == relative or name.startswith(relative + ".") for name in qualnames):
                return True
    return False


## Keep only the callable suffix represented by one imported module
## 保留导入模块对应的目标可调用对象限定名后缀
#
#  @param module Imported module name being indexed
#  @param forwarded_modules Module names and callable paths receiving forwarded arguments
#  @return Callable names available within this module
def _forwarded_qualnames_for_module(module, forwarded_modules):
    result = set()
    for candidate, qualnames in forwarded_modules.items():
        if module == candidate:
            result.update(qualnames)
            continue
        if candidate.startswith(module + "."):
            relative = candidate[len(module) + 1 :]
            result.update(relative + "." + qualname for qualname in qualnames)
            continue
        if module.startswith(candidate + "."):
            relative = module[len(candidate) + 1 :]
            for qualname in qualnames:
                if qualname.startswith(relative + "."):
                    result.add(qualname[len(relative) + 1 :])
    return result


## Choose the initial source files for one index without shared state.
## 为单个索引选择初始源码文件，不共享可变状态。
#
#  @param root Root directory or file for the source snapshot.
#  @param target_api Optional API identity that narrows the index.
#  @param source_files Optional explicit source file set.
#  @param import_roots Roots used to resolve imports.
#  @param dependency_modules Known external dependency modules.
#  @param module_name Resolver for a source path to its module name.
#  @param resolve_path Path canonicalizer for source identities.
#  @return API scope flag, selected entry path and initial source queue.
#  @exception ValueError If selection modes conflict or a selected path is invalid.
def _initial_sources(
    root,
    target_api,
    source_files,
    import_roots,
    dependency_modules,
    module_name,
    resolve_path,
):
    if target_api is not None and source_files is not None:
        raise ValueError("target_api and source_files cannot be combined")
    if target_api is not None and target_api.file_path is not None:
        entry = target_api.file_path.resolve()
        if not _within_source(entry, root):
            raise ValueError("API file must be within the requested source root")
        pending = [entry] if entry.is_file() else []
        if pending:
            pending.extend(
                _package_initializers(
                    entry,
                    root,
                    import_roots,
                    dependency_modules,
                    module_name=module_name,
                    resolve_path=resolve_path,
                )
            )
        return True, entry, pending
    if source_files is not None:
        selected = tuple(Path(path).resolve() for path in source_files)
        if any(not _within_source(path, root) or not path.is_file() for path in selected):
            raise ValueError("Selected source files must exist within the source root")
        return False, None, list(reversed(selected))
    return False, None, list(reversed(tuple(_python_files(root))))


## Parse one indexed source file with the active producer read policy.
## 按当前生产者读取策略解析一个索引源码文件。
#
#  @param file_path Source file to read and parse
#  @param source_store Optional producer snapshot store
#  @param source_policy Read policy paired with the snapshot store
#  @param parse_source PCResolve source parser
#  @return Parsed source AST
def _parse_index_file(file_path, source_store, source_policy, parse_source):
    if source_store is None:
        with tokenize.open(file_path) as stream:
            return parse_source(stream.read(), filename=str(file_path))

    # Reuse only a document prepared with the same source policy.
    # 只复用按相同源码策略准备的文档，保持原有编码和语法规则。
    document = source_store.read_document(str(file_path), source_policy)
    if document.error is not None:
        if document.error_stage == "parse":
            # Retain VPP's filename-bearing syntax diagnostics.
            # 保留VPP原有包含文件名的语法错误诊断。
            parse_source(document.text, filename=str(file_path))
        raise document.error
    return document.tree


## Resolve unique, unrebound module-level import aliases.
## 解析唯一且未重绑定的模块级导入别名。
#
#  @param tree Parsed module AST
#  @param module Module identity for this source file
#  @param file_path Source path used to resolve package-relative imports
#  @param read_import_facts PCResolve import-fact reader
#  @param read_scope_facts PCResolve lexical binding reader
#  @param resolve_import PCResolve relative-import resolver
#  @return Import binding names mapped to their resolved module paths
def _module_import_aliases(
    tree,
    module,
    file_path,
    read_import_facts,
    read_scope_facts,
    resolve_import,
):
    aliases = {}
    imported_bindings = {}
    rebound = set()
    for statement in tree.body:
        facts = read_import_facts(statement)
        if not facts:
            rebound.update(read_scope_facts([statement]).bound)
        for fact in facts:
            imported_bindings[fact.python_binding] = (
                imported_bindings.get(fact.python_binding, 0) + 1
            )
            if fact.kind == "import":
                aliases[fact.python_binding] = fact.name if fact.asname else fact.python_binding
            else:
                prefix = (
                    resolve_import(
                        module,
                        file_path.name.startswith("__init__."),
                        fact.module,
                        fact.level,
                    )
                    if fact.level
                    else fact.module
                )
                aliases[fact.python_binding] = prefix + "." + fact.name
    return {
        name: target
        for name, target in aliases.items()
        if name not in rebound and imported_bindings[name] == 1
    }


## Manage the bounded import graph used to extend a source index.
## 管理用于扩展源码索引的有界导入图。
class _ImportClosure(MutableRecord):
    _record_fields = (
        "root",
        "import_roots",
        "target_api",
        "dependency_modules",
        "module_name",
        "resolve_path",
        "read_import_facts",
        "resolve_import",
        "read_scope_facts",
        "pending",
        "queued",
        "queued_depth",
        "queued_qualnames",
        "external_files",
        "boundaries",
        "processed_qualnames",
        "discovered_dependency_modules",
        "locations",
        "visited",
    )
    __match_args__ = _record_fields

    ## Initialize the import graph and its traversal state.
    ## 初始化导入图及其遍历状态。
    #
    #  @param root Root source directory
    #  @param import_roots Additional import search roots
    #  @param target_api API identity whose forwarding paths are followed
    #  @param dependency_modules Allowed dependency module roots
    #  @param module_name Module-name resolver
    #  @param resolve_path Source-path resolver
    #  @param read_import_facts Import-fact reader
    #  @param resolve_import Relative-import resolver
    #  @param read_scope_facts Scope-fact reader
    #  @param pending Import traversal queue
    #  @param queued Already queued source files
    #  @param queued_depth Import depth by source file
    #  @param queued_qualnames Qualified names queued by source file
    #  @param external_files Files outside the root source directory
    #  @param boundaries Boundary ledger for traversal limits
    #  @param processed_qualnames Names already processed by source file
    #  @param discovered_dependency_modules Dependency roots discovered so far
    #  @param locations Cached module source locations
    #  @param visited Source files already visited
    def __init__(
        self,
        root,
        import_roots,
        target_api,
        dependency_modules,
        module_name,
        resolve_path,
        read_import_facts,
        resolve_import,
        read_scope_facts,
        pending,
        queued,
        queued_depth,
        queued_qualnames,
        external_files,
        boundaries,
        processed_qualnames=FACTORY_DEFAULT,
        discovered_dependency_modules=FACTORY_DEFAULT,
        locations=FACTORY_DEFAULT,
        visited=FACTORY_DEFAULT,
    ):
        self.root = root
        self.import_roots = import_roots
        self.target_api = target_api
        self.dependency_modules = dependency_modules
        self.module_name = module_name
        self.resolve_path = resolve_path
        self.read_import_facts = read_import_facts
        self.resolve_import = resolve_import
        self.read_scope_facts = read_scope_facts
        self.pending = pending
        self.queued = queued
        self.queued_depth = queued_depth
        self.queued_qualnames = queued_qualnames
        self.external_files = external_files
        self.boundaries = boundaries
        self.processed_qualnames = (
            {} if processed_qualnames is FACTORY_DEFAULT else processed_qualnames
        )
        self.discovered_dependency_modules = (
            set()
            if discovered_dependency_modules is FACTORY_DEFAULT
            else discovered_dependency_modules
        )
        self.locations = {} if locations is FACTORY_DEFAULT else locations
        self.visited = set() if visited is FACTORY_DEFAULT else visited

    ## Find external import targets that forward the requested API names.
    ## 查找转发所请求 API 名称的外部导入目标。
    #
    #  @param tree Parsed module AST
    #  @param module Module identity for the source file
    #  @param file_path Path to the source file
    #  @param target_qualnames Requested qualified names
    #  @return Forwarded names grouped by candidate module
    def forwarded_qualnames(
        self,
        tree,
        module,
        file_path,
        target_qualnames,
    ):
        if not target_qualnames or self.target_api is None:
            return {}
        candidates = _forwarded_import_modules(
            tree,
            _module_import_environment(
                tree,
                module,
                file_path.name == "__init__.py",
                self.read_import_facts,
                self.resolve_import,
                self.read_scope_facts,
            ),
            target_qualnames,
            self.read_scope_facts,
        )
        self.processed_qualnames.setdefault(file_path, set()).update(target_qualnames)
        forwarded = {}
        for candidate_module, candidate_qualname in candidates:
            forwarded.setdefault(candidate_module, set()).add(candidate_qualname)
        self._register_forwarded_dependencies(forwarded)
        return forwarded

    ## Register external dependency namespaces named by forwarded call targets.
    ## 注册转发调用目标所引用的外部依赖命名空间。
    #
    #  @param forwarded Callable names grouped by candidate module
    #  @return None
    def _register_forwarded_dependencies(self, forwarded):
        for candidate_module, qualnames in tuple(forwarded.items()):
            namespace = candidate_module.split(".", 1)[0]
            candidate_files = _module_files(
                candidate_module, self.root, self.import_roots, (namespace,)
            )
            # A package-qualified call may name a submodule through the imported
            # package object, such as ``pkg.api.consume``.
            # 包限定的调用可通过导入的包对象引用子模块，例如 pkg.api.consume。
            for qualname in qualnames:
                parts = qualname.split(".")
                for split in range(1, len(parts)):
                    nested_module = candidate_module + "." + ".".join(parts[:split])
                    nested_files = _module_files(
                        nested_module, self.root, self.import_roots, (namespace,)
                    )
                    if any(not _within_source(path, self.root) for path in nested_files):
                        forwarded.setdefault(nested_module, set()).add(".".join(parts[split:]))
            if not any(not _within_source(path, self.root) for path in candidate_files):
                continue
            if namespace in self.dependency_modules:
                continue
            if len(self.discovered_dependency_modules) >= 16:
                self.boundaries.append(
                    AnalysisBoundary(
                        code="external_dependency_module_limit",
                        message="Variadic forwarding reached more than 16 external modules.",
                        function=self.target_api,
                    )
                )
                continue
            self.dependency_modules.add(namespace)
            self.discovered_dependency_modules.add(namespace)

    ## Queue source dependencies referenced by imports in one module.
    ## 将模块导入所引用的源码依赖加入队列。
    #
    #  @param tree Parsed module AST
    #  @param module Module identity for the source file
    #  @param file_path Path to the source file
    #  @param forwarded_qualnames Forwarded names grouped by module
    def queue_import_dependencies(
        self,
        tree,
        module,
        file_path,
        forwarded_qualnames,
    ):
        for node in _import_statements(tree):
            for fact in self.read_import_facts(node):
                if fact.kind == "import":
                    modules = (fact.name,)
                else:
                    prefix = self.resolve_import(
                        module, file_path.name == "__init__.py", fact.module, fact.level
                    )
                    modules = (prefix, prefix + "." + fact.name)
                for name in modules:
                    related_modules = {name}
                    related_modules.update(
                        candidate
                        for candidate in forwarded_qualnames
                        if candidate.startswith(name + ".")
                    )
                    for related_module in related_modules:
                        found = self.locations.get(related_module)
                        if found is None:
                            found = _module_files(
                                related_module,
                                self.root,
                                self.import_roots,
                                self.dependency_modules,
                            )
                            if found:
                                self.locations[related_module] = found
                        for dependency in found:
                            self._queue_dependency(dependency, file_path, forwarded_qualnames)

    ## Add one dependency file when it is within the bounded import closure.
    ## 在有界导入闭包内加入一个依赖文件。
    #
    #  @param dependency Candidate dependency source path
    #  @param file_path Source file containing the import
    #  @param forwarded_qualnames Forwarded names grouped by module
    def _queue_dependency(
        self,
        dependency,
        file_path,
        forwarded_qualnames,
    ):
        dependency_module = self.module_name(dependency, self.import_roots)
        if not _within_source(dependency, self.root) and not _is_forwarded_module(
            dependency_module, forwarded_qualnames
        ):
            return

        # Crossing into an external namespace consumes one level of the import budget.
        # 跨入外部命名空间会消耗一层导入深度。
        dependency_namespace = dependency_module.split(".", 1)[0]
        current_namespace = (
            self.module_name(file_path, self.import_roots).split(".", 1)[0]
            if not _within_source(file_path, self.root)
            else None
        )
        dependency_depth = self.queued_depth.get(file_path, 0)
        if not _within_source(dependency, self.root) and dependency_namespace != current_namespace:
            dependency_depth += 1
        if dependency_depth > 4:
            self.boundaries.append(
                AnalysisBoundary(
                    code="external_dependency_depth_limit",
                    message="Variadic forwarding exceeded four external module hops.",
                    function=self.target_api,
                )
            )
            return
        selected_paths = (
            dependency,
            *_package_initializers(
                dependency,
                self.root,
                self.import_roots,
                self.dependency_modules,
                module_name=self.module_name,
                resolve_path=self.resolve_path,
            ),
        )
        for selected in selected_paths:
            selected_module = self.module_name(selected, self.import_roots)
            selected_targets = _forwarded_qualnames_for_module(selected_module, forwarded_qualnames)
            if not _within_source(selected, self.root) and not selected_targets:
                continue
            if selected_targets:
                known_targets = self.queued_qualnames.setdefault(selected, set())
                new_targets = selected_targets - known_targets
                known_targets.update(selected_targets)
            else:
                new_targets = set()
            if selected in self.queued and not new_targets:
                continue
            if (
                not _within_source(selected, self.root)
                and selected not in self.external_files
                and len(self.external_files) >= 128
            ):
                self.boundaries.append(
                    AnalysisBoundary(
                        code="external_dependency_file_limit",
                        message="Variadic forwarding exceeded 128 external source files.",
                        function=self.target_api,
                    )
                )
                continue
            new_file = selected not in self.queued
            if new_file:
                self.queued.add(selected)
                self.queued_depth[selected] = dependency_depth
                if not _within_source(selected, self.root):
                    self.external_files.add(selected)
            if new_file or new_targets:
                self.pending.append(selected)

    ## Traverse queued modules and collect their declarations and import facts.
    ## 遍历队列模块并收集声明与导入事实。
    #
    #  @param services PCResolve services and source-reading policy
    #  @param is_api_scope Whether traversal is limited to one API entry
    #  @return Collected declarations and module-level facts
    def collect_declarations(self, services, is_api_scope):
        functions = []
        constructors = []
        classes = []
        imports = {}
        module_bodies = {}
        condition_nodes = {}
        source_trees = {}

        while self.pending:
            file_path = self.pending.pop()
            target_qualnames = self.queued_qualnames.get(file_path, set())
            new_target_qualnames = target_qualnames - self.processed_qualnames.get(file_path, set())
            is_new_file = file_path not in self.visited
            if not is_new_file and not new_target_qualnames:
                continue

            # New forwarded names may revisit a file, but declarations and syntax are read once.
            # 发现新的转发名称时可重访文件，语法解析和声明收集只做一次。
            if is_new_file:
                self.visited.add(file_path)
                try:
                    tree = _parse_index_file(
                        file_path,
                        services.source_store,
                        services.source_policy,
                        services.parse_source,
                    )
                except (OSError, SyntaxError, UnicodeError) as exc:
                    self.boundaries.append(
                        AnalysisBoundary(
                            code="source_parse_failed",
                            message="{}: {}".format(file_path, exc),
                        )
                    )
                    continue
                source_trees[file_path] = tree
            else:
                tree = source_trees[file_path]

            module = self.module_name(file_path, self.import_roots)
            if is_new_file:
                module_bodies.setdefault(module, []).append((str(file_path), tree.body))
            resolved_aliases = _module_import_aliases(
                tree,
                module,
                file_path,
                services.read_import_facts,
                services.read_scope_facts,
                services.resolve_import,
            )
            if is_api_scope:
                forwarded_qualnames = self.forwarded_qualnames(
                    tree, module, file_path, new_target_qualnames
                )
                self.queue_import_dependencies(tree, module, file_path, forwarded_qualnames)
            imports[module] = resolved_aliases
            if is_new_file:
                collector = _FunctionCollector(module, file_path)
                collector.visit(tree)
                functions.extend(collector.functions)
                constructors.extend(collector.constructors)
                classes.extend(collector.classes)
                condition_nodes[file_path] = tuple(collector.conditions)

        return _IndexDeclarations(
            functions, constructors, classes, imports, condition_nodes, module_bodies
        )


## Assemble collected declarations and traversal facts into a stable source index.
## 将收集到的声明和遍历事实组装为稳定的源码索引。
#
#  @param source Normalized source context for this build
#  @param closure Completed import closure and boundary ledger
#  @param functions Collected function declarations
#  @param constructors Collected constructor declarations
#  @param classes Collected class declarations
#  @param imports Resolved module import aliases
#  @param condition_nodes Conditional syntax indexed by source path
#  @param source_store Optional source snapshot store used during parsing
#  @param is_api_scope Whether the index is limited to one API entry
#  @param resolve_star_imports PCResolve static star-import resolver
#  @param module_bodies Module bodies used to resolve star imports
#  @return Source index with deterministic declaration and path ordering
def _assemble_source_index(
    source,
    closure,
    functions,
    constructors,
    classes,
    imports,
    condition_nodes,
    source_store,
    is_api_scope,
    resolve_star_imports,
    module_bodies,
):
    star_facts = resolve_star_imports(module_bodies)
    for module, aliases in star_facts.aliases.items():
        imports[module].update(aliases)

    return SourceIndex(
        source=source,
        files=tuple(sorted(closure.visited)),
        functions=tuple(
            sorted(functions, key=lambda item: (str(item.identity.file_path), item.node.lineno))
        ),
        constructors=tuple(
            sorted(
                constructors,
                key=lambda item: (str(item.function.identity.file_path), item.function.node.lineno),
            )
        ),
        boundaries=tuple(closure.boundaries),
        imports=imports,
        classes=tuple(sorted(classes, key=lambda item: (str(item.file_path), item.lineno))),
        is_api_scope=is_api_scope,
        condition_nodes=condition_nodes,
        source_store=source_store,
    )


## Hold the PCResolve services used during one source-index build.
## 保存单次源码索引构建所需的 PCResolve 服务。
class _SourceIndexServices(FrozenRecord):
    _record_fields = (
        "source_store",
        "source_policy",
        "parse_source",
        "read_import_facts",
        "read_scope_facts",
        "resolve_import",
        "resolve_star_imports",
    )

    ## Store the producer callbacks and source-reading policy for a build.
    ## 保存本次构建所用的生产者回调和源码读取策略。
    #
    #  @param source_store Optional immutable source snapshot store
    #  @param source_policy Source decoding policy
    #  @param parse_source Python source parser
    #  @param read_import_facts Import fact reader
    #  @param read_scope_facts Lexical scope fact reader
    #  @param resolve_import Relative import resolver
    #  @param resolve_star_imports Static star-import resolver
    def __init__(
        self,
        source_store,
        source_policy,
        parse_source,
        read_import_facts,
        read_scope_facts,
        resolve_import,
        resolve_star_imports,
    ):
        object.__setattr__(self, "source_store", source_store)
        object.__setattr__(self, "source_policy", source_policy)
        object.__setattr__(self, "parse_source", parse_source)
        object.__setattr__(self, "read_import_facts", read_import_facts)
        object.__setattr__(self, "read_scope_facts", read_scope_facts)
        object.__setattr__(self, "resolve_import", resolve_import)
        object.__setattr__(self, "resolve_star_imports", resolve_star_imports)


## Hold declarations collected while traversing one bounded source closure.
## 保存遍历单个有界源码闭包时收集的声明。
class _IndexDeclarations(FrozenRecord):
    _record_fields = (
        "functions",
        "constructors",
        "classes",
        "imports",
        "condition_nodes",
        "module_bodies",
    )

    ## Store collected declarations and module-level facts.
    ## 保存收集到的声明及模块级事实。
    #
    #  @param functions Indexed functions
    #  @param constructors Indexed constructors
    #  @param classes Indexed classes
    #  @param imports Module import aliases
    #  @param condition_nodes Conditional expressions grouped by source path
    #  @param module_bodies Module AST bodies used for star-import resolution
    def __init__(self, functions, constructors, classes, imports, condition_nodes, module_bodies):
        object.__setattr__(self, "functions", functions)
        object.__setattr__(self, "constructors", constructors)
        object.__setattr__(self, "classes", classes)
        object.__setattr__(self, "imports", imports)
        object.__setattr__(self, "condition_nodes", condition_nodes)
        object.__setattr__(self, "module_bodies", module_bodies)


## Load the producer APIs and source policy used by source indexing.
## 加载源码索引使用的生产者 API 和源码读取策略。
#
#  @return Immutable bundle of source-index build services
def _source_index_services():
    from pcresolve.import_facts import import_facts, resolve_relative_module
    from pcresolve.scope_facts import statement_scope_facts
    from pcresolve.source_snapshot import SourceReadPolicy, SourceStore
    from pcresolve.source_syntax import parse_python_source
    from pcresolve.star_imports import static_star_imports

    source_store_factory = SourceStore
    source_store = source_store_factory() if hasattr(SourceStore, "read_document") else None
    return _SourceIndexServices(
        source_store,
        SourceReadPolicy("tokenize", legacy_keyword_attributes=True),
        parse_python_source,
        import_facts,
        statement_scope_facts,
        resolve_relative_module,
        static_star_imports,
    )


## Build a source index and its bounded package-local import closure.
## 构建源码索引及有界的包内导入闭包。
#
#  @param source Source directory, file, or source context
#  @param target_api Optional API identity limiting indexed sources
#  @param source_files Optional explicit source file set
#  @return Source index with declarations, imports and scan boundaries
def build_source_index(
    source,
    *,
    target_api=None,
    source_files=None,
):
    services = _source_index_services()

    root = source.package_root.resolve()
    if not root.exists():
        raise FileNotFoundError("Package root does not exist: {}".format(root))
    import_roots = normalized_import_roots(source)
    # Reuse path computations only during this build; source contents are still checked
    # 路径计算仅在本次索引构建内复用，源码内容仍按原流程检查
    module_name = lru_cache(maxsize=None)(module_name_for_path)
    resolve_path = lru_cache(maxsize=None)(Path.resolve)
    dependency_modules = set(source.dependency_modules)

    # Seed the worklist with the requested API file and its package ancestors when available.
    # 有入口文件时，将请求的 API 文件及祖先包初始化文件加入工作队列。
    is_api_scope, entry_path, pending = _initial_sources(
        root, target_api, source_files, import_roots, dependency_modules, module_name, resolve_path
    )
    queued_qualnames = {}
    if is_api_scope and pending:
        assert target_api is not None and entry_path is not None
        queued_qualnames[entry_path] = {target_api.qualname}

    boundaries = []
    closure = _ImportClosure(
        root=root,
        import_roots=import_roots,
        target_api=target_api,
        dependency_modules=dependency_modules,
        module_name=module_name,
        resolve_path=resolve_path,
        read_import_facts=services.read_import_facts,
        resolve_import=services.resolve_import,
        read_scope_facts=services.read_scope_facts,
        pending=pending,
        queued=set(pending),
        queued_depth={path: 0 for path in pending},
        queued_qualnames=queued_qualnames,
        external_files={path for path in pending if not _within_source(path, root)},
        boundaries=boundaries,
    )
    declarations = closure.collect_declarations(services, is_api_scope)

    normalized_source = SourceContext(
        package_root=root,
        import_roots=import_roots,
        dependency_modules=tuple(sorted(dependency_modules)),
    )
    return _assemble_source_index(
        normalized_source,
        closure,
        declarations.functions,
        declarations.constructors,
        declarations.classes,
        declarations.imports,
        declarations.condition_nodes,
        services.source_store,
        is_api_scope,
        services.resolve_star_imports,
        declarations.module_bodies,
    )
