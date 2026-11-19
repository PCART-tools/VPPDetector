## @package vppdetector.assess.observations.contextvar_packages
#  Build indexes for ContextVar package initialization proofs.
#
#
#  Discover package modules, build declaration and import indexes, and start a bounded scan for
#  writes to the selected ContextVar.
#  发现包模块，构建声明和导入索引，并启动对目标 ContextVar 写入的有界扫描。



import ast
import hashlib
import importlib.machinery
import io
import tokenize
from pathlib import Path

from ...source import module_name_for_path
from .contextvar_package_scan import PackageScanState, _scan_package_initialization
from .contextvar_support import _assignment, _module_imports


## Resolve a name or attribute through one module's imported-name index.
## 通过模块导入名称索引解析名称或属性。
#
#  @param imports Imported-name indexes by module
#  @param module Module containing the expression
#  @param expression Name or attribute expression
#  @return Qualified imported name or None when unsupported
def _imported_target(imports, module, expression):
    if isinstance(expression, ast.Name):
        return imports[module].get(expression.id, module + "." + expression.id)
    if isinstance(expression, ast.Attribute):
        parent = _imported_target(imports, module, expression.value)
        return parent + "." + expression.attr if isinstance(parent, str) else None
    return None


## Check whether source syntax contains only bounded literal values.
## 检查源码表达式是否只包含有界字面量。
#
#  @param node Source syntax node
#  @return Whether the node is a supported literal container
def _literal_container(node):
    if isinstance(node, (ast.Constant, ast.NameConstant)):
        return True
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        return all(_literal_container(item) for item in node.elts)
    if isinstance(node, ast.Dict):
        return all(
            key is not None and _literal_container(key) and _literal_container(value)
            for key, value in zip(node.keys, node.values)
        )
    return False


## Parse a module and record the hash of its original bytes.
## 解析模块并记录原始字节的哈希。
#
#  @param path Source file to read
#  @param source_hashes Mutable mapping receiving the source hash on success
#  @return Parsed syntax tree, or None if reading or parsing fails
def _read_module(path, source_hashes):
    resolved = Path(path).resolve()
    try:
        raw = resolved.read_bytes()
        encoding, _ = tokenize.detect_encoding(io.BytesIO(raw).readline)
        text = raw.decode(encoding).replace("\r\n", "\n").replace("\r", "\n")
        tree = ast.parse(text, filename=str(resolved))
    except (OSError, UnicodeError, SyntaxError, LookupError, RecursionError, tokenize.TokenError):
        return None
    source_hashes[str(resolved)] = hashlib.sha256(raw).hexdigest()
    return tree


## Discover and parse package modules and indexed dependencies.
## 发现并解析包模块和已索引的依赖。
#
#  @param context Analysis context providing source roots and indexed files
#  @param packages Package names to inspect
#  @return Module map and source hashes, or None when discovery is incomplete
def _discover_package_modules(context, packages):
    modules = {}
    source_hashes = {}
    for package in packages:
        found_package = False
        for root in context.index.source.import_roots:
            package_root = Path(root).joinpath(*package.split("."))
            paths = list(package_root.rglob("*.py")) if package_root.is_dir() else []
            package_module = Path(root).joinpath(*package.split(".")).with_suffix(".py")
            if package_module.is_file():
                paths.append(package_module)
            found_package |= bool(paths)
            for path in paths:
                resolved = path.resolve()
                module = module_name_for_path(resolved, context.index.source.import_roots)
                if not module:
                    return None
                tree = _read_module(resolved, source_hashes)
                if tree is None:
                    return None
                previous = modules.get(module)
                if previous is not None and previous[0] != resolved:
                    return None
                modules[module] = (resolved, tree)
        if not found_package:
            return None

    # Include indexed dependencies outside the proxy's top-level package.
    # 同时纳入代理所属顶层包之外已建立索引的依赖。
    for path in context.index.files:
        resolved = Path(path).resolve()
        module = module_name_for_path(resolved, context.index.source.import_roots)
        if not module:
            return None
        previous = modules.get(module)
        if previous is not None:
            if previous[0] != resolved:
                return None
            continue
        tree = _read_module(resolved, source_hashes)
        if tree is None:
            return None
        modules[module] = (resolved, tree)
    return modules, source_hashes


## Add one parsed module and its declarations to the package indexes.
## 将一个已解析模块及其声明加入包索引。
#
#  @param context Analysis context used to resolve imports
#  @param modules Mutable module map
#  @param imports Mutable module import map
#  @param functions Mutable top-level function and class map
#  @param classes Mutable top-level class map
#  @param module Qualified module name
#  @param path Source file path
#  @param tree Parsed module syntax tree
def _register_module(
    context,
    modules,
    imports,
    functions,
    classes,
    module,
    path,
    tree,
):
    modules[module] = (path, tree)
    imports[module] = _module_imports(context, module, path, tree)
    for item in tree.body:
        if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            functions[(module, item.name)] = item
            if isinstance(item, ast.ClassDef):
                classes[(module, item.name)] = item


## Build declaration and import indexes for the discovered modules.
## 为已发现模块构建声明和导入索引。
#
#  @param context Analysis context used to resolve imports
#  @param modules Mapping from module names to source paths and syntax trees
#  @return Function, class and import indexes
def _index_modules(context, modules):
    functions = {}
    classes = {}
    imports = {}
    for module, (path, tree) in modules.items():
        _register_module(context, modules, imports, functions, classes, module, path, tree)
    return functions, classes, imports


## Own package source indexes and load uniquely resolved modules on demand.
## 持有包源码索引并按需加载唯一解析的模块。
class _PackageModuleIndex:
    ## Initialize one package source index and its mutable lookup tables.
    ## 初始化一次包源码索引及其可变查询表。
    #
    #  @param context Analysis context providing source roots and import resolution
    #  @param modules Discovered source modules
    #  @param source_hashes Raw source digests collected during discovery
    #  @param functions Top-level function declarations
    #  @param classes Top-level class declarations
    #  @param imports Resolved import aliases by module
    #  @param contextvar_identity Defining module and name of the tracked ContextVar
    def __init__(
        self,
        context,
        modules,
        source_hashes,
        functions,
        classes,
        imports,
        contextvar_identity,
    ):
        self.context = context
        self.modules = modules
        self.source_hashes = source_hashes
        self.functions = functions
        self.classes = classes
        self.imports = imports
        self.contextvar_identity = contextvar_identity

    ## Resolve a name or attribute through one module's imported-name index.
    ## 通过模块导入名称索引解析名称或属性。
    #
    #  @param module Module containing the expression
    #  @param expression Name or attribute expression
    #  @return Qualified imported name or None when unsupported
    def imported_target(self, module, expression):
        return _imported_target(self.imports, module, expression)

    ## Find a local function from the declaration index.
    ## 从声明索引中查找本地函数。
    #
    #  @param module Module containing the definition
    #  @param name Function name
    #  @return Function definition or None when absent or ambiguous
    def local_function(self, module, name):
        function = self.functions.get((module, name))
        return function if isinstance(function, (ast.FunctionDef, ast.AsyncFunctionDef)) else None

    ## Find the longest indexed module prefix for a qualified target.
    ## 查找限定目标对应的最长已索引模块前缀。
    #
    #  @param target Qualified target name
    #  @return Module name or None when no prefix is indexed
    def source_module(self, target):
        if not isinstance(target, str):
            return None
        parts = target.split(".")
        for end in range(len(parts), 0, -1):
            module = ".".join(parts[:end])
            if module in self.modules:
                return module
        return None

    ## Check whether a source or extension module is available in the import roots.
    ## 检查导入根中是否存在源码模块或扩展模块。
    #
    #  @param target Qualified target name
    #  @return Whether an importable module prefix is present
    def module_is_available(self, target):
        parts = target.split(".")
        for root in self.context.index.source.import_roots:
            base = Path(root)
            for end in range(1, len(parts) + 1):
                stem = base.joinpath(*parts[:end])
                if stem.with_suffix(".py").is_file() or (stem / "__init__.py").is_file():
                    return True
                if any(
                    stem.with_suffix(suffix).is_file()
                    for suffix in importlib.machinery.EXTENSION_SUFFIXES
                ):
                    return True
        return False

    ## Check whether a call is protected by an ImportError handler.
    ## 检查调用是否处于 ImportError 处理器保护之下。
    #
    #  @param module Module containing the call
    #  @param call Call expression being inspected
    #  @return Whether an enclosing try body catches ImportError
    def import_error_is_caught(self, module, call):
        source = self.modules.get(module)
        if source is None:
            return False
        parents = {
            child: parent
            for parent in ast.walk(source[1])
            for child in ast.iter_child_nodes(parent)
        }
        current = call
        while current in parents:
            current = parents[current]
            if isinstance(current, ast.Try) and any(
                call in list(ast.walk(item)) for item in current.body
            ):
                return any(
                    isinstance(handler.type, ast.Name)
                    and handler.type.id == "ImportError"
                    or isinstance(handler.type, ast.Tuple)
                    and any(
                        isinstance(item, ast.Name) and item.id == "ImportError"
                        for item in handler.type.elts
                    )
                    for handler in current.handlers
                )
        return False

    ## Check whether a node contains only bounded literal values.
    ## 检查节点是否只包含有界字面量。
    #
    #  @param node Source syntax node
    #  @return Whether the node is a supported literal container
    def literal_container(self, node):
        return _literal_container(node)

    ## Load a uniquely resolved target module within the package scan limit.
    ## 在包扫描上限内加载唯一解析的目标模块。
    #
    #  @param target Qualified target name
    #  @return Whether the target module was loaded or already present
    def load_target_module(self, target):
        if not isinstance(target, str):
            return False
        parts = target.split(".")

        # Try the longest module prefix first so a member name can be resolved through its module.
        # 先尝试最长的模块前缀，以便通过所属模块解析成员名。
        for end in range(len(parts), 0, -1):
            module = ".".join(parts[:end])
            if module in self.modules:
                return True
            paths = []
            for root in self.context.index.source.import_roots:
                stem = Path(root).joinpath(*module.split("."))
                paths.extend(
                    path.resolve()
                    for path in (stem.with_suffix(".py"), stem / "__init__.py")
                    if path.is_file()
                )
            paths = list(dict.fromkeys(paths))
            if not paths:
                continue
            if len(paths) != 1 or len(self.modules) >= 256:
                return False
            tree = _read_module(paths[0], self.source_hashes)
            if tree is None:
                return False
            _register_module(
                self.context,
                self.modules,
                self.imports,
                self.functions,
                self.classes,
                module,
                paths[0],
                tree,
            )
            return True
        return False

    ## Resolve a qualified name to one indexed function or constructor.
    ## 将限定名称解析为一个已索引函数或构造方法。
    #
    #  @param target Qualified target name
    #  @return Definition node or None when unresolved or ambiguous
    def function_target(self, target):
        if not isinstance(target, str):
            return None
        parts = target.split(".")
        for end in range(len(parts), 0, -1):
            module = ".".join(parts[:end])
            if module not in self.modules:
                continue
            qualname = parts[end:]
            if len(qualname) == 1:
                function = self.functions.get((module, qualname[0]))
                if isinstance(function, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    return function
                class_node = self.classes.get((module, qualname[0]))
                if class_node is not None:
                    initializers = [
                        item
                        for item in class_node.body
                        if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))
                        and item.name == "__init__"
                    ]
                    return initializers[0] if len(initializers) == 1 else None
            if len(qualname) == 2:
                class_node = self.classes.get((module, qualname[0]))
                if class_node is not None and qualname[1] == "__init__":
                    methods = [
                        item
                        for item in class_node.body
                        if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))
                        and item.name == "__init__"
                    ]
                    return methods[0] if len(methods) == 1 else None
            return None
        return None

    ## Resolve a qualified name to an indexed source class.
    ## 将限定名称解析为已索引源码类。
    #
    #  @param target Qualified target name
    #  @return Module and class node, or None when unresolved
    def class_target(self, target):
        if not isinstance(target, str):
            return None
        parts = target.split(".")
        for end in range(len(parts), 0, -1):
            module = ".".join(parts[:end])
            if module not in self.modules:
                self.load_target_module(module)
            if (
                module in self.modules
                and len(parts) == end + 1
                and (module, parts[end]) in self.classes
            ):
                return module, self.classes[(module, parts[end])]
        return None

    ## Prove that construction and inherited constructors have no indexed effects.
    ## 证明构造及继承构造方法没有已索引的副作用。
    #
    #  @param module Module containing the class
    #  @param class_node Source class definition
    #  @param visited Optional identities already checked in this proof
    #  @return Whether construction is proven inert
    def constructor_is_inert(self, module, class_node, visited=None):
        visited = set() if visited is None else visited
        key = (module, class_node.name)
        if (
            key in visited
            or class_node.decorator_list
            or any(item.arg == "metaclass" for item in class_node.keywords)
        ):
            return False
        visited.add(key)
        methods = {
            item.name
            for item in class_node.body
            if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))
        }
        if "__init__" in methods or "__new__" in methods:
            return False
        builtin_bases = {
            "bool", "bytes", "dict", "float", "frozenset", "int", "list",
            "object", "set", "str", "tuple",
        }

        # Every supported base must leave constructor effects provably inert.
        # 每个受支持的基类都必须能证明其构造行为无相关副作用。
        for base in class_node.bases:
            target = _imported_target(self.imports, module, base)
            if (
                isinstance(base, ast.Name)
                and base.id in builtin_bases
                and base.id not in self.imports[module]
            ):
                continue
            resolved = self.class_target(target)
            if resolved is None or not self.constructor_is_inert(*resolved, visited):
                return False
        return True

    ## Check whether source syntax references the selected ContextVar.
    ## 检查源码语法是否引用所选 ContextVar。
    #
    #  @param module Module containing the syntax
    #  @param node Source syntax node
    #  @return Whether the selected ContextVar is referenced
    def references_contextvar(self, module, node):
        if self.contextvar_identity is None:
            return False
        for item in ast.walk(node):
            if isinstance(item, ast.Name):
                if (module, item.id) == self.contextvar_identity:
                    return True
                if self.imports[module].get(item.id) == ".".join(self.contextvar_identity):
                    return True
            elif isinstance(item, ast.Attribute):
                target = _imported_target(self.imports, module, item)
                if target == ".".join(self.contextvar_identity):
                    return True
        return False

    ## Recognize reads from a known namespace or literal mapping.
    ## 识别已知命名空间或字面量映射的读取。
    #
    #  @param module Module containing the call
    #  @param call Call expression being inspected
    #  @return Whether the call reads a recognized mapping
    def reads_known_mapping(self, module, call):
        if not isinstance(call.func, ast.Attribute) or call.func.attr not in {
            "get", "items", "keys", "values",
        }:
            return False
        if (
            isinstance(call.func.value, ast.Call)
            and isinstance(call.func.value.func, ast.Name)
            and call.func.value.func.id in {"globals", "locals"}
            and call.func.value.func.id not in self.imports[module]
        ):
            return True
        if not isinstance(call.func.value, ast.Name):
            return False
        source = self.modules.get(module)
        if source is None:
            return False
        value = _assignment(source[1], call.func.value.id)
        return isinstance(value, ast.Dict)


## Run one package initialization proof with isolated traversal state.
## 使用独立遍历状态执行一次包初始化证明。
class _PackageScanSession:
    ## Create the per-proof scanner around one module index.
    ## 围绕一个模块索引创建单次证明扫描器。
    #
    #  @param module_index Module and source-fact index for this proof
    def __init__(self, module_index):
        self.state = PackageScanState(module_index, set())

    ## Scan each initially discovered module for an unruled-out ContextVar write.
    ## 扫描初始发现的各模块，判断是否存在无法排除的 ContextVar 写入。
    #
    #  @return Whether the package proof is inconclusive or finds a write
    def has_unproven_write(self):
        for module, (_, tree) in tuple(self.state.index.modules.items()):
            if _scan_package_initialization(
                self.state, tree, module, execute_definitions=True
            ):
                return True
        return False


## Inspect package initialization for writes to a selected ContextVar.
## 检查包初始化是否写入选定的 ContextVar。
#
#  @param context Analysis context for source discovery
#  @param packages Package names to inspect
#  @param contextvar_identity Identity of the selected ContextVar, when known
#  @return Package proof, or True when a write cannot be ruled out
def _package_sets_contextvar(
    context,
    packages,
    contextvar_identity=None,
):
    discovered = _discover_package_modules(context, packages)
    if discovered is None:
        return True
    modules, source_hashes = discovered

    functions, classes, imports = _index_modules(context, modules)
    module_index = _PackageModuleIndex(
        context,
        modules,
        source_hashes,
        functions,
        classes,
        imports,
        contextvar_identity,
    )
    session = _PackageScanSession(module_index)
    if session.has_unproven_write():
        return True
    return {
        "state": "no_contextvar_write",
        "source_hashes": source_hashes,
        "assumptions": [
            "source_snapshot_bindings_hold",
            "no_external_monkeypatch_or_import_hook",
            "all_relevant_import_source_is_available",
        ],
    }
