## @package vppdetector.source
#  Index source files and derive Python-signature facts.
#  建立源码索引并提取Python签名事实。

from __future__ import annotations

import ast
import tokenize
from collections import deque
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Iterable, List, Optional, Sequence, Tuple, Union

from .models import AnalysisBoundary, FunctionIdentity, SourceContext, VariadicKind


FunctionNode = Union[ast.FunctionDef, ast.AsyncFunctionDef]


## Store the parameter categories of one source function signature.
## 保存一个源码函数签名中的参数类别。
@dataclass(frozen=True)
class SignatureFacts:
    positional_only: Tuple[str, ...]
    positional_or_keyword: Tuple[str, ...]
    keyword_only: Tuple[str, ...]
    vararg: Optional[str]
    kwarg: Optional[str]

    ## Create signature facts from an AST argument list
    ## 根据AST参数列表创建签名事实
    #
    #  @param arguments Function definition's AST argument list
    #  @return SignatureFacts containing declared positional, keyword and variadic names
    @classmethod
    def from_arguments(cls, arguments):
        return cls(
            positional_only=tuple(arg.arg for arg in arguments.posonlyargs),
            positional_or_keyword=tuple(arg.arg for arg in arguments.args),
            keyword_only=tuple(arg.arg for arg in arguments.kwonlyargs),
            vararg=arguments.vararg.arg if arguments.vararg else None,
            kwarg=arguments.kwarg.arg if arguments.kwarg else None,
        )

    ## Check whether the signature accepts the requested variadic channel
    ## 检查签名是否接受指定的可变参数通道
    #
    #  @param kind Variadic channel or operation kind being checked
    #  @return Whether the requested positional or keyword variadic channel exists
    def accepts_variadic(self, kind):
        if kind is VariadicKind.KEYWORD:
            return self.kwarg is not None
        return self.vararg is not None


## Store a source function, its signature and its lookup context.
## 保存源码函数、签名及其查找上下文。
@dataclass
class IndexedFunction:
    identity: FunctionIdentity
    signature: SignatureFacts
    node: FunctionNode
    is_overload: bool
    is_bound_method: bool = False
    query_class: Optional[FunctionIdentity] = None
    query_alias: Optional[FunctionIdentity] = None

    ## Return the variadic parameter names and their channel kinds
    ## 返回可变参数名称及对应通道类型
    #
    #  @return Tuple of declared parameter names paired with their variadic kinds
    @property
    def variadic_parameters(self):
        parameters = []
        if self.signature.vararg:
            parameters.append((self.signature.vararg, VariadicKind.POSITIONAL))
        if self.signature.kwarg:
            parameters.append((self.signature.kwarg, VariadicKind.KEYWORD))
        return tuple(parameters)


## Associate a source class identity with its constructor implementation.
## 将源码类身份关联到其构造器实现。
@dataclass(frozen=True)
class IndexedConstructor:
    class_identity: FunctionIdentity
    function: IndexedFunction


## Index source functions, classes, imports and analysis boundaries.
## 索引源码函数、类、导入信息及分析边界。
@dataclass
class SourceIndex:
    source: SourceContext
    files: Tuple[Path, ...]
    functions: Tuple[IndexedFunction, ...]
    constructors: Tuple[IndexedConstructor, ...]
    boundaries: Tuple[AnalysisBoundary, ...]
    imports: dict = field(default_factory=dict)
    classes: Tuple[FunctionIdentity, ...] = ()
    is_api_scope: bool = False
    condition_nodes: dict = field(default_factory=dict, repr=False)
    source_store: object = field(default=None, repr=False, compare=False)
    _definition_index: object = field(default=None, init=False, repr=False)
    _location_members: Optional[tuple] = field(default=None, init=False, repr=False, compare=False)
    _function_locations: dict = field(default_factory=dict, init=False, repr=False, compare=False)
    _constructor_locations: dict = field(
        default_factory=dict, init=False, repr=False, compare=False
    )

    ## Find one indexed function matching the requested source identity
    ## 查找与请求源码身份匹配的索引函数
    #
    #  @param identity Source-level identity used for lookup
    #  @return Unique matching function, or None if the identity is absent or ambiguous
    def find(self, identity):
        requested_path = identity.file_path.resolve() if identity.file_path else None
        candidates = [
            function
            for function in self.functions
            if function.identity.module == identity.module
            and function.identity.qualname == identity.qualname
        ]
        if requested_path is not None:
            candidates = [
                function
                for function in candidates
                if function.identity.file_path
                and function.identity.file_path.resolve() == requested_path
            ]
        if identity.lineno:
            candidates = [
                function for function in candidates if function.identity.lineno == identity.lineno
            ]
        elif len(candidates) > 1:
            implementations = [function for function in candidates if not function.is_overload]
            if len(implementations) == 1:
                candidates = implementations
        return candidates[0] if len(candidates) == 1 else None

    ## Resolve an exact import-backed API or source class through PCResolve
    ## 通过PCResolve解析精确的导入API或源码类
    #
    #  @param identity Source-level identity used for lookup
    #  @return Resolved function or constructor, or None if it is absent or ambiguous
    def resolve_imported(self, identity):
        if identity.file_path or identity.lineno:
            constructors = [
                item.function
                for item in self.constructors
                if item.class_identity.module == identity.module
                and item.class_identity.qualname == identity.qualname
                and (
                    not identity.file_path
                    or item.class_identity.file_path
                    and item.class_identity.file_path.resolve() == identity.file_path.resolve()
                )
                and (not identity.lineno or item.class_identity.lineno == identity.lineno)
            ]
            return constructors[0] if len(constructors) == 1 else None

        definitions = self._definitions()
        function = definitions.resolve_name(identity.module, "", identity.qualname, self.imports)
        if function is not None:
            return function
        class_identity = definitions.resolve_name(
            identity.module, "", identity.qualname, self.imports, kind="class"
        )
        if class_identity is None:
            return None
        constructors = [
            item.function for item in self.constructors if item.class_identity == class_identity
        ]
        return constructors[0] if len(constructors) == 1 else None

    ## Locate a source class; invocation phase selection belongs to PCResolve
    ## 定位源码类；调用阶段由PCResolve确定
    #
    #  @param identity Source-level identity used for lookup
    #  @return Resolved source class identity, or None if absent or ambiguous
    def resolve_class(self, identity):
        if identity.file_path or identity.lineno:
            candidates = [item for item in self.classes
                if item.module == identity.module and item.qualname == identity.qualname
                and (not identity.file_path or item.file_path == identity.file_path.resolve())
                and (not identity.lineno or item.lineno == identity.lineno)]
            return candidates[0] if len(candidates) == 1 else None
        return self._definitions().resolve_name(
            identity.module, "", identity.qualname, self.imports, kind="class"
        )

    ## Canonicalize a class prefix; PCResolve still owns inherited lookup
    ## 规范化类前缀，但将继承查找交由PCResolve
    #
    #  @param identity Source-level identity used for lookup
    #  @return Canonical requested method identity, or None if its class cannot be resolved
    def resolve_method_identity(self, identity):
        function = self.find(identity)
        if function is not None:
            return function.identity
        if identity.file_path or identity.lineno:
            return None
        owner, separator, method = identity.qualname.rpartition(".")
        if not separator:
            return None
        class_identity = self._definitions().resolve_name(
            identity.module, "", owner, self.imports, kind="class"
        )
        if class_identity is None:
            return None

        # Location belongs to the requested method, not to its declaring class.
        # An inherited implementation can be in a different source module.
        # 位置提示属于请求的方法而非声明它的类；继承实现可能位于其他源码模块。
        return FunctionIdentity(class_identity.module, class_identity.qualname + "." + method)

    ## Build and cache the source definition lookup table
    ## 构建并缓存源码定义查找表
    #
    #  @return Cached PCResolve definition index for source functions and classes
    def _definitions(self):
        if self._definition_index is None:
            from pcresolve.call_resolution import DefinitionIndex, DefinitionRecord

            grouped = {}
            for function in self.functions:
                key = (function.identity.module, function.identity.qualname)
                grouped.setdefault(key, []).append(function)
            records = []
            for (module, qualname), functions in grouped.items():
                implementations = [function for function in functions if not function.is_overload]
                selected = implementations if len(implementations) == 1 else functions
                records.extend(
                    DefinitionRecord(module, qualname, function) for function in selected
                )
            records.extend(
                DefinitionRecord(
                    identity.module,
                    identity.qualname,
                    identity,
                    kind="class",
                )
                for identity in self.classes
            )
            self._definition_index = DefinitionIndex(records)
        return self._definition_index

    ## Look up an exact position within this fixed source snapshot
    ## 在固定源码快照中按精确位置查找定义
    #
    #  @param file_path Path of the source file
    #  @param lineno One-based source line of the function or class definition
    #  @param identity Optional identity restricting candidates at the source location
    #  @return Unique function or constructor at the location, or None if ambiguous or absent
    def find_by_location(
        self, file_path, lineno, *, identity=None
    ):
        self._prepare_locations()
        resolved = file_path.resolve()
        candidates = self._function_locations.get((resolved, lineno), ())
        if identity is not None:
            candidates = [function for function in candidates
                          if function.identity.module == identity.module
                          and function.identity.qualname == identity.qualname]
        if len(candidates) == 1:
            return candidates[0]
        constructors = self._constructor_locations.get((resolved, lineno), ())
        if identity is not None:
            constructors = [function for function in constructors
                            if function.identity.module == identity.module
                            and function.identity.qualname.rpartition('.')[0] == identity.qualname]
        return constructors[0] if len(constructors) == 1 else None

    ## Build source-position indexes for functions and constructors
    ## 为函数和构造器建立源码位置索引
    #
    def _prepare_locations(self):
        members = self._location_members
        if members is not None and members[0] is self.functions and members[1] is self.constructors:
            return
        paths, functions, constructors = {}, {}, {}

        ## Return the lookup position for one source identity
        ## 返回指定源码身份的查找位置
        #
        #  @param identity Source-level identity used for lookup
        #  @return Pair of resolved file path and definition line number
        def position(identity):
            path = identity.file_path
            if path not in paths:
                paths[path] = path.resolve()
            return paths[path], identity.lineno

        for function in self.functions:
            if function.identity.file_path:
                functions.setdefault(position(function.identity), []).append(function)
        for item in self.constructors:
            if item.class_identity.file_path:
                constructors.setdefault(position(item.class_identity), []).append(item.function)

        # Keep candidate lists: duplicates must remain ambiguous, and function
        # ambiguity retains the existing unique-constructor fallback.
        # 保留全部候选以维持重复定义的歧义；函数候选歧义仍沿用原有唯一构造器回退。
        self._function_locations = functions
        self._constructor_locations = constructors
        self._location_members = self.functions, self.constructors


## Collect source functions, constructors, lambdas and import facts.
## 收集源码函数、构造器、lambda及导入事实。
class _FunctionCollector(ast.NodeVisitor):
    ## Initialize the object state required by the enclosing class
    ## 初始化所属类所需的对象状态
    #
    #  @param module Python module name associated with the source
    #  @param file_path Path of the source file
    def __init__(self, module, file_path):
        self.module = module
        self.file_path = file_path
        self.scope = []
        self.scope_kinds = []
        self.functions = []
        self.constructors = []
        self.classes = []
        self.conditions = []

    ## Visit conditional definitions while retaining their source conditions
    ## 访问条件定义并保留其源码条件
    #
    #  @param node Conditional statement AST being visited
    def visit_If(self, node):
        self.conditions.append(node.test)
        self.generic_visit(node)

    ## Traverse the remaining AST structure using the collector policy
    ## 按照收集器策略遍历其余AST结构
    #
    #  @param node AST node whose child structure is visited
    def generic_visit(self, node):

        # Visit statement structure normally and collect expression lambdas
        # iteratively so giant expression trees cannot overflow this visitor.
        # 正常遍历语句结构，并迭代收集表达式中的lambda，避免大型表达式树导致访问器递归溢出。
        for child in ast.iter_child_nodes(node):
            if isinstance(child, ast.expr):
                self._collect_lambdas(child)
            else:
                self.visit(child)

    ## Collect lambda definitions from an expression without recursive overflow
    ## 从表达式中收集lambda定义并避免递归溢出
    #
    #  @param expression Expression AST to walk for lambda definitions
    def _collect_lambdas(self, expression):

        # An iterative expression walk keeps giant non-lambda expressions safe.
        # 对非lambda表达式也采用迭代遍历，避免深层语法树溢出。
        pending = [expression]
        while pending:
            node = pending.pop()
            if isinstance(node, ast.Lambda):
                name = '<lambda>@%s:%s' % (node.lineno, node.col_offset)

                # A statement view gives existing consumers an exact return body;
                # identity and all expression/call locations remain from the lambda.
                # 语句视图为现有消费者提供精确的返回体；身份及表达式、调用位置仍来自原lambda节点。
                returned = ast.copy_location(ast.Return(value=node.body), node.body)
                view = ast.copy_location(ast.FunctionDef(
                    name=name, args=node.args, body=[returned], decorator_list=[],
                    returns=None, type_comment=None,
                ), node)
                self.functions.append(IndexedFunction(
                    FunctionIdentity(self.module, '.'.join((*self.scope, name)),
                                     self.file_path, node.lineno),
                    SignatureFacts.from_arguments(node.args), view, False,
                ))
            pending.extend(ast.iter_child_nodes(node))

    ## Inspect a class node while resolving the requested definition
    ## 检查类节点并解析请求的定义
    #
    #  @param node Class definition AST being indexed
    def visit_ClassDef(self, node):
        class_qualname = ".".join((*self.scope, node.name))
        class_identity = FunctionIdentity(
            module=self.module,
            qualname=class_qualname,
            file_path=self.file_path,
            lineno=node.lineno,
        )
        self.classes.append(class_identity)
        constructor = None

        # Keep nominal constructor locations for source-position lookup.
        # AnalysisContext asks PCResolve for actual class invocation phases.
        # 保留构造器的名义位置以供源码定位；实际类调用阶段由AnalysisContext向PCResolve查询。
        for method in ("__init__", "__new__"):
            candidates = [
                item
                for item in node.body
                if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)) and item.name == method
            ]
            implementations = [
                item
                for item in candidates
                if not any(_is_overload_decorator(d) for d in item.decorator_list)
            ]
            if len(implementations) == 1:
                constructor = implementations[0]
                break
            if candidates:

                # A declared initializer with no unique implementation is not
                # evidence that construction instead uses the allocator body.
                # 声明的初始化器若没有唯一实现，并不能证明构造过程会改用分配器函数体。
                break
        if constructor is not None:
            constructor_identity = FunctionIdentity(
                module=self.module,
                qualname="{}.{}".format(class_qualname, constructor.name),
                file_path=self.file_path,
                lineno=constructor.lineno,
            )
            self.constructors.append(
                IndexedConstructor(
                    class_identity=class_identity,
                    function=IndexedFunction(
                        identity=constructor_identity,
                        signature=SignatureFacts.from_arguments(constructor.args),
                        node=constructor,
                        is_overload=False,
                        is_bound_method=True,
                    ),
                )
            )
        self.scope.append(node.name)
        self.scope_kinds.append("class")
        self.generic_visit(node)
        self.scope_kinds.pop()
        self.scope.pop()

    ## Inspect a function node while collecting matching API facts
    ## 检查函数节点并收集匹配的API事实
    #
    #  @param node Function definition AST being indexed
    def visit_FunctionDef(self, node):
        self._visit_function(node)

    ## Collect an async function using the shared function visitor
    ## 使用通用函数访问逻辑收集异步函数
    #
    #  @param node Async function definition AST being indexed
    def visit_AsyncFunctionDef(self, node):
        self._visit_function(node)

    ## Index one function and visit its source-level nested definitions
    ## 索引单个函数并访问其源码级嵌套定义
    #
    #  @param node Function or async-function definition AST being indexed
    def _visit_function(self, node):
        qualname = ".".join((*self.scope, node.name))
        identity = FunctionIdentity(
            module=self.module,
            qualname=qualname,
            file_path=self.file_path,
            lineno=node.lineno,
        )
        is_direct_class_member = bool(self.scope_kinds and self.scope_kinds[-1] == "class")
        is_static_method = any(
            _decorator_name(item).split(".")[-1] == "staticmethod" for item in node.decorator_list
        )
        self.functions.append(
            IndexedFunction(
                identity=identity,
                signature=SignatureFacts.from_arguments(node.args),
                node=node,
                is_overload=any(_is_overload_decorator(item) for item in node.decorator_list),
                is_bound_method=is_direct_class_member and not is_static_method,
            )
        )
        self.scope.append(node.name)
        self.scope_kinds.append("function")
        self.generic_visit(node)
        self.scope_kinds.pop()
        self.scope.pop()


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


## Find external modules receiving a directly forwarded variadic parameter
## 查找直接接收可变参数转发的外部模块
#
#  @param tree Parsed source tree whose imports are inspected
#  @param module Module name associated with the source file
#  @param import_facts PCResolve import-fact resolver
#  @param resolve_relative_module PCResolve relative-import resolver
#  @param statement_scope_facts PCResolve lexical binding resolver
#  @param is_package Whether the current module is a package
#  @param target_qualnames Optional target qualified names limiting forwarding analysis
#  @return Imported module and callable names reached by direct variadic forwarding
def _forwarded_import_modules(
    tree, module, is_package, import_facts, resolve_relative_module, statement_scope_facts,
    target_qualnames=None,
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


    # 被重新绑定或存在多次导入的名称不能作为确定的外部目标
    aliases = {
        name: target for name, target in aliases.items()
        if name not in rebound and counts[name] == 1
    }
    modules = set()
    if target_qualnames is not None:
        for binding in aliases:
            imported_qualname = imported_qualnames[binding]
            for target_qualname in target_qualnames:
                if target_qualname == imported_qualname:
                    forwarded_qualname = imported_qualname
                elif target_qualname.startswith(imported_qualname + "."):
                    forwarded_qualname = target_qualname
                else:
                    continue
                modules.add((dependency_roots[binding], forwarded_qualname))
    parents = {}
    for parent in ast.walk(tree):
        for child in ast.iter_child_nodes(parent):
            parents[child] = parent

    imported_targets = {
        name: (
            dependency_roots[name],
            imported_qualnames[name],
            imported_attribute_prefixes[name],
        )
        for name in aliases
    }
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
            local_functions.setdefault(parent_qualname, {}).setdefault(
                candidate.name, set()
            ).add(qualified)
        elif isinstance(candidate, ast.ClassDef):
            qualified = ".".join(part for part in (parent_qualname, candidate.name) if part)
            class_qualnames.add(qualified)
            class_bases[qualified] = tuple(
                base.id for base in candidate.bases if isinstance(base, ast.Name)
            )

    scope_alias_cache = {}

    ## Collect imported aliases visible in the selected scope
    ## 收集所选作用域内可见的导入别名
    #
    #  @param scope Lexical scope whose aliases are collected
    #  @return Aliases bound in the selected scope
    def aliases_for_scope(scope):
        cached = scope_alias_cache.get(id(scope))
        if cached is not None:
            return cached
        local_names = set(statement_scope_facts(scope.body).bound)
        arguments = scope.args
        local_names.update(
            argument.arg
            for argument in (
                arguments.posonlyargs + arguments.args + arguments.kwonlyargs
            )
        )
        if arguments.vararg:
            local_names.add(arguments.vararg.arg)
        if arguments.kwarg:
            local_names.add(arguments.kwarg.arg)
        result = {
            name: target for name, target in imported_targets.items()
            if name not in local_names
        }
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
                    assigned_targets.setdefault(target.id, set()).add(
                        imported_targets[value.id]
                    )
                else:
                    invalid_targets.add(target.id)
        for name, targets in assigned_targets.items():
            if len(targets) == 1 and name not in invalid_targets:
                result[name] = next(iter(targets))
        scope_alias_cache[id(scope)] = result
        return result


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
        forwards = any(
            keyword.arg is None and isinstance(keyword.value, ast.Name)
            and keyword.value.id == kwarg
            for keyword in node.keywords
        ) if kwarg else False
        if vararg:
            forwards = forwards or any(
                isinstance(argument, ast.Starred)
                and isinstance(argument.value, ast.Name)
                and argument.value.id == vararg
                for argument in node.args
            )
        if not forwards:
            continue

        if (isinstance(node.func, ast.Attribute)
                and node.func.attr == "__init__"
                and isinstance(node.func.value, ast.Call)
                and isinstance(node.func.value.func, ast.Name)
                and node.func.value.func.id == "super"
                and reachable is not None):
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
        scope_aliases = aliases_for_scope(scope) if isinstance(
            scope, (ast.FunctionDef, ast.AsyncFunctionDef)
        ) else imported_targets
        imported_target = scope_aliases.get(function.id)
        if imported_target is None:
            parent_qualname = scope_qualname.rpartition(".")[0]
            local_targets = local_functions.get(parent_qualname, {}).get(function.id, set())
            if len(local_targets) == 1 and reachable is not None:
                reachable.update(local_targets)
            continue
        dependency, imported_qualname, attribute_prefix = imported_target
        if attribute_prefix:
            if tuple(attributes[:len(attribute_prefix)]) != attribute_prefix:
                continue
            attributes = attributes[len(attribute_prefix):]
        forwarded_qualname = ".".join(
            part for part in (imported_qualname, *attributes) if part
        )
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
            relative = module[len(candidate) + 1:]
            if any(name == relative or name.startswith(relative + ".")
                   for name in qualnames):
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
            relative = candidate[len(module) + 1:]
            result.update(relative + "." + qualname for qualname in qualnames)
            continue
        if module.startswith(candidate + "."):
            relative = module[len(candidate) + 1:]
            for qualname in qualnames:
                if qualname.startswith(relative + "."):
                    result.add(qualname[len(relative) + 1:])
    return result


## Index all sources, or one located API's package-local import closure
## 索引完整源码，或构建指定API的包内导入闭包
#
#  @param source Library source directory, file, or source context
#  @param target_api Optional API identity limiting source indexing to its import closure
#  @return Index of the selected sources, functions, classes and import information
def build_source_index(
    source, *, target_api=None
):
    from pcresolve.import_facts import import_facts, resolve_relative_module
    from pcresolve.scope_facts import statement_scope_facts
    from pcresolve.source_snapshot import SourceReadPolicy, SourceStore
    from pcresolve.source_syntax import parse_python_source
    from pcresolve.star_imports import static_star_imports

    source_store = SourceStore() if hasattr(SourceStore, 'read_document') else None
    source_policy = SourceReadPolicy('tokenize', legacy_keyword_attributes=True)

    root = source.package_root.resolve()
    if not root.exists():
        raise FileNotFoundError("Package root does not exist: {}".format(root))
    import_roots = normalized_import_roots(source)
    # Reuse path computations only during this build; source contents are still checked
    # 路径计算仅在本次索引构建内复用，源码内容仍按原流程检查
    module_name = lru_cache(maxsize=None)(module_name_for_path)
    resolve_path = lru_cache(maxsize=None)(Path.resolve)
    dependency_modules = set(source.dependency_modules)
    discovered_dependency_modules = set()
    normalized_source = SourceContext(
        package_root=root,
        import_roots=import_roots,
        dependency_modules=tuple(sorted(dependency_modules)),
    )
    is_api_scope = target_api is not None and target_api.file_path is not None
    if is_api_scope:
        entry_path = target_api.file_path.resolve()
        if not _within_source(entry_path, root):
            raise ValueError("API file must be within the requested source root")
        pending = [entry_path] if entry_path.is_file() else []
        if pending:
            pending.extend(_package_initializers(
                entry_path, root, import_roots, dependency_modules,
                module_name=module_name, resolve_path=resolve_path
            ))
    else:
        pending = list(reversed(tuple(_python_files(root))))
    queued = set(pending)
    queued_depth = {path: 0 for path in pending}
    queued_qualnames = {}
    if is_api_scope and pending:
        queued_qualnames[entry_path] = {target_api.qualname}
    external_files = {path for path in pending if not _within_source(path, root)}
    visited = set()
    locations = {}
    functions = []
    constructors = []
    classes = []
    boundaries = []
    imports = {}
    module_bodies = {}
    condition_nodes = {}
    source_trees = {}
    processed_qualnames = {}

    while pending:
        file_path = pending.pop()
        target_qualnames = queued_qualnames.get(file_path, set())
        new_target_qualnames = target_qualnames - processed_qualnames.get(file_path, set())
        is_new_file = file_path not in visited
        if not is_new_file and not new_target_qualnames:
            continue
        if is_new_file:
            visited.add(file_path)
            try:
                if source_store is None:
                    with tokenize.open(file_path) as stream:
                        tree = parse_python_source(stream.read(), filename=str(file_path))
                else:

                    # Reuse only a document prepared with the same source policy.
                    # 只复用按相同源码策略准备的文档，保持原有编码和语法规则。
                    document = source_store.read_document(str(file_path), source_policy)
                    if document.error is not None:
                        if document.error_stage == 'parse':

                    # Retain VPP's filename-bearing syntax diagnostics.
                    # 保留VPP原有包含文件名的语法错误诊断。
                            parse_python_source(document.text, filename=str(file_path))
                        raise document.error
                    tree = document.tree
            except (OSError, SyntaxError, UnicodeError) as exc:
                boundaries.append(
                    AnalysisBoundary(
                        code="source_parse_failed",
                        message="{}: {}".format(file_path, exc),
                    )
                )
                continue
            source_trees[file_path] = tree
        else:
            tree = source_trees[file_path]
        module = module_name(file_path, import_roots)
        if is_new_file:
            module_bodies.setdefault(module, []).append((str(file_path), tree.body))
        aliases = {}
        imported_bindings = {}
        rebound = set()
        for statement in tree.body:
            facts = import_facts(statement)
            if not facts:
                rebound.update(statement_scope_facts([statement]).bound)
            for fact in facts:
                imported_bindings[fact.python_binding] = (
                    imported_bindings.get(fact.python_binding, 0) + 1
                )
                if fact.kind == "import":
                    aliases[fact.python_binding] = fact.name if fact.asname else fact.python_binding
                else:
                    prefix = (
                        resolve_relative_module(
                            module,
                            file_path.name.startswith("__init__."),
                            fact.module,
                            fact.level,
                        )
                        if fact.level
                        else fact.module
                    )
                    aliases[fact.python_binding] = prefix + "." + fact.name
        resolved_aliases = {
            name: target for name, target in aliases.items()
            if name not in rebound and imported_bindings[name] == 1
        }
        if is_api_scope:
            candidates = (
                _forwarded_import_modules(
                    tree,
                    module,
                    file_path.name == "__init__.py",
                    import_facts,
                    resolve_relative_module,
                    statement_scope_facts,
                    new_target_qualnames,
                )
                if new_target_qualnames else ()
            )
            processed_qualnames.setdefault(file_path, set()).update(new_target_qualnames)
            forwarded_qualnames = {}
            for candidate_module, candidate_qualname in candidates:
                forwarded_qualnames.setdefault(candidate_module, set()).add(candidate_qualname)
            for candidate_module, qualnames in tuple(forwarded_qualnames.items()):
                namespace = candidate_module.split(".", 1)[0]
                candidate_files = _module_files(
                    candidate_module, root, import_roots, (namespace,)
                )
                # A package-qualified call may name a submodule through the
                # imported package object, such as ``pkg.api.consume``.
                for qualname in qualnames:
                    parts = qualname.split(".")
                    for split in range(1, len(parts)):
                        nested_module = candidate_module + "." + ".".join(parts[:split])
                        nested_files = _module_files(
                            nested_module, root, import_roots, (namespace,)
                        )
                        if any(not _within_source(path, root) for path in nested_files):
                            forwarded_qualnames.setdefault(nested_module, set()).add(
                                ".".join(parts[split:])
                            )
                if not any(not _within_source(path, root) for path in candidate_files):
                    continue
                if namespace not in dependency_modules:
                    if len(discovered_dependency_modules) >= 16:
                        boundaries.append(AnalysisBoundary(
                            code="external_dependency_module_limit",
                            message="Variadic forwarding reached more than 16 external modules.",
                            function=target_api,
                        ))
                        continue
                    dependency_modules.add(namespace)
                    discovered_dependency_modules.add(namespace)
            for node in _import_statements(tree):
                for fact in import_facts(node):
                    if fact.kind == "import":
                        modules = (fact.name,)
                    else:
                        prefix = resolve_relative_module(
                            module, file_path.name == "__init__.py", fact.module, fact.level
                        )
                        modules = (prefix, prefix + "." + fact.name)
                    for name in modules:
                        related_modules = {name}
                        related_modules.update(
                            candidate for candidate in forwarded_qualnames
                            if candidate.startswith(name + ".")
                        )
                        for related_module in related_modules:
                            found = locations.get(related_module)
                            if found is None:
                                found = _module_files(
                                    related_module, root, import_roots, dependency_modules
                                )
                                if found:
                                    locations[related_module] = found
                            for dependency in found:
                                dependency_module = module_name(
                                    dependency, import_roots
                                )
                                if (not _within_source(dependency, root)
                                        and not _is_forwarded_module(
                                            dependency_module, forwarded_qualnames
                                        )):
                                    continue
                                dependency_namespace = dependency_module.split(".", 1)[0]
                                current_namespace = (
                                    module.split(".", 1)[0]
                                    if not _within_source(file_path, root)
                                    else None
                                )
                                dependency_depth = queued_depth.get(file_path, 0)
                                if (not _within_source(dependency, root)
                                        and dependency_namespace != current_namespace):
                                    dependency_depth += 1
                                if dependency_depth > 4:
                                    boundaries.append(AnalysisBoundary(
                                        code="external_dependency_depth_limit",
                                        message="Variadic forwarding exceeded four external module hops.",
                                        function=target_api,
                                    ))
                                    continue
                                selected_paths = (
                                    dependency,
                                    *_package_initializers(
                                        dependency, root, import_roots, dependency_modules,
                                        module_name=module_name, resolve_path=resolve_path
                                    ),
                                )
                                for selected in selected_paths:
                                    selected_module = module_name(
                                        selected, import_roots
                                    )
                                    selected_targets = _forwarded_qualnames_for_module(
                                        selected_module, forwarded_qualnames
                                    )
                                    if (not _within_source(selected, root)
                                            and not selected_targets):
                                        continue
                                    if selected_targets:
                                        known_targets = queued_qualnames.setdefault(selected, set())
                                        new_targets = selected_targets - known_targets
                                        known_targets.update(selected_targets)
                                    else:
                                        new_targets = set()
                                    if selected in queued and not new_targets:
                                        continue
                                    if (not _within_source(selected, root)
                                            and selected not in external_files
                                            and len(external_files) >= 128):
                                        boundaries.append(AnalysisBoundary(
                                            code="external_dependency_file_limit",
                                            message="Variadic forwarding exceeded 128 external source files.",
                                            function=target_api,
                                        ))
                                        continue
                                    new_file = selected not in queued
                                    if new_file:
                                        queued.add(selected)
                                        queued_depth[selected] = dependency_depth
                                        if not _within_source(selected, root):
                                            external_files.add(selected)
                                    if new_file or new_targets:
                                        pending.append(selected)
        imports[module] = resolved_aliases
        if is_new_file:
            collector = _FunctionCollector(module, file_path)
            collector.visit(tree)
            functions.extend(collector.functions)
            constructors.extend(collector.constructors)
            classes.extend(collector.classes)
            condition_nodes[file_path] = tuple(collector.conditions)

    star_facts = static_star_imports(module_bodies)
    for module, aliases in star_facts.aliases.items():
        imports[module].update(aliases)

    normalized_source = SourceContext(
        package_root=root,
        import_roots=import_roots,
        dependency_modules=tuple(sorted(dependency_modules)),
    )
    return SourceIndex(
        source=normalized_source,
        files=tuple(sorted(visited)),
        functions=tuple(
            sorted(functions, key=lambda item: (str(item.identity.file_path), item.node.lineno))
        ),
        constructors=tuple(
            sorted(
                constructors,
                key=lambda item: (str(item.function.identity.file_path), item.function.node.lineno),
            )
        ),
        boundaries=tuple(boundaries),
        imports=imports,
        classes=tuple(sorted(classes, key=lambda item: (str(item.file_path), item.lineno))),
        is_api_scope=is_api_scope,
        condition_nodes=condition_nodes,
        source_store=source_store,
    )


## Check whether a path is contained within a source root
## 检查路径是否位于源码根目录内
#
#  @param path Filesystem path of the source being read or checked
#  @param root Source file or directory limiting the lookup
#  @return Whether the path equals the source file or lies under the source directory
def _within_source(path, root):
    if root.is_file():
        return path == root
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


## Check whether a module belongs to an excluded dependency namespace
## 检查模块是否属于排除的依赖命名空间
#
#  @param module Python module name associated with the source
#  @param dependency_modules Module namespaces included as explicit dependencies
#  @return Whether the module equals or is nested under a dependency namespace
def _is_dependency_module(module, dependency_modules):
    return any(module == dependency or module.startswith(dependency + ".")
               for dependency in dependency_modules)


## Resolve source files belonging to one module name
## 解析指定模块名对应的源码文件
#
#  @param module Python module name associated with the source
#  @param root AST root or source root used for lookup
#  @param import_roots Module roots used to resolve source imports
#  @param dependency_modules Module namespaces included as explicit dependencies
#  @return Sorted tuple of matching source paths, retaining ambiguous candidates
def _module_files(
    module,
    root,
    import_roots,
    dependency_modules=(),
):
    parts = module.split(".")
    if not all(part.isidentifier() for part in parts):
        return ()
    files = set()
    for import_root in import_roots:
        stem = import_root.joinpath(*parts)
        for candidate in (stem.with_suffix(".py"), stem / "__init__.py"):
            if not candidate.is_file():
                continue
            path = candidate.resolve()
            if _within_source(path, root) or _is_dependency_module(module, dependency_modules):
                files.add(path)

    # Preserve ambiguous source candidates for PCResolve, never choose a root
    # or file/package collision as an implicit ownership decision.
    # 将歧义源码候选交给PCResolve处理；不得把导入根或文件/包冲突隐式判为所有权归属。
    return tuple(sorted(files))


## Return package initializer files for an import path
## 返回导入路径对应的包初始化文件
#
#  @param path Filesystem path of the source being read or checked
#  @param root AST root or source root used for lookup
#  @param import_roots Module roots used to resolve source imports
#  @param dependency_modules Module namespaces included as explicit dependencies
#  @param module_name Optional build-local module-name lookup
#  @param resolve_path Optional build-local path resolver
#  @return Iterator of eligible ancestor package initializer paths
def _package_initializers(
    path,
    root,
    import_roots,
    dependency_modules=(),
    *, module_name=None, resolve_path=None,
):
    module_name = module_name or module_name_for_path
    resolve_path = resolve_path or Path.resolve
    for import_root in import_roots:

        # A standalone file may itself be the inferred import root. There
        # cannot be an ancestor package chain ending at a file path.
        # 单独的源码文件本身可能是推断出的导入根；文件路径不可能再作为祖先包链的末端。
        if path == import_root:
            continue
        try:
            path.relative_to(import_root)
        except ValueError:
            continue
        parent = path.parent
        while parent != import_root:
            candidate = parent / "__init__.py"
            if candidate.is_file():
                resolved = resolve_path(candidate)
                module = module_name(resolved, import_roots)
                if (_within_source(resolved, root)
                        or _is_dependency_module(module, dependency_modules)):
                    yield resolved
            parent = parent.parent


## Resolve explicit import roots or infer a root from the source layout
## 解析显式导入根目录，或根据源码布局推断根目录
#
#  @param source Library source directory, file, or source context
#  @return Tuple of absolute import roots in their configured order
def normalized_import_roots(source):
    if source.import_roots:
        return tuple(path.resolve() for path in source.import_roots)
    root = source.package_root.resolve()
    if root.is_file():
        return (root.parent,)
    if (root / "__init__.py").is_file():
        return (root.parent,)
    source_root = root / "src"
    if source_root.is_dir():
        return (source_root,)
    return (root,)


## Derive a Python module name from a file and its import roots
## 根据源码文件及导入根目录推导Python模块名
#
#  @param file_path Path of the source file
#  @param import_roots Module roots used to resolve source imports
#  @return Dotted module name, or the file stem if no import root contains the path
def module_name_for_path(file_path, import_roots):
    for import_root in import_roots:
        try:
            relative = file_path.resolve().relative_to(import_root.resolve())
        except ValueError:
            continue
        parts = list(relative.parts)
        if not parts:
            continue
        filename = parts.pop()
        stem = Path(filename).stem
        if stem != "__init__":
            parts.append(stem)
        return ".".join(parts)
    return file_path.stem


## Enumerate Python source files under the requested root
## 枚举指定根目录下的Python源码文件
#
#  @param root AST root or source root used for lookup
#  @return Iterator over eligible Python paths; a directly supplied .pyi file is included
def _python_files(root):
    if root.is_file():
        if root.suffix in {".py", ".pyi"}:
            yield root
        return
    for path in sorted(root.rglob("*.py")):
        if not any(part in {".git", ".tox", ".venv", "venv", "__pycache__"} for part in path.parts):
            yield path.resolve()


## Read the dotted name of a source decorator expression
## 读取源码装饰器表达式的点分隔名称
#
#  @param node Decorator expression AST to inspect
#  @return Dotted decorator name, or an empty string for unsupported syntax
def _decorator_name(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _decorator_name(node.value)
        return "{}.{}".format(prefix, node.attr) if prefix else node.attr
    if isinstance(node, ast.Call):
        return _decorator_name(node.func)
    return ""


## Check whether a function is marked as a typing overload
## 检查函数是否标记为typing重载
#
#  @param node Decorator expression AST to inspect
#  @return Whether the decorator's final name component is overload
def _is_overload_decorator(node):
    return _decorator_name(node).split(".")[-1] == "overload"
