## @package vppdetector.source.index
#  Core source index and AST declaration collector.
#
#
#  Collect AST declarations and provide lookups for indexed functions, classes and constructors.
#  收集 AST 声明，并提供已索引函数、类和构造器的查询。



import ast

from .._records import FACTORY_DEFAULT, MutableRecord
from ..models import FunctionIdentity
from .records import IndexedConstructor, IndexedFunction, SignatureFacts


## Index source declarations and their lookup locations for one source context.
## 索引一个源码上下文中的声明及其查找位置。
class SourceIndex(MutableRecord):
    _record_fields = (
        "source",
        "files",
        "functions",
        "constructors",
        "boundaries",
        "imports",
        "classes",
        "is_api_scope",
        "condition_nodes",
        "source_store",
        "_definition_index",
        "_location_members",
        "_function_locations",
        "_constructor_locations",
    )
    _record_compare_fields = tuple(
        name
        for name in _record_fields
        if name
        not in {
            "source_store",
            "_location_members",
            "_function_locations",
            "_constructor_locations",
        }
    )
    _record_repr_fields = tuple(
        name
        for name in _record_fields
        if name
        not in {
            "condition_nodes",
            "source_store",
            "_definition_index",
            "_location_members",
            "_function_locations",
            "_constructor_locations",
        }
    )
    __match_args__ = (
        "source",
        "files",
        "functions",
        "constructors",
        "boundaries",
        "imports",
        "classes",
        "is_api_scope",
        "condition_nodes",
        "source_store",
    )

    ## Initialize a SourceIndex instance with its declared state.
    ## 使用声明的状态初始化 SourceIndex 实例。
    #
    #  @param source Value stored in the `source` field
    #  @param files Value stored in the `files` field
    #  @param functions Value stored in the `functions` field
    #  @param constructors Value stored in the `constructors` field
    #  @param boundaries Value stored in the `boundaries` field
    #  @param imports Input used to initialize the SourceIndex instance
    #  @param classes Value stored in the `classes` field
    #  @param is_api_scope Value stored in the `is_api_scope` field
    #  @param condition_nodes Input used to initialize the SourceIndex instance
    #  @param source_store Value stored in the `source_store` field
    def __init__(
        self,
        source,
        files,
        functions,
        constructors,
        boundaries,
        imports=FACTORY_DEFAULT,
        classes=(),
        is_api_scope=False,
        condition_nodes=FACTORY_DEFAULT,
        source_store=None,
    ):
        self.source = source
        self.files = files
        self.functions = functions
        self.constructors = constructors
        self.boundaries = boundaries
        self.imports = {} if imports is FACTORY_DEFAULT else imports
        self.classes = classes
        self.is_api_scope = is_api_scope
        self.condition_nodes = {} if condition_nodes is FACTORY_DEFAULT else condition_nodes
        self.source_store = source_store
        self._definition_index = None
        self._location_members = None
        self._function_locations = {}
        self._constructor_locations = {}

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
            candidates = [
                item
                for item in self.classes
                if item.module == identity.module
                and item.qualname == identity.qualname
                and (not identity.file_path or item.file_path == identity.file_path.resolve())
                and (not identity.lineno or item.lineno == identity.lineno)
            ]
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
            from pcresolve.call_resolution import (
                DefinitionIndex,
                DefinitionRecord,
            )

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
            self._definition_index = DefinitionIndex(tuple(records))
        return self._definition_index

    ## Look up an exact position within this fixed source snapshot
    ## 在固定源码快照中按精确位置查找定义
    #
    #  @param file_path Path of the source file
    #  @param lineno One-based source line of the function or class definition
    #  @param identity Optional identity restricting candidates at the source location
    #  @return Unique function or constructor at the location, or None if ambiguous or absent
    def find_by_location(
        self,
        file_path,
        lineno,
        *,
        identity=None,
    ):
        self._prepare_locations()
        resolved = file_path.resolve()
        candidates = self._function_locations.get((resolved, lineno), [])
        if identity is not None:
            candidates = [
                function
                for function in candidates
                if function.identity.module == identity.module
                and function.identity.qualname == identity.qualname
            ]
        if len(candidates) == 1:
            return candidates[0]
        constructors = self._constructor_locations.get((resolved, lineno), [])
        if identity is not None:
            constructors = [
                function
                for function in constructors
                if function.identity.module == identity.module
                and function.identity.qualname.rpartition(".")[0] == identity.qualname
            ]
        return constructors[0] if len(constructors) == 1 else None

    ## Build source-position indexes for functions and constructors
    ## 为函数和构造器建立源码位置索引
    #
    def _prepare_locations(self):
        members = self._location_members
        if members is not None and members[0] is self.functions and members[1] is self.constructors:
            return

        # Rebuild the location tables together when either declaration collection has changed.
        # 任一声明集合变化时，一起重建两张位置索引表。
        paths = {}
        functions = {}
        constructors = {}

        ## Return the lookup position for one source identity
        ## 返回指定源码身份的查找位置
        #
        #  @param identity Source-level identity used for lookup
        #  @return Pair of resolved file path and definition line number
        def position(identity):
            path = identity.file_path
            assert path is not None
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
                name = "<lambda>@%s:%s" % (node.lineno, node.col_offset)

                # A statement view gives existing consumers an exact return body;
                # identity and all expression/call locations remain from the lambda.
                # 语句视图为现有消费者提供精确的返回体；身份及表达式、调用位置仍来自原lambda节点。
                returned = ast.copy_location(ast.Return(value=node.body), node.body)
                view = ast.copy_location(
                    ast.FunctionDef(
                        name=name,
                        args=node.args,
                        body=[returned],
                        decorator_list=[],
                        returns=None,
                        type_comment=None,
                    ),
                    node,
                )
                self.functions.append(
                    IndexedFunction(
                        FunctionIdentity(
                            self.module, ".".join((*self.scope, name)), self.file_path, node.lineno
                        ),
                        SignatureFacts.from_arguments(node.args),
                        view,
                        False,
                    )
                )
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

        # Visit nested declarations with the class scope active, then restore the enclosing scope.
        # 在类作用域中访问嵌套声明，结束后恢复外层作用域。
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


## Resolve the dotted source spelling of a decorator expression.
## 解析装饰器表达式在源码中的点分名称。
#
#  @param node Decorator expression node
#  @return Dotted decorator name, or an empty string when unsupported
def _decorator_name(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _decorator_name(node.value)
        return "{}.{}".format(prefix, node.attr) if prefix else node.attr
    if isinstance(node, ast.Call):
        return _decorator_name(node.func)
    return ""


## Check whether a function uses an overload decorator.
## 检查函数是否使用 overload 装饰器。
#
#  @param node Decorator expression node
#  @return Whether its final name component is overload
def _is_overload_decorator(node):
    return _decorator_name(node).split(".")[-1] == "overload"
