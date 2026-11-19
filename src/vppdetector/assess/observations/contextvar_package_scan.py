## @package vppdetector.assess.observations.contextvar_package_scan
#  Traverse package initialization while checking ContextVar writes.
#
#
#  Walk initialization nodes and follow supported calls and imports using traversal state owned
#  by one package scan.
#  使用单次包扫描拥有的遍历状态检查初始化节点，跟进受支持的调用和导入。



import ast

from ..._records import MutableRecord


## Hold only traversal-local state for one package initialization scan.
## 仅保存一次包初始化扫描的遍历局部状态。
#
class PackageScanState(MutableRecord):
    _record_fields = ("index", "reached")
    __match_args__ = _record_fields

    ## Initialize traversal state for one package proof.
    ## 初始化一次包证明的遍历状态。
    #
    #  @param index Package source index and lookup operations
    #  @param reached Function paths already visited by this scan
    def __init__(self, index, reached):
        self.index = index
        self.reached = reached


## Follow a literal dynamic import when its source can be resolved.
## 在源码可解析时跟踪字面量动态导入。
#
#  @param state Package indexes and source-resolution operations
#  @param current Call expression being inspected
#  @param current_module Module containing the call
#  @param execute_current_definitions Whether definition annotations are evaluated
#  @param active_contextvar Whether the selected ContextVar is active in this path
#  @param pending Traversal worklist receiving child nodes
#  @return True for an unproven safe path, False when handled, or None if not applicable
def _scan_dynamic_import(
    state,
    current,
    current_module,
    execute_current_definitions,
    active_contextvar,
    pending,
):
    if not (
        isinstance(current.func, ast.Name)
        and current.func.id == "__import__"
        and current.func.id not in state.index.imports[current_module]
        and current.args
        and isinstance(current.args[0], ast.Constant)
        and isinstance(current.args[0].value, str)
    ):
        return None
    imported_module = current.args[0].value
    if not state.index.load_target_module(imported_module):
        import_is_available = state.index.module_is_available(imported_module)
        if not import_is_available and state.index.import_error_is_caught(
            current_module, current
        ):
            pending.extend(
                (item, current_module, execute_current_definitions, active_contextvar)
                for item in ast.iter_child_nodes(current)
            )
            return False
        return True

    # Scan the imported initializer before continuing through the remaining import work.
    # 先扫描导入模块的初始化代码，再继续处理剩余的导入工作。
    imported_tree = state.index.modules[imported_module][1]
    if _scan_package_initialization(state, imported_tree, imported_module, True, active_contextvar):
        return True
    pending.extend(
        (item, current_module, execute_current_definitions, active_contextvar)
        for item in ast.iter_child_nodes(current)
    )
    return False


## Inspect one call and enqueue supported source-backed execution.
## 检查单个调用并将受支持的源码执行加入待处理队列。
#
#  @param state Package indexes and source-resolution operations
#  @param current Call expression being inspected
#  @param current_module Module containing the call
#  @param execute_current_definitions Whether definition annotations are evaluated
#  @param active_contextvar Whether the selected ContextVar is active in this path
#  @param pending Traversal worklist receiving reachable nodes
#  @return True for an unproven safe path, False when handled, or None to traverse children
def _scan_call(
    state,
    current,
    current_module,
    execute_current_definitions,
    active_contextvar,
    pending,
):
    if isinstance(current, ast.Call):
        target = state.index.imported_target(current_module, current.func)
        function = state.index.function_target(target)
        if function is None:
            dynamic_import = _scan_dynamic_import(
                state,
                current,
                current_module,
                execute_current_definitions,
                active_contextvar,
                pending,
            )
            if dynamic_import is not None:
                return dynamic_import
        if (
            function is None
            and isinstance(current.func, ast.Name)
            and target == current_module + "." + current.func.id
        ):
            function = state.index.local_function(current_module, current.func.id)
        if function is None and state.index.load_target_module(target):
            function = state.index.function_target(target)
        if function is None:
            class_match = state.index.class_target(target)
            arguments = current.args + [item.value for item in current.keywords]
            if (
                class_match is not None
                and state.index.constructor_is_inert(*class_match)
                and all(state.index.literal_container(item) for item in arguments)
            ):
                pending.extend(
                    (item, current_module, execute_current_definitions, active_contextvar)
                    for item in ast.iter_child_nodes(current)
                )
                return False
        if function is None and (
            any(
                state.index.references_contextvar(current_module, argument)
                for argument in current.args
            )
            or any(
                state.index.references_contextvar(current_module, keyword.value)
                for keyword in current.keywords
            )
        ):
            return True
        if function is None and target != "contextvars.ContextVar":
            if state.index.reads_known_mapping(current_module, current):
                pending.extend(
                    (item, current_module, execute_current_definitions, active_contextvar)
                    for item in ast.iter_child_nodes(current)
                )
                return False
            if (
                isinstance(current.func, ast.Name)
                and current.func.id
                in {
                    "classmethod",
                    "globals",
                    "isinstance",
                    "issubclass",
                    "locals",
                    "property",
                    "staticmethod",
                }
                and current.func.id not in state.index.imports[current_module]
            ):
                pending.extend(
                    (item, current_module, execute_current_definitions, active_contextvar)
                    for item in ast.iter_child_nodes(current)
                )
                return False
            if (
                isinstance(current.func, ast.Attribute)
                and current.func.attr == "__setattr__"
                and isinstance(current.func.value, ast.Name)
                and current.func.value.id == "object"
                and "object" not in state.index.imports[current_module]
            ):
                pending.extend(
                    (item, current_module, execute_current_definitions, active_contextvar)
                    for item in ast.iter_child_nodes(current)
                )
                return False
            if (
                isinstance(current.func, ast.Name)
                and current.func.id in {"eval", "exec", "__import__"}
                and current.func.id not in state.index.imports[current_module]
            ):
                return True
            pending.extend(
                (item, current_module, execute_current_definitions, active_contextvar)
                for item in ast.iter_child_nodes(current)
            )
            return False
        if function is not None:
            target_module = state.index.source_module(target) or current_module
            function_contextvar = (
                active_contextvar
                or state.index.references_contextvar(current_module, current)
                or state.index.references_contextvar(target_module, function)
            )
            key = (target, id(function), function_contextvar)
            if key not in state.reached:
                state.reached.add(key)
                pending.extend(
                    (item, target_module, execute_current_definitions, function_contextvar)
                    for item in function.body
                )
                return False
    return None


## Traverse initialization and stop when a ContextVar write cannot be ruled out.
## 遍历初始化过程，在无法排除 ContextVar 写入时停止。
#
#  @param state Package indexes and source-resolution operations
#  @param node Syntax subtree to inspect
#  @param module Module containing the subtree
#  @param execute_definitions Whether definition annotations are evaluated
#  @param contextvar_active Whether the selected ContextVar is active in this path
#  @return Whether a write or an unmodeled effect prevents a no-write proof
def _scan_package_initialization(
    state,
    node,
    module,
    execute_definitions=False,
    contextvar_active=False,
):
    pending = [(node, module, execute_definitions, contextvar_active)]
    while pending:
        current, current_module, execute_current_definitions, active_contextvar = pending.pop()

        # Definitions can execute decorators and defaults before the function body is ever called.
        # 函数定义时可以执行装饰器并求值默认值，函数体则等到调用时执行。
        if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef)):
            expressions = (
                current.decorator_list
                + current.args.defaults
                + [item for item in current.args.kw_defaults if item is not None]
            )
            if execute_current_definitions:
                arguments = (
                    current.args.posonlyargs
                    + current.args.args
                    + current.args.kwonlyargs
                    + ([current.args.vararg] if current.args.vararg is not None else [])
                    + ([current.args.kwarg] if current.args.kwarg is not None else [])
                )
                expressions.extend(
                    item.annotation for item in arguments if item.annotation is not None
                )
                if current.returns is not None:
                    expressions.append(current.returns)
            pending.extend(
                (item, current_module, execute_current_definitions, active_contextvar)
                for item in expressions
            )
            continue
        if isinstance(current, ast.Lambda):
            pending.extend(
                (item, current_module, execute_current_definitions, active_contextvar)
                for item in current.args.defaults
                + [item for item in current.args.kw_defaults if item is not None]
            )
            continue

        # Class bodies execute when their definitions are evaluated.
        # 类定义求值时会执行类体。
        if isinstance(current, ast.ClassDef):
            pending.extend(
                (item, current_module, execute_current_definitions, active_contextvar)
                for item in current.decorator_list + current.bases + current.body
            )
            pending.extend(
                (keyword.value, current_module, execute_current_definitions, active_contextvar)
                for keyword in current.keywords
            )
            continue

        # An unresolved write could change the observed ContextVar during package initialization.
        # 未能解析的写入可能在包初始化期间改变被观测的 ContextVar。
        if (
            isinstance(current, ast.Call)
            and isinstance(current.func, ast.Attribute)
            and current.func.attr in {"reset", "set"}
        ):
            if (
                active_contextvar
                or state.index.contextvar_identity is None
                or state.index.references_contextvar(current_module, current.func.value)
            ):
                return True
            pending.extend(
                (item, current_module, execute_current_definitions, active_contextvar)
                for item in ast.iter_child_nodes(current)
            )
            continue

        if isinstance(current, ast.Call):
            call_result = _scan_call(
                state,
                current,
                current_module,
                execute_current_definitions,
                active_contextvar,
                pending,
            )
            if call_result is True:
                return True
            if call_result is False:
                continue

        pending.extend(
            (item, current_module, execute_current_definitions, active_contextvar)
            for item in ast.iter_child_nodes(current)
        )
    return False
