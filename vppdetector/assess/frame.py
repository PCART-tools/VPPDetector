## @package vppdetector.assess.frame
#  Mutable abstract frame for one source function path.
#
#
#  Own local values, facts and return state during one function evaluation. Copy branch-local
#  mutable state together with the proof to preserve aliases.
#  持有一次函数求值的局部值、事实及返回状态，分支复制与证明共享复制记录以保留别名关系。



import ast
import builtins
import copy
import tokenize
from contextlib import contextmanager

from ..facts.calls import direct_calls
from ..models import (
    FunctionIdentity,
    ParameterState,
)
from .binding import _Stop
from .calls import CallOperations
from .expressions import ExpressionOperations
from .fresh import NO_FRESH_RECEIVER, FreshReceiverOperations
from .inputs import ArgumentBindingOperations
from .values import (
    _UNKNOWN,
    _KeySet,
    _Keywords,
    _Positionals,
    _raw_selected,
    _SourceClass,
    _SourceInstance,
    _tracked,
    _Value,
)

_DEFAULT_FRAME_VALUE = object()


## Hold the mutable state of one interpreted source-function path.
## 保存源码函数的一条解释路径上的可变状态。
class _Frame(
    CallOperations, ArgumentBindingOperations, ExpressionOperations, FreshReceiverOperations
):
    ## Initialize one function frame with its selected source context
    ## 使用当前选定的源码上下文初始化一个函数帧
    #
    #  @param proof Proof ledger coordinating nested analysis
    #  @param function Indexed function interpreted by this frame
    #  @param analysis Producer facts for the function, if already available
    #  @param values Abstract local values for this path
    #  @param ancestry Function identities already followed
    #  @param facts Caller and path facts available to the function
    #  @param context Source context selected for this frame's function
    #  @param receiver Verified fresh-receiver state propagated to this frame
    #  @param returned Whether the path already returned
    #  @param rejection_guard Whether a narrow rejection guard is active
    #  @param result Existing abstract return value, or a fresh default
    #  @param pending_values In-progress call argument values
    #  @param expression_depth Current expression nesting depth
    def __init__(
        self,
        proof,
        function,
        analysis,
        values,
        ancestry,
        facts,
        *,
        context,
        receiver=NO_FRESH_RECEIVER,
        returned=False,
        rejection_guard=False,
        result=_DEFAULT_FRAME_VALUE,
        pending_values=_DEFAULT_FRAME_VALUE,
        expression_depth=0,
    ):
        self.proof = proof
        self.context = context
        self.function = function
        self.analysis = analysis
        self.values = values
        self.ancestry = ancestry
        self.facts = facts
        self.receiver = receiver
        self.returned = returned
        self.rejection_guard = rejection_guard
        self.result = _Value() if result is _DEFAULT_FRAME_VALUE else result
        self.pending_values = [] if pending_values is _DEFAULT_FRAME_VALUE else pending_values
        self.expression_depth = expression_depth

    ## Set one local binding without changing its fact projections.
    ## 设置一个局部绑定，不改变其事实投影。
    #
    #  @param name Local variable name
    #  @param value Abstract value assigned to the local
    def set_local(self, name, value):
        self.values[name] = value

    ## Remove one local binding when restoring a temporary scope.
    ## 恢复临时作用域时移除一个局部绑定。
    #
    #  @param name Local variable name
    def remove_local(self, name):
        self.values.pop(name, None)

    ## Invalidate facts rooted at a reassigned local or attribute path.
    ## 清除以重新赋值的局部变量或属性路径为根的事实。
    #
    #  @param path Local name or source-level attribute path
    #  @param descendants Whether to clear facts for child paths as well
    def invalidate_facts(self, path, descendants=False):
        for known_path in tuple(self.facts):
            if known_path == path or (
                descendants and known_path.startswith(path + ".")
            ):
                del self.facts[known_path]

    ## Assign one local and invalidate stale facts for it and its attributes.
    ## 赋值一个局部变量，并清除它及其属性上的过期事实。
    #
    #  @param name Local variable name
    #  @param value Abstract value assigned to the local
    def bind_local(self, name, value):
        self.set_local(name, value)
        self.invalidate_facts(name, descendants=True)

    ## Record a completed return value and terminate the current statement path.
    ## 记录返回值并终止当前语句路径。
    #
    #  @param value Abstract return value
    def record_return(self, value):
        self.result = value
        self.returned = True

    ## Scope a rejection guard to one selected conditional branch.
    ## 将拒绝守卫限制在一个选定的条件分支内。
    #
    #  @param enabled Whether this branch establishes the narrow rejection guard
    #  @return Context manager that restores the previous guard on exit
    @contextmanager
    def rejection_guard_scope(self, enabled):
        previous = self.rejection_guard
        self.rejection_guard = previous or enabled
        try:
            yield
        finally:
            self.rejection_guard = previous

    ## Track one nested expression and restore depth after failure
    ## 跟踪一层嵌套表达式，并在失败时恢复深度
    #
    #  @return Context manager that decrements expression depth on exit
    @contextmanager
    def expression_depth_scope(self):
        self.expression_depth += 1
        try:
            yield
        finally:
            self.expression_depth -= 1

    ## Stop the proof with an explicit analysis boundary
    ## 以明确的分析边界终止证明
    #
    #  @param reason Machine-readable analysis boundary reason
    #  @param node Source AST node locating the boundary, when available
    def unknown(self, reason, node):
        self.proof.unknown(
            self.function, reason, ast.unparse(node), node if self.analysis is not None else None
        )

    ## Determine whether a syntax node depends on the selected argument
    ## 判断语法节点是否依赖选定实参
    #
    #  @param node AST subtree inspected for selected-argument references
    #  @return Whether the syntax references a tracked value or argument carrier
    def related(self, node):
        return any(self._node_is_related(item) for item in ast.walk(node))

    ## Check whether this frame is inside a nested expression.
    ## 检查当前帧是否位于嵌套表达式中。
    #
    #  @return Whether the expression depth makes prior consumption uncertain
    def has_nested_expression(self):
        return self.expression_depth > 1

    ## Check whether selected data remains in this frame's local state.
    ## 检查此帧局部状态中是否仍保留所选实参数据。
    #
    #  @param consumed_values Values already proven consumed on this proof path
    #  @return Whether values or pending call arguments still reference the selection
    def has_live_selected_value(self, consumed_values):
        return any(
            _raw_selected(value, consumed_values=consumed_values)
            for value in self.values.values()
        ) or any(
            _raw_selected(value, consumed_values=consumed_values)
            for pending in self.pending_values
            for value in pending
        )

    ## Check whether local state shares a value recorded as consumed
    ## 检查局部状态是否引用了已登记消费的值
    #
    #  @param consumed_values Values already consumed on this proof path
    #  @param selected_ids Object identities recorded as consumed
    #  @return Whether locals or pending arguments contain one of those values
    def has_consumed_value_alias(self, consumed_values, selected_ids=None):
        if selected_ids is None:
            selected_ids = {id(value) for value in consumed_values}
        seen = set()

        ## Search an abstract value graph by identity while tolerating cycles.
        ## 按对象身份遍历抽象值图，并安全处理循环引用。
        #
        #  @param value Value or container to inspect
        #  @return True when the selected value is reachable
        def contains(value):
            identity = id(value)
            if identity in selected_ids:
                return True
            if identity in seen:
                return False
            seen.add(identity)
            if isinstance(value, _Keywords):
                return any(contains(item) for item in value.items.values())
            if isinstance(value, _Positionals):
                return any(contains(item) for item in value.items)
            if isinstance(value, _SourceInstance):
                return any(contains(item) for item in value.attributes.values())
            return False

        return any(contains(value) for value in self.values.values()) or any(
            contains(value) for pending in self.pending_values for value in pending
        )

    ## Check whether a syntax node is related to the selected parameter.
    ## 检查语法节点是否与所选参数相关。
    #
    #  @param node Syntax node being checked
    #  @return True when the node may depend on the selected parameter
    def _node_is_related(self, node):
        if not isinstance(node, ast.Name):
            return False
        value = self.values.get(node.id)
        return _tracked(value) or (isinstance(value, (_Keywords, _Positionals)) and value.carrier)

    ## Resolve a supported one-item mapping iteration in a for loop
    ## 解析 for 循环中受支持的单项映射遍历
    #
    #  @param statement For-loop AST node to validate
    #  @return Modeled keyword mapping, or None if the iteration is unsupported
    def mapping_items(self, statement):
        if (
            not isinstance(statement, ast.For)
            or statement.orelse
            or not isinstance(statement.target, (ast.Tuple, ast.List))
            or len(statement.target.elts) != 2
            or not all(isinstance(item, ast.Name) for item in statement.target.elts)
            or not isinstance(statement.iter, ast.Call)
            or statement.iter.args
            or statement.iter.keywords
            or not isinstance(statement.iter.func, ast.Attribute)
            or statement.iter.func.attr != "items"
            or not isinstance(statement.iter.func.value, ast.Name)
        ):
            return None
        if self.analysis is None:
            return None
        mapping_name = statement.iter.func.value.id
        mapping = self.values.get(mapping_name)
        edge = next(
            (
                item
                for item in direct_calls(self.analysis, self.function.identity)
                if (item.lineno, item.col_offset, item.end_lineno, item.end_col_offset)
                == (
                    statement.iter.lineno,
                    statement.iter.col_offset,
                    statement.iter.end_lineno,
                    statement.iter.end_col_offset,
                )
            ),
            None,
        )
        if (
            not isinstance(mapping, _Keywords)
            or mapping.source_state
            or len(mapping.items) != 1
            or edge is None
            or edge.callee_name != mapping_name + ".items"
            or not edge.receiver_sources
            or any(
                source.get("kind") != "parameter"
                or source.get("source") != mapping_name
                or source.get("relation") != "direct"
                or source.get("value_incomplete")
                for source in edge.receiver_sources
            )
        ):
            return None
        return mapping

    ## Accept finite-model reads, not calls, projections or known getters
    ## 只接受有限模型中的直接读取，不接受调用、投影或getter
    #
    #  @param node Guard expression AST to check for a supported direct read
    #  @return Whether the expression is a supported direct, untracked read
    def simple_guard_read(self, node):
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
            return self.simple_guard_read(node.operand)
        if isinstance(node, ast.Name):
            value = self.values.get(node.id)
            return isinstance(value, _Value) and not value.tracked
        if not isinstance(node, ast.Attribute) or not isinstance(node.value, ast.Name):
            return False
        positional = self.function.node.args.posonlyargs + self.function.node.args.args
        if (
            not self.function.is_bound_method
            or not positional
            or node.value.id != positional[0].arg
            or node.value.id in self.values
        ):
            return False
        owner = self.function.identity.qualname.rpartition(".")[0]
        names = {owner + "." + name for name in (node.attr, "__getattribute__", "__getattr__")}
        return not any(
            function.identity.module == self.function.identity.module
            and function.identity.qualname in names
            for function in self.context.index.functions
        )

    ## Record an unrelated error-only guard without inventing its value
    ## 记录无关的仅错误守卫，不据此虚构条件值
    #
    #  @param statement Conditional AST node containing the guard
    #  @return Whether a supported normal-path precondition was recorded
    def normal_path_guard(self, statement):
        if self.related(statement) or not self.simple_guard_read(statement.test):
            return False
        for exceptional, normal, required in (
            (statement.body, statement.orelse, False),
            (statement.orelse, statement.body, True),
        ):
            if len(exceptional) != 1 or any(not isinstance(item, ast.Pass) for item in normal):
                continue
            raised = exceptional[0]
            if not isinstance(raised, ast.Raise) or raised.cause is not None:
                continue
            call = raised.exc
            if not isinstance(call, ast.Call) or not isinstance(call.func, ast.Name):
                continue
            if self.analysis is None:
                continue
            exception = getattr(builtins, call.func.id, None)
            if (
                not isinstance(exception, type)
                or not issubclass(exception, Exception)
                or call.keywords
                or any(not isinstance(item, ast.Constant) for item in call.args)
                or not self.unshadowed_builtin_name(call.func.id)
            ):
                continue
            edge = next(
                (
                    edge
                    for edge in direct_calls(self.analysis, self.function.identity)
                    if (edge.lineno, edge.col_offset, edge.end_lineno, edge.end_col_offset)
                    == (call.lineno, call.col_offset, call.end_lineno, call.end_col_offset)
                ),
                None,
            )
            if edge is None or edge.target is not None or edge.target_status != "builtin_boundary":
                continue
            test = ast.unparse(statement.test)
            condition = f"({test})" if required else f"not ({test})"
            self.proof.note(
                self.function,
                "normal_path_precondition",
                f"Normal execution requires {condition}; the guard value is not inferred.",
                statement.test,
            )
            return True
        return False

    ## Confirm that a builtin name is not rebound in the source scope
    ## 确认内建名称未在源码作用域中被重新绑定
    #
    #  @param name Name to match or validate in the current scope
    #  @return Whether the name is unbound in the frame and containing source scopes
    def unshadowed_builtin_name(self, name):
        # PCResolve publishes its source-scope API at runtime.
        # PCResolve 在运行时提供作用域查询接口。
        from pcresolve.scope_facts import statement_scope_facts

        file_path = self.function.identity.file_path
        if file_path is None:
            return False

        try:
            with tokenize.open(file_path) as stream:
                tree = ast.parse(stream.read())
        except (OSError, SyntaxError, UnicodeError):
            return False
        scopes = [tree] + [
            item
            for item in ast.walk(tree)
            if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))
            and item.end_lineno is not None
            and item.lineno <= self.function.node.lineno <= item.end_lineno
        ]
        return name not in self.values and all(
            name not in (facts.bound | facts.globals | facts.nonlocals)
            for scope in scopes
            for facts in (statement_scope_facts(scope.body),)
        )

    ## Join only pure local identity probes, without reading custom truth values
    ## 只合并本地纯身份判断，不触发自定义真假转换
    #
    #  @param node Identity-test expression AST to evaluate
    #  @param depth Current recursive or structural analysis depth
    #  @return Set of possible truth values, or None for an unsupported expression
    def finite_identity_truth(self, node, depth=0):
        if depth > 8:
            return None
        if isinstance(node, ast.BoolOp) and len(node.values) <= 8:
            possibilities = {isinstance(node.op, ast.And)}
            for child in node.values:
                incoming = self.finite_identity_truth(child, depth + 1)
                if incoming is None:
                    return None
                possibilities = {
                    (left and right if isinstance(node.op, ast.And) else left or right)
                    for left in possibilities
                    for right in incoming
                }
            return possibilities
        if (
            not isinstance(node, ast.Compare)
            or len(node.ops) != 1
            or not isinstance(node.ops[0], (ast.Is, ast.IsNot))
            or not isinstance(node.left, ast.Name)
            or not isinstance(node.comparators[0], ast.Constant)
            or node.comparators[0].value is not None
        ):
            return None
        value = self.values.get(node.left.id)
        if not isinstance(value, _Value):
            return None
        if value.literal is _UNKNOWN:
            return {False, True}
        equal = value.literal is None
        return {equal if isinstance(node.ops[0], ast.Is) else not equal}

    ## Create an isolated proof frame for one control-flow branch
    ## 为单个控制流分支创建隔离的证明帧
    #
    #  @return Branch frame with isolated mutable state and proof evidence
    def _branch_frame(self):
        _, branch = self.proof.fork_for_branch(self)
        return branch

    ## Copy one frame's mutable state into an isolated proof
    ## 将单个帧的可变状态复制到隔离的证明中
    #
    #  @param proof Proof that will own the copied frame
    #  @param memo Shared deepcopy memo for the complete active state graph
    #  @return Frame copy with isolated mutable state
    def _copy_branch_state(self, proof, memo):
        branch = copy.copy(self)
        branch.proof = proof
        branch.values = copy.deepcopy(self.values, memo)
        branch.facts = copy.deepcopy(self.facts, memo)
        branch.pending_values = copy.deepcopy(self.pending_values, memo)
        branch.result = copy.deepcopy(self.result, memo)
        return branch

    ## Reject only when every reachable modeled branch rejects the argument
    ## 仅在所有可达且已建模分支均拒绝实参时判定拒绝
    #
    #  @param statement Conditional AST node whose branches are analyzed
    #  @param continuation Statements to analyze after a branch
    #  @return False if at least one branch does not prove rejection
    #  @exception _Stop If every modeled branch proves rejection
    def _reject_if_all_branches_reject(self, statement, continuation):
        evidence_checkpoint = self.proof.branch_evidence_checkpoint()
        outcomes = []
        branches = []
        for body in (statement.body, [*statement.orelse, *continuation]):
            branch = self._branch_frame()
            branches.append(branch)
            try:
                branch.statements(body)
            except _Stop as outcome:
                outcomes.append(outcome)
            else:
                outcomes.append(None)

        # Publish speculative evidence only after every modeled continuation rejects.
        # 仅当所有已建模的后续路径均拒绝实参时，才合并推测分支的证据。
        if not all(
            outcome is not None and outcome.state is ParameterState.REJECTED for outcome in outcomes
        ):
            return False

        for branch in branches:
            self.proof.merge_branch_evidence(branch.proof, evidence_checkpoint)
        reasons = {outcome.reason for outcome in outcomes if outcome is not None}
        reason = reasons.pop() if len(reasons) == 1 else "all_condition_branches_rejected"
        self.proof.note(
            self.function,
            "all_condition_branches_rejected",
            "The condition is unresolved, but each branch independently proves rejection "
            "of the selected argument.",
            statement.test,
        )
        raise _Stop(ParameterState.REJECTED, reason)

    ## Interpret supported statements and join their finite outcomes
    ## 解释受支持语句并合并其有限执行结果
    #
    #  @param statements Source statements to interpret
    def statements(self, statements):
        from .statements import handle

        for statement_index, statement in enumerate(statements):
            if self.returned:
                break
            handle(self, statement, statements[statement_index + 1 :])

    ## Bind exact builtin tuple/list shapes without invoking an iterator protocol
    ## 绑定精确的内建tuple/list形状，不调用自定义迭代协议
    #
    #  @param target Assignment target AST to unpack
    #  @param value Abstract positional value to bind
    #  @param depth Current recursive or structural analysis depth
    #  @return List of target names paired with their abstract values
    def finite_unpack(self, target, value, depth=0):
        if depth > 8:
            self.unknown("unpacking_binding_unproven", target)
        if isinstance(target, ast.Name):
            return [(target.id, value)]
        if (
            not isinstance(target, (ast.Tuple, ast.List))
            or not isinstance(value, _Positionals)
            or value.kind not in ("tuple", "list")
            or len(target.elts) != len(value.items)
            or len(target.elts) > 1000
        ):
            self.unknown("unpacking_binding_unproven", target)
        result = []
        for child, item in zip(target.elts, value.items):
            result.extend(self.finite_unpack(child, item, depth + 1))
        if value.carrier and _tracked(value):
            self.proof.handled(
                self.function,
                "consumed_presence",
                "Exact unpacking requires the selected captured element.",
                target,
            )
        return result

    ## Resolve truth only for values with a supported finite protocol
    ## 仅对具有受支持有限协议的值解析真假
    #
    #  @param value Abstract value whose finite truth is queried
    #  @return Known truth value, or None when the model cannot determine it
    @staticmethod
    def truth(value):
        if isinstance(value, (_Keywords, _Positionals, _KeySet)):
            return bool(value.items)
        if isinstance(value, _Value) and value.literal is not _UNKNOWN:
            return bool(value.literal)
        return None

    ## Resolve a simple imported source class and its constructor
    ## 解析简单导入源码类及其构造器
    #
    #  @param name Imported class binding in the analyzed module
    #  @return Source class and constructor model, or None when either is unproven
    def imported_source_class(self, name):
        aliases = self.context.index.imports.get(self.function.identity.module, {})
        imported = aliases.get(name)
        if not isinstance(imported, str) or "." not in imported:
            return None
        module, qualname = imported.rsplit(".", 1)
        identity = self.context.index.resolve_class(FunctionIdentity(module, qualname))
        if identity is None or identity.file_path is None:
            return None
        constructor = self.context.index.resolve_imported(identity)
        if (
            constructor is None
            or constructor.node.decorator_list
            or constructor.identity.qualname.rsplit(".", 1)[-1] != "__init__"
        ):
            return None
        if not self.context.source_queries.is_plain_class(identity):
            return None
        return _SourceClass(identity, constructor)

    ## Expand finite positional values while retaining their source slots
    ## 展开有限位置实参并保留其来源槽位
    #
    #  @param nodes Positional argument AST nodes, including any starred arguments
    #  @return List of abstract positional argument values
    def positional_items(self, nodes):
        positional = []
        for argument in nodes:
            if isinstance(argument, ast.Starred):
                value = self.expression(argument.value)
                if not isinstance(value, _Positionals):
                    self.unknown("dynamic_argument_expansion", argument)
                positional.extend(value.items)
            else:
                positional.append(self.expression(argument))
        return positional

    ## Project one original position through a supported container operation
    ## 通过受支持容器操作投影一个原始位置
    #
    #  @param value Modeled positional sequence being indexed or sliced
    #  @param node Subscript AST selecting the modeled positional value
    #  @return Selected abstract element or modeled sequence slice
    def positional_projection(self, value, node):
        ## Resolve one selected positional item from its projected sequence
        ## 从投影序列解析选定的位置实参项
        #
        #  @param item Index or slice-bound AST expression, or None for an omitted bound
        #  @return Integer index or None for an omitted bound
        def index(item):
            if item is None:
                return None
            if isinstance(item, ast.Constant) and type(item.value) is int:
                return item.value
            if (
                isinstance(item, ast.UnaryOp)
                and isinstance(item.op, (ast.USub, ast.UAdd))
                and isinstance(item.operand, ast.Constant)
                and type(item.operand.value) is int
            ):
                return -item.operand.value if isinstance(item.op, ast.USub) else item.operand.value
            self.unknown("positional_projection_unproven", node)

        try:
            if isinstance(node.slice, ast.Slice):
                selection = slice(
                    index(node.slice.lower), index(node.slice.upper), index(node.slice.step)
                )
                return _Positionals(
                    value.items[selection], value.carrier, value.kind, value.source_state
                )
            selected = index(node.slice)
            if selected is None:
                self.unknown("positional_projection_unproven", node)
            return value.items[selected]
        except (IndexError, TypeError, ValueError):
            self.unknown("positional_projection_unproven", node)

    ## Extract finite positional and keyword values from a call expression
    ## 从调用表达式提取有限的位置和关键字实参值
    #
    #  @param node Call AST whose arguments are interpreted
    #  @return Pair of positional values and keyword-name-to-value mapping
    def arguments(self, node):
        positional = self.positional_items(node.args)

        keywords = {}
        for keyword in node.keywords:
            value = self.expression(keyword.value)
            items = (
                {keyword.arg: value}
                if keyword.arg is not None
                else (value.items if isinstance(value, _Keywords) else None)
            )
            if items is None:
                self.unknown("dynamic_argument_expansion", keyword.value)
            for name, item in items.items():
                if name in keywords:
                    if _tracked(item) or _tracked(keywords[name]):
                        self.proof.reject(self.function, "duplicate_argument_binding", name, node)
                    self.unknown("call_binding_unproven", node)
                keywords[name] = item
        return positional, keywords

    ## Analyze a call expression while preserving argument provenance
    ## 分析调用表达式并保留实参来源信息
    #
    #  @param node Call AST to interpret
    #  @return Abstract result of the supported call model
    def call(self, node):
        self.pending_values.append([])
        try:
            return self._call(node)
        finally:
            self.pending_values.pop()

    ## Resolve a supported instance check without invoking custom behavior
    ## 解析受支持的实例检查且不调用自定义行为
    #
    #  @param node Instance-check call AST to interpret
    #  @return Abstract truth value, including an unknown value when not provable
    def instance_guard(self, node):
        value = self.expression(node.args[0])
        if not isinstance(value, _Value) or value.literal is _UNKNOWN:
            return _Value(tracked=_tracked(value))
        expression = ast.unparse(node.args[1])
        if (
            isinstance(node.args[1], ast.Name)
            and expression in ("str", "bytes", "int", "float", "bool", "object")
            and self.unshadowed_builtin_name(expression)
        ):
            return _Value(isinstance(value.literal, getattr(builtins, expression)), value.tracked)
        classes = self.context.index
        identity = classes._definitions().resolve_name(
            self.function.identity.module,
            self.function.identity.qualname,
            expression,
            classes.imports,
            kind="class",
        )
        if identity and identity.file_path:
            # A primitive cannot be an instance of a plain source class. Custom
            # metaclasses/inherited instance checks deliberately remain unknown.
            # 基本类型值不可能是普通源码类的实例；自定义元类或继承来的实例检查仍保留为未知。
            try:
                with tokenize.open(identity.file_path) as stream:
                    tree = ast.parse(stream.read())
            except (OSError, SyntaxError, UnicodeError):
                return _Value()
            matching = [
                item
                for item in ast.walk(tree)
                if isinstance(item, ast.ClassDef) and item.lineno == identity.lineno
            ]
            if (
                len(matching) == 1
                and not matching[0].keywords
                and not matching[0].decorator_list
                and all(
                    isinstance(base, ast.Name) and base.id == "object" for base in matching[0].bases
                )
                and not any(
                    isinstance(item, ast.Name)
                    and item.id == "object"
                    and isinstance(item.ctx, ast.Store)
                    or isinstance(item, (ast.FunctionDef, ast.ClassDef))
                    and item.name == "object"
                    for item in ast.walk(tree)
                )
                and "object" not in classes.imports.get(identity.module, {})
            ):
                return _Value(False, value.tracked)
        return _Value(tracked=value.tracked)
