## @package vppdetector.assess.expressions
#  Bounded expression evaluation for parameter-assessment frames.
#
#
#  Dispatch syntax by expression category and delegate calls to call handling. A frame tracks
#  nesting depth across recursive evaluation.
#  按表达式类别分派语法，将调用交给调用处理，并由帧跟踪递归求值深度。



import ast
import operator

from .binding import _finite
from .values import (
    _UNKNOWN,
    _key_presence,
    _KeySet,
    _Keywords,
    _LocalFunction,
    _Positionals,
    _SourceInstance,
    _tracked,
    _Value,
)


## Interpret supported expressions within an assessment frame.
## 在评估帧中解释受支持的表达式。
class ExpressionOperations:
    ## Interpret one expression and record failures at the expression boundary.
    ## 解释一个表达式，并在表达式边界记录失败。
    #
    #  @param node Expression AST node to interpret
    #  @return Abstract value produced by the expression
    def expression(self, node):
        with self.expression_depth_scope():
            return self._expression(node)

    ## Evaluate one supported expression form without changing path ownership.
    ## 在不改变路径所有权的前提下求值一种受支持的表达式。
    #
    #  @param node Expression AST node to evaluate
    #  @return Abstract result or conservative unknown value
    def _expression(self, node):
        if isinstance(node, (ast.Constant, ast.Name, ast.Attribute)):
            return self._value_expression(node)
        if isinstance(node, ast.IfExp):
            return self._conditional_expression(node)
        if isinstance(node, (ast.Tuple, ast.List)):
            return self._container_expression(node)
        if isinstance(node, ast.Subscript):
            return self._container_expression(node)
        if isinstance(node, ast.JoinedStr):
            return self._formatted_string_expression(node)
        if isinstance(node, ast.Dict):
            return self._container_expression(node)
        if isinstance(node, ast.Call):
            return self.call(node)
        if isinstance(node, (ast.BinOp, ast.UnaryOp, ast.BoolOp, ast.Compare)):
            return self._operation_expression(node)

        # Unsupported syntax stops the proof if it depends on the selected argument.
        # 不支持的语法若依赖选定实参，则终止证明。
        if self.related(node):
            self.unknown("unsupported_value_use", node)
        return _Value()

    ## Resolve literals, names and source attributes.
    ## 解析字面量、名称和源码属性。
    #
    #  @param node Literal, name or attribute AST node
    #  @return Abstract value associated with the node
    def _value_expression(self, node):
        if isinstance(node, ast.Constant):
            return _finite(node)
        if isinstance(node, ast.Name):
            value = self.values.get(node.id, _Value())
            if isinstance(value, _Value) and not self.related(node):
                source_class = self.imported_source_class(node.id)
                if source_class is not None:
                    return source_class
            if isinstance(value, _LocalFunction):
                self.unknown("deferred_callable_not_followed", node)
            if node.id in self.facts and isinstance(value, _Value):
                return _Value(
                    self.facts[node.id],
                    value.tracked,
                    type_selected=value.type_selected,
                    iterable=value.iterable,
                )
            return value
        if isinstance(node.value, ast.Name):
            receiver = self.values.get(node.value.id)
            if isinstance(receiver, _SourceInstance):
                if node.attr not in receiver.attributes:
                    self.unknown("callable_instance_state_unproven", node)
                return receiver.attributes[node.attr]
        path = ast.unparse(node)
        if path in self.facts:
            return _Value(self.facts[path])
        if self.related(node):
            self.unknown("unsupported_attribute_use", node)
        return _Value()

    ## Select the statically determined branch of a conditional expression.
    ## 选择条件表达式中静态确定的分支。
    #
    #  @param node Conditional expression AST node
    #  @return Abstract value from the selected branch
    def _conditional_expression(self, node):
        condition = self.expression(node.test)
        truth = self.truth(condition)
        if truth is None:
            self.unknown("unresolved_condition", node.test)
        self.proof.note(
            self.function,
            "selected_expression_branch",
            f"{ast.unparse(node.test)}: {truth}",
            node.test,
        )
        return self.expression(node.body if truth else node.orelse)

    ## Evaluate supported tuple, list, mapping and subscript forms.
    ## 求值受支持的元组、列表、映射和下标形式。
    #
    #  @param node Container or subscript AST node
    #  @return Abstract container or projected value
    def _container_expression(self, node):
        if isinstance(node, (ast.Tuple, ast.List)):
            return _Positionals(
                tuple(self.positional_items(node.elts)),
                carrier=any(
                    isinstance(child, ast.Starred) and self.related(child.value)
                    for child in node.elts
                ),
                kind="tuple" if isinstance(node, ast.Tuple) else "list",
            )
        if isinstance(node, ast.Subscript):
            value = self.expression(node.value)
            if isinstance(value, _Positionals):
                return self.positional_projection(value, node)
            if self.related(node):
                self.unknown("unsupported_value_use", node)
            return _Value()
        if isinstance(node, ast.Dict):
            items = {}
            carrier = False
            for key, value in zip(node.keys, node.values):
                if key is None:
                    mapping = self.expression(value)
                    if not isinstance(mapping, _Keywords):
                        self.unknown("dynamic_argument_expansion", node)
                    # Dictionary displays overwrite keys; call keyword expansions can raise.
                    # 字典字面量会覆盖重名键，调用时展开重复关键字可能报错。
                    items.update(mapping.items)
                    carrier = carrier or mapping.carrier
                    continue
                if not isinstance(key, ast.Constant) or type(key.value) is not str:
                    self.unknown("dynamic_argument_expansion", node)
                items[key.value] = self.expression(value)
            return _Keywords(items, carrier)
        return _Value()

    ## Build a finite string from supported formatted-string components.
    ## 根据受支持的格式化字符串片段构造有限字符串。
    #
    #  @param node Formatted-string AST node
    #  @return Abstract formatted string
    def _formatted_string_expression(self, node):
        pieces = []
        tracked = False
        key_presence = False
        for item in node.values:
            if isinstance(item, ast.Constant) and type(item.value) is str:
                pieces.append(item.value)
                continue
            if not isinstance(item, ast.FormattedValue) or item.format_spec is not None:
                self.unknown("unsupported_value_use", node)
            value = self.expression(item.value)
            if not isinstance(value, _Value) or value.literal is _UNKNOWN:
                self.unknown("unsupported_value_use", node)
            if item.conversion not in (-1, 115, 114, 97):
                self.unknown("unsupported_value_use", node)
            conversions = {115: str, 114: repr, 97: ascii}
            convert = conversions.get(item.conversion, str)
            pieces.append(convert(value.literal))
            tracked = tracked or value.tracked
            key_presence = key_presence or _key_presence(value)
        return _Value("".join(pieces), tracked, key_presence)

    ## Evaluate supported arithmetic, boolean and comparison expressions.
    ## 求值受支持的算术、布尔和比较表达式。
    #
    #  @param node Operation AST node
    #  @return Abstract operation result
    def _operation_expression(self, node):
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Sub):
            left, right = self.expression(node.left), self.expression(node.right)
            if isinstance(left, _KeySet) and isinstance(right, _KeySet):
                return _KeySet(
                    {key: tracked for key, tracked in left.items.items() if key not in right.items}
                )
            if _tracked(left) or _tracked(right):
                self.unknown("key_comparison_unproven", node)
            return _Value()
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            left, right = self.expression(node.left), self.expression(node.right)
            if (
                isinstance(left, _Positionals)
                and isinstance(right, _Positionals)
                and left.kind == right.kind
            ):
                return _Positionals(
                    left.items + right.items, left.carrier or right.carrier, left.kind
                )
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
            value = self.expression(node.operand)
            truth = self.truth(value)
            return _Value(
                not truth if truth is not None else _UNKNOWN, _tracked(value), _key_presence(value)
            )
        if isinstance(node, ast.BoolOp):
            tracked = False
            key_presence = False
            for item in node.values:
                value = self.expression(item)
                tracked = tracked or _tracked(value)
                key_presence = key_presence or _key_presence(value)
                truth = self.truth(value)
                if truth is None:
                    joined = self.finite_identity_truth(node)
                    if joined is not None and len(joined) == 1:
                        # Only builtin identity tests can establish this path-independent result.
                        # 只有内置的对象身份比较能得出与路径无关的结论。
                        return _Value(next(iter(joined)))
                    return _Value(tracked=tracked)
                if truth == isinstance(node.op, ast.Or):
                    return _Value(truth, tracked)
            return _Value(truth, tracked, key_presence and isinstance(node.op, ast.And) and truth)
        if isinstance(node, ast.Compare) and len(node.ops) == 1:
            return self._comparison_expression(node)
        if self.related(node):
            self.unknown("unsupported_value_use", node)
        return _Value()

    ## Compare finite values and supported argument containers.
    ## 比较有限值和受支持的实参容器。
    #
    #  @param node Single-operation comparison AST node
    #  @return Abstract comparison result
    def _comparison_expression(self, node):
        left, right = self.expression(node.left), self.expression(node.comparators[0])
        tracked = _tracked(left) or (not isinstance(right, _Keywords) and _tracked(right))
        lval = left.literal if isinstance(left, _Value) else _UNKNOWN
        rval = right.literal if isinstance(right, _Value) else _UNKNOWN
        operation = node.ops[0]

        # Mapping membership tracks presence of the selected key independently of its stored value.
        # 映射的成员资格检查独立跟踪选定键是否存在，无需读取键值。
        if isinstance(operation, (ast.In, ast.NotIn)) and isinstance(right, _Positionals):
            primitives = (str, bytes, int, float, bool, type(None))
            if type(lval) not in primitives or any(
                not isinstance(item, _Value) or type(item.literal) not in primitives
                for item in right.items
            ):
                self.unknown("sequence_membership_unproven", node)
            present = lval in tuple(item.literal for item in right.items)
            return _Value(
                present if isinstance(operation, ast.In) else not present,
                _tracked(left) or _tracked(right),
                derived=_tracked(left) or _tracked(right),
            )
        if (
            isinstance(operation, (ast.Eq, ast.NotEq))
            and isinstance(left, _Keywords)
            and isinstance(right, _Keywords)
            and (not left.items or not right.items)
        ):
            equal = not left.items and not right.items
            selected = _tracked(left) or _tracked(right)
            return _Value(
                equal if isinstance(operation, ast.Eq) else not equal,
                selected,
                selected,
                derived=selected,
            )
        if isinstance(operation, (ast.In, ast.NotIn)) and isinstance(right, _Keywords):
            if lval is not _UNKNOWN:
                present = lval in right.items
                tracked = tracked or _tracked(right.items.get(lval))
                return _Value(
                    present if isinstance(operation, ast.In) else not present,
                    tracked,
                    _tracked(right.items.get(lval)),
                    derived=tracked,
                )

        if lval is not _UNKNOWN and rval is not _UNKNOWN:
            if isinstance(operation, (ast.Is, ast.IsNot)) and (lval is None or rval is None):
                result = lval is rval
                return _Value(
                    result if isinstance(operation, ast.Is) else not result,
                    tracked,
                    derived=tracked,
                )
            if isinstance(operation, (ast.Eq, ast.NotEq)):
                result = lval == rval
                return _Value(
                    result if isinstance(operation, ast.Eq) else not result,
                    tracked,
                    derived=tracked,
                )
            numeric = type(lval) in (bool, int, float) and type(rval) in (bool, int, float)
            text = type(lval) is type(rval) and type(lval) in (str, bytes)
            comparison = {
                ast.Lt: operator.lt,
                ast.LtE: operator.le,
                ast.Gt: operator.gt,
                ast.GtE: operator.ge,
            }.get(type(operation))
            if comparison is not None and (numeric or text):
                return _Value(comparison(lval, rval), tracked, derived=tracked)
        return _Value(tracked=tracked)
