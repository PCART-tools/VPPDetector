## @package vppdetector.assess.binding
#  Bind abstract call arguments to source signatures and report proof outcomes.
#
#
#  Assign finite positional and keyword values to indexed parameter slots. Binding errors stop
#  the proof with the associated evidence.
#  将有限的位置值和关键字值分配到索引中的参数槽位，绑定错误以相应证据结束证明。



import ast
import inspect

from ..models import ChangeKind, ParameterState
from .values import _BoundValues, _Keywords, _Positionals, _tracked, _Value


## Convert a supported literal AST expression into a finite abstract value
## 将受支持的字面量AST表达式转换为有限抽象值
#
#  @param node Literal expression AST to interpret
#  @return Literal abstract value, or an unknown abstract value for unsupported syntax
def _finite(node):
    if isinstance(node, ast.Constant) and type(node.value) in (
        str,
        bytes,
        int,
        float,
        bool,
        type(None),
    ):
        return _Value(node.value)
    return _Value()


## Build the callable signature used for positional and keyword binding
## 构建用于位置和关键字绑定的可调用对象签名
#
#  @param function Indexed source function under analysis
#  @param bound Whether the callable is already bound to a receiver
#  @return Signature used to bind abstract positional and keyword arguments
def _signature(function, bound):
    args = function.node.args
    positional = args.posonlyargs + args.args

    # Positional defaults apply to the final slots. Keyword-only defaults keep their names.
    # 位置参数的默认值对应末尾槽位；仅限关键字参数的默认值按名称匹配。
    defaults = dict(
        zip(
            (node.arg for node in positional[len(positional) - len(args.defaults) :]), args.defaults
        )
    )
    defaults.update(
        (node.arg, value)
        for node, value in zip(args.kwonlyargs, args.kw_defaults)
        if value is not None
    )

    parameters = []
    for nodes, kind in (
        (args.posonlyargs, inspect.Parameter.POSITIONAL_ONLY),
        (args.args, inspect.Parameter.POSITIONAL_OR_KEYWORD),
        ((args.vararg,) if args.vararg else (), inspect.Parameter.VAR_POSITIONAL),
        (args.kwonlyargs, inspect.Parameter.KEYWORD_ONLY),
        ((args.kwarg,) if args.kwarg else (), inspect.Parameter.VAR_KEYWORD),
    ):
        for node in nodes:
            if bound and positional and node is positional[0]:
                continue
            default = (
                _finite(defaults[node.arg]) if node.arg in defaults else inspect.Parameter.empty
            )
            parameters.append(inspect.Parameter(node.arg, kind, default=default))
    return inspect.Signature(parameters)


## Carry a terminal parameter state and its reason through proof execution.
## 在证明执行过程中传递终止参数状态及原因。
class _Stop(Exception):
    ## Initialize the object state required by the enclosing class
    ## 初始化所属类所需的对象状态
    #
    #  @param state Current abstract or analysis state
    #  @param reason Machine-readable reason for stopping the proof
    def __init__(self, state, reason):
        self.state, self.reason = state, reason


## Bind finite positional and keyword values to a source signature
## 将有限的位置和关键字值绑定到源码签名
#
#  @param function Indexed source function under analysis
#  @param proof Proof ledger receiving selected-argument binding outcomes
#  @param positional Positional argument values for the source call
#  @param keywords Keyword argument values for the source call
#  @param bound Whether the callable is already bound to a receiver
#  @param node Optional call AST node locating a binding conflict
#  @param caller Optional indexed caller; defaults to the bound function
#  @param change Optional parameter change used to classify entry-binding failures
#  @return Bound abstract values and the effective positional argument count
def bind(
    proof,
    function,
    positional,
    keywords,
    bound,
    node=None,
    *,
    caller=None,
    change=None,
):
    signature = _signature(function, bound)
    owner = caller or function
    slots = [
        p.name
        for p in signature.parameters.values()
        if p.kind in (p.POSITIONAL_ONLY, p.POSITIONAL_OR_KEYWORD)
    ]

    # Only binding conflicts involving the selected argument can prove rejection.
    # 只把与所选变更参数相关的绑定冲突作为拒绝证据
    for position, value in enumerate(positional):
        if not _tracked(value):
            continue
        if position >= len(slots) and not function.signature.vararg:
            proof.reject(
                owner,
                "too_many_positional_arguments",
                f"Selected value reaches positional slot {position}; capacity is {len(slots)}.",
                node,
                function.identity,
            )
        if position < len(slots) and slots[position] in keywords:
            proof.reject(
                owner, "duplicate_argument_binding", slots[position], node, function.identity
            )
    for name, value in keywords.items():
        if not _tracked(value):
            continue
        parameter = signature.parameters.get(name)
        if parameter and parameter.kind is inspect.Parameter.POSITIONAL_OR_KEYWORD:
            if name in slots[: len(positional)]:
                proof.reject(owner, "duplicate_argument_binding", name, node, function.identity)
        if (parameter is None or parameter.kind is inspect.Parameter.POSITIONAL_ONLY) and not (
            function.signature.kwarg
        ):
            proof.reject(owner, "unexpected_keyword_argument", name, node, function.identity)
    try:
        binding = signature.bind(*positional, **keywords)
    except TypeError as exc:
        if change and change.kind is ChangeKind.RENAME:
            try:
                partial = signature.bind_partial(*positional, **keywords)
            except TypeError:
                partial = None
            missing = [
                p.name
                for p in signature.parameters.values()
                if p.default is p.empty
                and p.kind not in (p.VAR_POSITIONAL, p.VAR_KEYWORD)
                and partial is not None
                and p.name not in partial.arguments
            ]
            if change.new_name is not None and missing == [change.new_name]:
                proof.reject(
                    owner,
                    "required_parameter_unbound",
                    change.new_name,
                    node,
                    function.identity,
                )

        # An entry binding failure prevents the call from entering and does not prove rejection.
        # 入口绑定失败只说明调用无法进入，不能据此认定所选参数被拒绝
        if (
            change is not None
            and caller is None
            and node is None
            and not function.node.decorator_list
        ):
            proof.note(
                function,
                "entry_binding_failed",
                "The original call cannot enter this source implementation: "
                + str(exc)
                + ". This does not reject the selected argument "
                "or authorize its deletion.",
            )
            raise _Stop(ParameterState.NOT_ENTERED, "entry_binding_failed")
        proof.unknown(owner, "call_binding_unproven", str(exc), node)

    # After binding succeeds, apply defaults before constructing the variadic containers.
    # 调用绑定成功后填入默认值，再构造可变参数容器。
    binding.apply_defaults()
    values = dict(binding.arguments)
    if function.signature.vararg:
        values[function.signature.vararg] = _Positionals(
            tuple(values.get(function.signature.vararg, ())), carrier=True
        )
    if function.signature.kwarg:
        values[function.signature.kwarg] = _Keywords(
            values.get(function.signature.kwarg, {}), carrier=True
        )
    return _BoundValues(values, len(positional) + int(bool(bound)))
