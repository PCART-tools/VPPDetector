## @package vppdetector.source.records
#  Indexed function identities and Python signature shapes.
#
#
#  Describe indexed declarations and record positional-only, positional-or-keyword, and
#  keyword-only parameter names, along with the names of the *args and **kwargs slots.
#  描述已索引的声明，记录仅限位置、位置或关键字、仅限关键字三类参数的名称，
#  以及 *args 和 **kwargs 槽位的名称。



from .._records import FrozenRecord, MutableRecord
from ..models import VariadicKind


## Store the parameter categories of one source function signature.
## 保存一个源码函数签名中的参数类别。
class SignatureFacts(FrozenRecord):
    _record_fields = (
        "positional_only",
        "positional_or_keyword",
        "keyword_only",
        "vararg",
        "kwarg",
    )
    __match_args__ = _record_fields

    ## Initialize a SignatureFacts instance with its declared state.
    ## 使用声明的状态初始化 SignatureFacts 实例。
    #
    #  @param positional_only Value stored in the `positional_only` field
    #  @param positional_or_keyword Value stored in the `positional_or_keyword` field
    #  @param keyword_only Value stored in the `keyword_only` field
    #  @param vararg Value stored in the `vararg` field
    #  @param kwarg Value stored in the `kwarg` field
    def __init__(self, positional_only, positional_or_keyword, keyword_only, vararg, kwarg):
        object.__setattr__(self, "positional_only", positional_only)
        object.__setattr__(self, "positional_or_keyword", positional_or_keyword)
        object.__setattr__(self, "keyword_only", keyword_only)
        object.__setattr__(self, "vararg", vararg)
        object.__setattr__(self, "kwarg", kwarg)

    ## Create signature facts from an AST argument list
    ## 根据AST参数列表创建签名事实
    #
    #  @param cls Signature record class receiving the factory call
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
class IndexedFunction(MutableRecord):
    _record_fields = (
        "identity",
        "signature",
        "node",
        "is_overload",
        "is_bound_method",
        "query_class",
        "query_alias",
    )
    __match_args__ = _record_fields

    ## Initialize an indexed source function and its query projections.
    ## 初始化一个索引源码函数及其查询投影。
    #
    #  @param identity Value stored in the `identity` field
    #  @param signature Value stored in the `signature` field
    #  @param node Value stored in the `node` field
    #  @param is_overload Value stored in the `is_overload` field
    #  @param is_bound_method Value stored in the `is_bound_method` field
    #  @param query_class Value stored in the `query_class` field
    #  @param query_alias Value stored in the `query_alias` field
    def __init__(
        self,
        identity,
        signature,
        node,
        is_overload,
        is_bound_method=False,
        query_class=None,
        query_alias=None,
    ):
        self.identity = identity
        self.signature = signature
        self.node = node
        self.is_overload = is_overload
        self.is_bound_method = is_bound_method
        self.query_class = query_class
        self.query_alias = query_alias

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
class IndexedConstructor(FrozenRecord):
    _record_fields = ("class_identity", "function")
    __match_args__ = _record_fields

    ## Pair one indexed initializer with the class it constructs.
    ## 将一个索引初始化方法与其构造的类关联。
    #
    #  @param class_identity Value stored in the `class_identity` field
    #  @param function Value stored in the `function` field
    def __init__(self, class_identity, function):
        object.__setattr__(self, "class_identity", class_identity)
        object.__setattr__(self, "function", function)
