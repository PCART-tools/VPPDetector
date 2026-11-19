## @package vppdetector.assess.values
#  Abstract values used by the parameter assessment interpreter.
#
#
#  Represent finite scalars, selected arguments, containers and callable values and track their
#  relationship to the selected input.
#  表示有限标量、选定实参、容器和可调用值，并跟踪其与选定输入的关系。



from .._records import FrozenRecord, MutableRecord

_UNKNOWN = object()


## Source parameter values retaining the actual wrapper argument count.
#
## 保留包装函数实际实参数量的源码参数值。
class _BoundValues(dict):
    ## Store abstract bindings with the original positional argument count.
    ## 保存抽象绑定及原始位置实参数量。
    #
    #  @param values Abstract values propagated through the analysis
    #  @param positional_count Number of positional arguments supplied
    def __init__(self, values, positional_count):
        super().__init__(values)
        self.positional_count = positional_count


## Represent a bounded value and its tracked provenance.
## 表示有界值及其跟踪来源。
class _Value(FrozenRecord):
    _record_fields = (
        "literal",
        "tracked",
        "key_presence",
        "source_state",
        "consumed",
        "type_selected",
        "iterable",
        "derived",
    )
    literal = _UNKNOWN
    tracked = False
    key_presence = False
    source_state = False
    consumed = False
    type_selected = False
    iterable = None
    derived = False
    __match_args__ = (
        "literal",
        "tracked",
        "key_presence",
        "source_state",
        "consumed",
        "type_selected",
        "iterable",
        "derived",
    )

    ## Store one bounded value and its provenance flags.
    ## 保存单个有界值及其来源标记。
    #
    #  @param literal Known literal value, or the unknown sentinel
    #  @param tracked Whether the value derives from the selected argument
    #  @param key_presence Whether its meaning depends on key presence
    #  @param source_state Whether it represents mutable source state
    #  @param consumed Whether a supported operation consumed the value
    #  @param type_selected Whether a selected type fact contributed to it
    #  @param iterable Optional finite iterable projection
    #  @param derived Whether the value was derived from another value
    def __init__(
        self,
        literal=_UNKNOWN,
        tracked=False,
        key_presence=False,
        source_state=False,
        consumed=False,
        type_selected=False,
        iterable=None,
        derived=False,
    ):
        object.__setattr__(self, "literal", literal)
        object.__setattr__(self, "tracked", tracked)
        object.__setattr__(self, "key_presence", key_presence)
        object.__setattr__(self, "source_state", source_state)
        object.__setattr__(self, "consumed", consumed)
        object.__setattr__(self, "type_selected", type_selected)
        object.__setattr__(self, "iterable", iterable)
        object.__setattr__(self, "derived", derived)


## Represent a finite keyword mapping and its carrier state.
## 表示有限关键字映射及其载体状态。
class _Keywords(MutableRecord):
    _record_fields = ("items", "carrier", "source_state")
    carrier = False
    source_state = False
    __match_args__ = ("items", "carrier", "source_state")

    ## Store finite keyword items and their carrier/source-state flags.
    ## 保存有限关键字项及其载体和源码状态标记。
    #
    #  @param items Mapping of keyword names to abstract values
    #  @param carrier Whether the mapping is the selected variadic carrier
    #  @param source_state Whether the mapping represents mutable source state
    def __init__(self, items, carrier=False, source_state=False):
        object.__setattr__(self, "items", items)
        object.__setattr__(self, "carrier", carrier)
        object.__setattr__(self, "source_state", source_state)


## Represent positional values and their expansion carrier.
## 表示位置实参值及其展开载体。
class _Positionals(FrozenRecord):
    _record_fields = ("items", "carrier", "kind", "source_state")
    carrier = False
    kind = "tuple"
    source_state = False
    __match_args__ = ("items", "carrier", "kind", "source_state")

    ## Store finite positional items and their expansion kind.
    ## 保存有限位置项及其展开类型。
    #
    #  @param items Ordered abstract positional values
    #  @param carrier Whether the sequence is the selected variadic carrier
    #  @param kind Built-in sequence kind represented by the value
    #  @param source_state Whether the sequence represents mutable source state
    def __init__(self, items, carrier=False, kind="tuple", source_state=False):
        object.__setattr__(self, "items", items)
        object.__setattr__(self, "carrier", carrier)
        object.__setattr__(self, "kind", kind)
        object.__setattr__(self, "source_state", source_state)


## Represent known keys and their tracked presence in the selected argument.
## 表示所选实参中已知键及其跟踪的出现状态。
class _KeySet(FrozenRecord):
    _record_fields = ("items",)
    __match_args__ = ("items",)

    ## Store known mapping keys and their tracked-presence flags.
    ## 保存已知映射键及其跟踪的出现标记。
    #
    #  @param items Mapping of keys to selected-presence booleans
    def __init__(self, items):
        object.__setattr__(self, "items", items)

## Represent a source-defined instance with modeled attributes.
## 表示带有建模属性的源码定义实例。
class _SourceInstance(FrozenRecord):
    _record_fields = ("attributes",)
    __match_args__ = ("attributes",)

    ## Initialize a _SourceInstance instance with its declared state.
    ## 使用声明的状态初始化 _SourceInstance 实例。
    #
    #  @param attributes Value stored in the `attributes` field
    def __init__(self, attributes):
        object.__setattr__(self, "attributes", attributes)


## Represent a directly imported source class with a verified constructor
## 表示具有已验证构造器的直接导入源码类
class _SourceClass(FrozenRecord):
    _record_fields = ("identity", "constructor")
    __match_args__ = ("identity", "constructor")

    ## Initialize a _SourceClass instance with its declared state.
    ## 使用声明的状态初始化 _SourceClass 实例。
    #
    #  @param identity Value stored in the `identity` field
    #  @param constructor Value stored in the `constructor` field
    def __init__(self, identity, constructor):
        object.__setattr__(self, "identity", identity)
        object.__setattr__(self, "constructor", constructor)


## Represent a local function available to source interpretation.
## 表示源码解释器可处理的局部函数。
class _LocalFunction(FrozenRecord):
    _record_fields = ("node",)
    __match_args__ = ("node",)

    ## Initialize a _LocalFunction instance with its declared state.
    ## 使用声明的状态初始化 _LocalFunction 实例。
    #
    #  @param node Value stored in the `node` field
    def __init__(self, node):
        object.__setattr__(self, "node", node)


## Represent a bounded text file supplied by an exact caller context manager
## 表示由精确调用方上下文管理器提供的有界文本文件
class _CallerFile(MutableRecord):
    _record_fields = ("text", "path", "sha256", "context_evidence", "read_count")
    context_evidence = None
    read_count = 0
    __match_args__ = ("text", "path", "sha256", "context_evidence", "read_count")

    ## Initialize a _CallerFile instance with its declared state.
    ## 使用声明的状态初始化 _CallerFile 实例。
    #
    #  @param text Value stored in the `text` field
    #  @param path Value stored in the `path` field
    #  @param sha256 Value stored in the `sha256` field
    #  @param context_evidence Value stored in the `context_evidence` field
    #  @param read_count Value stored in the `read_count` field
    def __init__(self, text, path, sha256, context_evidence=None, read_count=0):
        object.__setattr__(self, "text", text)
        object.__setattr__(self, "path", path)
        object.__setattr__(self, "sha256", sha256)
        object.__setattr__(self, "context_evidence", context_evidence)
        object.__setattr__(self, "read_count", read_count)


## Represent the source owner fields required for receiver member lookup.
## 表示接收者成员查找所需的源码所属类字段。
class _ReceiverOwner(FrozenRecord):
    _record_fields = ("module", "qualname")
    __match_args__ = ("module", "qualname")

    ## Initialize a _ReceiverOwner instance with its declared state.
    ## 使用声明的状态初始化 _ReceiverOwner 实例。
    #
    #  @param module Value stored in the `module` field
    #  @param qualname Value stored in the `qualname` field
    def __init__(self, module, qualname):
        object.__setattr__(self, "module", module)
        object.__setattr__(self, "qualname", qualname)


## Mark a source receiver class record whose required shape was checked.
## 标记已检查所需形状的源码接收者类记录。
class _ReceiverClassEvidence(FrozenRecord):
    ## Create the marker for validated receiver-class evidence.
    ## 创建表示已校验接收者类证据的标记。
    _record_fields = ()
    __match_args__ = ()
    pass


## Preserve the allocation effects needed for later receiver member lookups.
## 保存后续接收者成员查找所需的分配影响。
class _ReceiverAllocation(FrozenRecord):
    _record_fields = (
        "decorated_members",
        "aliases",
        "forwarding_aliases",
        "lookup_error",
        "forwarding_error",
    )
    lookup_error = None
    forwarding_error = None
    __match_args__ = (
        "decorated_members",
        "aliases",
        "forwarding_aliases",
        "lookup_error",
        "forwarding_error",
    )

    ## Initialize a _ReceiverAllocation instance with its declared state.
    ## 使用声明的状态初始化 _ReceiverAllocation 实例。
    #
    #  @param decorated_members Value stored in the `decorated_members` field
    #  @param aliases Value stored in the `aliases` field
    #  @param forwarding_aliases Value stored in the `forwarding_aliases` field
    #  @param lookup_error Value stored in the `lookup_error` field
    #  @param forwarding_error Value stored in the `forwarding_error` field
    def __init__(
        self,
        decorated_members,
        aliases,
        forwarding_aliases,
        lookup_error=None,
        forwarding_error=None,
    ):
        object.__setattr__(self, "decorated_members", decorated_members)
        object.__setattr__(self, "aliases", aliases)
        object.__setattr__(self, "forwarding_aliases", forwarding_aliases)
        object.__setattr__(self, "lookup_error", lookup_error)
        object.__setattr__(self, "forwarding_error", forwarding_error)


## Project allocation records to the effects needed for member lookup.
## 将分配记录投影为成员查找所需的影响。
#
#  @param allocation Producer allocation record or a previously projected value
#  @return Lookup effects, including deferred errors, or None for a non-record input
def _allocation_effects(allocation):
    if isinstance(allocation, _ReceiverAllocation):
        return allocation
    if not isinstance(allocation, dict):
        return None
    decorated = set()
    aliases = {}
    forwarding = []
    forwarding_error = None
    try:
        for decoration in allocation.get("class_decorations", ()):
            decorated.update(decoration.get("attributes", ()))
            for generated in decoration.get("generated_class_members", ()):
                if not isinstance(generated, dict):
                    try:
                        generated.get("attribute")
                    except AttributeError as exc:
                        if forwarding_error is None:
                            forwarding_error = (type(exc), exc.args)
                    continue
                attribute = generated.get("attribute")
                target = generated.get("target_method")
                attribute = attribute if isinstance(attribute, str) else None
                target = target if isinstance(target, str) else None
                if attribute is not None:
                    aliases[attribute] = target
                if (
                    generated.get("kind") == "source_alias_method"
                    and generated.get("wrapper_body") == "forward_same_arguments_to_target_method"
                ):
                    forwarding.append((attribute, target))
        for hook in allocation.get("class_creation_hooks", ()):
            if isinstance(hook, dict):
                decorated.update(hook.get("attributes", ()))
    except (AttributeError, TypeError) as exc:
        return _ReceiverAllocation(frozenset(), (), (), (type(exc), exc.args))
    if not all(isinstance(item, str) for item in decorated):
        return None
    return _ReceiverAllocation(
        frozenset(decorated),
        tuple(aliases.items()),
        tuple(forwarding),
        forwarding_error=forwarding_error,
    )


## Represent a source method bound to a modeled receiver.
## 表示绑定到建模接收者的源码方法。
class _BoundSourceMethod(FrozenRecord):
    _record_fields = (
        "target",
        "tracked",
        "key_presence",
        "decorated_members",
        "own_attributes",
        "receiver_class",
        "hierarchy",
        "allocation",
    )
    tracked = False
    key_presence = False
    decorated_members = frozenset()
    own_attributes = frozenset()
    receiver_class = None
    hierarchy = ()
    allocation = None
    __match_args__ = (
        "target",
        "tracked",
        "key_presence",
        "decorated_members",
        "own_attributes",
        "receiver_class",
        "hierarchy",
        "allocation",
    )

    ## Initialize a _BoundSourceMethod instance with its declared state.
    ## 使用声明的状态初始化 _BoundSourceMethod 实例。
    #
    #  @param target Value stored in the `target` field
    #  @param tracked Value stored in the `tracked` field
    #  @param key_presence Value stored in the `key_presence` field
    #  @param decorated_members Value stored in the `decorated_members` field
    #  @param own_attributes Value stored in the `own_attributes` field
    #  @param receiver_class Value stored in the `receiver_class` field
    #  @param hierarchy Value stored in the `hierarchy` field
    #  @param allocation Value stored in the `allocation` field
    def __init__(
        self,
        target,
        tracked=False,
        key_presence=False,
        decorated_members=frozenset(),
        own_attributes=frozenset(),
        receiver_class=None,
        hierarchy=(),
        allocation=None,
    ):
        object.__setattr__(self, "target", target)
        object.__setattr__(self, "tracked", tracked)
        object.__setattr__(self, "key_presence", key_presence)
        object.__setattr__(self, "decorated_members", decorated_members)
        object.__setattr__(self, "own_attributes", own_attributes)
        object.__setattr__(self, "receiver_class", receiver_class)
        object.__setattr__(self, "hierarchy", hierarchy)
        object.__setattr__(self, "allocation", allocation)


## Read the bounded source-derived state of an abstract value
## 读取抽象值中有界的源码状态
#
#  @param value Source-derived value record to convert
#  @return Modeled caller file, scalar, iterable, mapping or sequence state
#  @exception ValueError If the value is not a supported source-derived state
def _source_state(
    value,
):
    if not isinstance(value, dict):
        raise ValueError("Unproven receiver state")
    kind = value.get("kind")
    if (
        kind == "caller_file_text"
        and isinstance(value.get("text"), str)
        and isinstance(value.get("path"), str)
        and isinstance(value.get("sha256"), str)
    ):
        return _CallerFile(
            value["text"], value["path"], value["sha256"], value.get("context_evidence")
        )

    if kind == "literal" and type(value.get("value")) in (str, bytes, int, float, bool, type(None)):
        return _Value(value["value"], source_state=True)
    if (
        kind == "iterable"
        and value.get("basis") == "bounded_stub_return_protocol"
        and isinstance(value.get("call_target"), str)
    ):
        return _Value(source_state=True, iterable=True)
    if (
        kind == "mapping"
        and isinstance(value.get("items"), dict)
        and all(type(key) is str for key in value["items"])
    ):
        return _Keywords(
            {key: _source_state(item) for key, item in value["items"].items()}, source_state=True
        )
    if kind in {"tuple", "list"} and isinstance(value.get("items"), list):
        return _Positionals(
            tuple(_source_state(item) for item in value["items"]), kind=kind, source_state=True
        )
    raise ValueError("Unproven receiver state")


## Check whether the selected value remains linked to the changed argument
## 检查选定值是否仍关联到变更实参
#
#  @param value Abstract value whose selected-argument provenance is checked
#  @return Whether the value or its supported contents are tracked
def _tracked(value):
    if isinstance(value, _Keywords):
        return any(_tracked(item) for item in value.items.values())
    if isinstance(value, _Positionals):
        return any(_tracked(item) for item in value.items)
    if isinstance(value, _KeySet):
        return any(value.items.values())
    return isinstance(value, _Value) and value.tracked


## Keep unresolved original values distinct from proved scalar conversions
## 区分尚未解析的原始值与已证明的标量转换值
#
#  @param value Abstract value checked for unconsumed selected content
#  @param seen Optional set of visited object identities used to avoid cycles
#  @param consumed_values Values already proven consumed on this path
#  @return Whether an unconsumed selected value remains reachable
def _raw_selected(
    value,
    seen=None,
    consumed_values=(),
):

    # Exclude already consumed objects by identity, including when reached through an alias.
    # 按对象身份排除已消费的值，包括通过别名访问的值。
    if any(value is consumed for consumed in consumed_values):
        return False
    seen = set() if seen is None else seen
    if id(value) in seen:
        return False
    seen.add(id(value))
    if isinstance(value, _Value):
        return value.tracked and not value.consumed
    if isinstance(value, _Keywords):
        return any(_raw_selected(item, seen, consumed_values) for item in value.items.values())
    if isinstance(value, _Positionals):
        return any(_raw_selected(item, seen, consumed_values) for item in value.items)
    if isinstance(value, _SourceInstance):
        return any(_raw_selected(item, seen, consumed_values) for item in value.attributes.values())
    return isinstance(value, _KeySet) and _tracked(value)


## Check whether a value carries a protected source-state fact
## 检查值是否携带受保护的源码状态事实
#
#  @param value Abstract value checked for protected source state
#  @return Whether the value or its supported contents carry protected source state
def _protected_state(value):
    if isinstance(value, _SourceInstance):
        return True
    if bool(getattr(value, "source_state", False)):
        return True
    if isinstance(value, _Positionals):
        return any(_protected_state(item) for item in value.items)
    if isinstance(value, _Keywords):
        return any(_protected_state(item) for item in value.items.values())
    return False


## Check whether the selected value represents tracked key presence
## 检查选定值是否表示被跟踪键的出现
#
#  @param value Abstract value checked for tracked key presence
#  @return Whether the value represents tracked key presence
def _key_presence(value):
    if isinstance(value, _Value):
        return value.key_presence
    return isinstance(value, (_Keywords, _KeySet)) and _tracked(value)
