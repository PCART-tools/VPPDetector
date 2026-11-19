## @package vppdetector.models
#  Source identities, findings and parameter-level evidence models.
#
#
#  Define the value records for source, caller inputs, propagation paths, findings, coverage and
#  assessment results.
#  定义源码、调用方输入、传播路径、检测发现、覆盖状态及评估结果记录。



from enum import Enum
from pathlib import Path

from ._records import (
    FACTORY_DEFAULT as _FACTORY_DEFAULT,
)
from ._records import (
    FrozenRecord as _FrozenRecord,
)
from ._records import (
    asdict_record as asdict_record,
)
from ._records import (
    replace_record as replace_record,
)


## Enum whose values remain convenient at CLI and report boundaries.
#
## 在命令行和报告边界便于使用其值的枚举。
class StringEnum(str, Enum):
    ## Return the enum value used at report and CLI boundaries
    ## 返回报告和命令行边界使用的枚举值
    #
    #  @return Enum value as a string
    def __str__(self):
        return self.value


## Identify whether a variadic parameter captures positional or keyword arguments.
## 标识可变参数捕获的是位置实参还是关键字实参。
class VariadicKind(StringEnum):
    POSITIONAL = "var_positional"
    KEYWORD = "var_keyword"


## Identify the supported parameter change operation.
## 标识受支持的参数变更操作。
class ChangeKind(StringEnum):
    DELETE = "delete"
    RENAME = "rename"


## Disposition of one changed argument, not a repair or compatibility verdict.
#
## 单个变更实参的处置状态，不代表修复或兼容性结论。
class ParameterState(StringEnum):
    HANDLED = "handled"
    REJECTED = "rejected"
    IGNORED = "ignored"
    UNKNOWN = "unknown"
    NOT_ENTERED = "not_entered"


## Observed analysis limits, never a proof of complete coverage.
#
## 记录观察到的分析限制，不证明覆盖完整。
class ScanCoverageStatus(StringEnum):
    NO_KNOWN_BOUNDARY = "no_known_boundary"
    LIMITED = "limited"
    UNAVAILABLE = "unavailable"


## One parameter deletion or rename supplied by the caller.
#
## 调用方提供的单项参数删除或重命名。
class ParameterChange(_FrozenRecord):
    _record_fields = ("kind", "old_name", "new_name", "old_position")
    new_name = None
    old_position = None
    __match_args__ = ("kind", "old_name", "new_name", "old_position")

    ## Initialize a ParameterChange instance with its declared state.
    ## 使用声明的状态初始化 ParameterChange 实例。
    #
    #  @param kind Value stored in the `kind` field
    #  @param old_name Value stored in the `old_name` field
    #  @param new_name Value stored in the `new_name` field
    #  @param old_position Value stored in the `old_position` field
    def __init__(self, kind, old_name, new_name=None, old_position=None):
        object.__setattr__(self, "kind", kind)
        object.__setattr__(self, "old_name", old_name)
        object.__setattr__(self, "new_name", new_name)
        object.__setattr__(self, "old_position", old_position)
        self.__post_init__()

    ## Validate and normalize the parameter-change fields
    ## 校验并规范化参数变更字段
    #
    #  @exception ValueError If a parameter name or old position is invalid
    def __post_init__(self):
        object.__setattr__(self, "kind", ChangeKind(self.kind))
        if not self.old_name.isidentifier():
            raise ValueError("old_name must be a parameter name")
        if self.kind is ChangeKind.RENAME and (
            not self.new_name or not self.new_name.isidentifier()
        ):
            raise ValueError("A rename requires new_name")
        if self.old_position is not None and (
            type(self.old_position) is not int or self.old_position < 0
        ):
            raise ValueError("old_position must be a nonnegative integer")


## Source files and module roots available to the analysis.
#
## 分析可使用的源文件和模块根目录。
class SourceContext(_FrozenRecord):
    _record_fields = ("package_root", "import_roots", "dependency_modules")
    __match_args__ = ("package_root", "import_roots", "dependency_modules")

    ## Initialize a SourceContext instance with its declared state.
    ## 使用声明的状态初始化 SourceContext 实例。
    #
    #  @param package_root Value stored in the `package_root` field
    #  @param import_roots Value stored in the `import_roots` field
    #  @param dependency_modules Value stored in the `dependency_modules` field
    def __init__(
        self, package_root, import_roots=_FACTORY_DEFAULT, dependency_modules=_FACTORY_DEFAULT
    ):
        object.__setattr__(self, "package_root", package_root)
        if import_roots is _FACTORY_DEFAULT:
            import_roots = tuple()
        object.__setattr__(self, "import_roots", import_roots)
        if dependency_modules is _FACTORY_DEFAULT:
            dependency_modules = tuple()
        object.__setattr__(self, "dependency_modules", dependency_modules)


## Source-level identity of one function or method.
#
## 函数或方法的源码级身份。
class FunctionIdentity(_FrozenRecord):
    _record_fields = ("module", "qualname", "file_path", "lineno")
    file_path = None
    lineno = None
    __match_args__ = ("module", "qualname", "file_path", "lineno")

    ## Initialize a FunctionIdentity instance with its declared state.
    ## 使用声明的状态初始化 FunctionIdentity 实例。
    #
    #  @param module Value stored in the `module` field
    #  @param qualname Value stored in the `qualname` field
    #  @param file_path Value stored in the `file_path` field
    #  @param lineno Value stored in the `lineno` field
    def __init__(self, module, qualname, file_path=None, lineno=None):
        object.__setattr__(self, "module", module)
        object.__setattr__(self, "qualname", qualname)
        object.__setattr__(self, "file_path", file_path)
        object.__setattr__(self, "lineno", lineno)


## Represent a complete source range with start and end coordinates.
## 表示带有起止坐标的完整源码范围。
class SourceSpan(_FrozenRecord):
    _record_fields = ("file_path", "lineno", "col_offset", "end_lineno", "end_col_offset")
    __match_args__ = ("file_path", "lineno", "col_offset", "end_lineno", "end_col_offset")

    ## Initialize a SourceSpan instance with its declared state.
    ## 使用声明的状态初始化 SourceSpan 实例。
    #
    #  @param file_path Value stored in the `file_path` field
    #  @param lineno Value stored in the `lineno` field
    #  @param col_offset Value stored in the `col_offset` field
    #  @param end_lineno Value stored in the `end_lineno` field
    #  @param end_col_offset Value stored in the `end_col_offset` field
    def __init__(self, file_path, lineno, col_offset, end_lineno, end_col_offset):
        object.__setattr__(self, "file_path", file_path)
        object.__setattr__(self, "lineno", lineno)
        object.__setattr__(self, "col_offset", col_offset)
        object.__setattr__(self, "end_lineno", end_lineno)
        object.__setattr__(self, "end_col_offset", end_col_offset)


## Trusted, call-specific runtime checkpoint; never a static lookup proof.
#
## The observation must come from an uncaught exception trace of the original
## call. The entry and checker mappings contained this same primitive value,
## and the checker lookup produced lookup_value at raise_span.
#
## 可信的特定调用运行时检查点，不构成静态查找证明。观察须来自原调用的未捕获异常轨迹
## ；入口和检查器映射包含同一原始值，且检查器在 raise_span 处查找得到
## lookup_value。
class ObservedKeywordCheck(_FrozenRecord):
    _record_fields = (
        "entry",
        "call_text",
        "keyword",
        "value",
        "checker",
        "raise_span",
        "mapping_parameter",
        "key_variable",
        "lookup_variable",
        "attribute_name",
        "lookup_value",
        "exception",
        "uncaught",
        "source_hashes",
    )
    __match_args__ = (
        "entry",
        "call_text",
        "keyword",
        "value",
        "checker",
        "raise_span",
        "mapping_parameter",
        "key_variable",
        "lookup_variable",
        "attribute_name",
        "lookup_value",
        "exception",
        "uncaught",
        "source_hashes",
    )

    ## Initialize a ObservedKeywordCheck instance with its declared state.
    ## 使用声明的状态初始化 ObservedKeywordCheck 实例。
    #
    #  @param entry Value stored in the `entry` field
    #  @param call_text Value stored in the `call_text` field
    #  @param keyword Value stored in the `keyword` field
    #  @param value Value stored in the `value` field
    #  @param checker Value stored in the `checker` field
    #  @param raise_span Value stored in the `raise_span` field
    #  @param mapping_parameter Value stored in the `mapping_parameter` field
    #  @param key_variable Value stored in the `key_variable` field
    #  @param lookup_variable Value stored in the `lookup_variable` field
    #  @param attribute_name Value stored in the `attribute_name` field
    #  @param lookup_value Value stored in the `lookup_value` field
    #  @param exception Value stored in the `exception` field
    #  @param uncaught Value stored in the `uncaught` field
    #  @param source_hashes Value stored in the `source_hashes` field
    def __init__(
        self,
        entry,
        call_text,
        keyword,
        value,
        checker,
        raise_span,
        mapping_parameter,
        key_variable,
        lookup_variable,
        attribute_name,
        lookup_value,
        exception,
        uncaught,
        source_hashes,
    ):
        object.__setattr__(self, "entry", entry)
        object.__setattr__(self, "call_text", call_text)
        object.__setattr__(self, "keyword", keyword)
        object.__setattr__(self, "value", value)
        object.__setattr__(self, "checker", checker)
        object.__setattr__(self, "raise_span", raise_span)
        object.__setattr__(self, "mapping_parameter", mapping_parameter)
        object.__setattr__(self, "key_variable", key_variable)
        object.__setattr__(self, "lookup_variable", lookup_variable)
        object.__setattr__(self, "attribute_name", attribute_name)
        object.__setattr__(self, "lookup_value", lookup_value)
        object.__setattr__(self, "exception", exception)
        object.__setattr__(self, "uncaught", uncaught)
        object.__setattr__(self, "source_hashes", source_hashes)


## Trusted original-call element provenance into an actual fixed method formal.
#
## A traced source call expanded this exact builtin mapping into the identified
## bound method, which actually entered with the same original primitive in the
## fixed parameter. The original invocation completed normally. This records
## binding consumption, not a general dispatch or compatibility proof.
#
## 原调用元素进入实际方法固定形参的可信来源。轨迹中的源码调用将该精确内置映射展开到
## 指定绑定方法，并以相同原始值进入固定参数；原调用正常完成。这只记录绑定消耗，不证
## 明一般分派或兼容性。
class ObservedFixedBinding(_FrozenRecord):
    _record_fields = (
        "entry",
        "call_text",
        "keyword",
        "value",
        "caller",
        "call_span",
        "target",
        "parameter",
        "mapping_variable",
        "target_bound_receiver",
        "received_builtin_dict",
        "origin_confirmed",
        "target_entered",
        "completed_normally",
        "source_hashes",
    )
    __match_args__ = (
        "entry",
        "call_text",
        "keyword",
        "value",
        "caller",
        "call_span",
        "target",
        "parameter",
        "mapping_variable",
        "target_bound_receiver",
        "received_builtin_dict",
        "origin_confirmed",
        "target_entered",
        "completed_normally",
        "source_hashes",
    )

    ## Initialize a ObservedFixedBinding instance with its declared state.
    ## 使用声明的状态初始化 ObservedFixedBinding 实例。
    #
    #  @param entry Value stored in the `entry` field
    #  @param call_text Value stored in the `call_text` field
    #  @param keyword Value stored in the `keyword` field
    #  @param value Value stored in the `value` field
    #  @param caller Value stored in the `caller` field
    #  @param call_span Value stored in the `call_span` field
    #  @param target Value stored in the `target` field
    #  @param parameter Value stored in the `parameter` field
    #  @param mapping_variable Value stored in the `mapping_variable` field
    #  @param target_bound_receiver Value stored in the `target_bound_receiver` field
    #  @param received_builtin_dict Value stored in the `received_builtin_dict` field
    #  @param origin_confirmed Value stored in the `origin_confirmed` field
    #  @param target_entered Value stored in the `target_entered` field
    #  @param completed_normally Value stored in the `completed_normally` field
    #  @param source_hashes Value stored in the `source_hashes` field
    def __init__(
        self,
        entry,
        call_text,
        keyword,
        value,
        caller,
        call_span,
        target,
        parameter,
        mapping_variable,
        target_bound_receiver,
        received_builtin_dict,
        origin_confirmed,
        target_entered,
        completed_normally,
        source_hashes,
    ):
        object.__setattr__(self, "entry", entry)
        object.__setattr__(self, "call_text", call_text)
        object.__setattr__(self, "keyword", keyword)
        object.__setattr__(self, "value", value)
        object.__setattr__(self, "caller", caller)
        object.__setattr__(self, "call_span", call_span)
        object.__setattr__(self, "target", target)
        object.__setattr__(self, "parameter", parameter)
        object.__setattr__(self, "mapping_variable", mapping_variable)
        object.__setattr__(self, "target_bound_receiver", target_bound_receiver)
        object.__setattr__(self, "received_builtin_dict", received_builtin_dict)
        object.__setattr__(self, "origin_confirmed", origin_confirmed)
        object.__setattr__(self, "target_entered", target_entered)
        object.__setattr__(self, "completed_normally", completed_normally)
        object.__setattr__(self, "source_hashes", source_hashes)


## Trusted original-call rejection by a source nonempty-dictionary guard.
#
## The checker received the selected original primitive in an exact builtin
## dictionary, completed the whole guard with a true outcome and raised the
## uncaught exception at the recorded source statement.
#
## 原调用被源码中的非空字典守卫拒绝的可信记录。检查器在精确内置字典中接收所选原始值
## ，完整守卫结果为真，并在记录的源码语句处抛出未捕获异常。
class ObservedCaptureRejection(_FrozenRecord):
    _record_fields = (
        "entry",
        "call_text",
        "keyword",
        "value",
        "checker",
        "guard_span",
        "raise_span",
        "mapping_parameter",
        "exception",
        "received_builtin_dict",
        "origin_confirmed",
        "guard_value",
        "guard_completed",
        "uncaught",
        "source_hashes",
    )
    __match_args__ = (
        "entry",
        "call_text",
        "keyword",
        "value",
        "checker",
        "guard_span",
        "raise_span",
        "mapping_parameter",
        "exception",
        "received_builtin_dict",
        "origin_confirmed",
        "guard_value",
        "guard_completed",
        "uncaught",
        "source_hashes",
    )

    ## Initialize a ObservedCaptureRejection instance with its declared state.
    ## 使用声明的状态初始化 ObservedCaptureRejection 实例。
    #
    #  @param entry Value stored in the `entry` field
    #  @param call_text Value stored in the `call_text` field
    #  @param keyword Value stored in the `keyword` field
    #  @param value Value stored in the `value` field
    #  @param checker Value stored in the `checker` field
    #  @param guard_span Value stored in the `guard_span` field
    #  @param raise_span Value stored in the `raise_span` field
    #  @param mapping_parameter Value stored in the `mapping_parameter` field
    #  @param exception Value stored in the `exception` field
    #  @param received_builtin_dict Value stored in the `received_builtin_dict` field
    #  @param origin_confirmed Value stored in the `origin_confirmed` field
    #  @param guard_value Value stored in the `guard_value` field
    #  @param guard_completed Value stored in the `guard_completed` field
    #  @param uncaught Value stored in the `uncaught` field
    #  @param source_hashes Value stored in the `source_hashes` field
    def __init__(
        self,
        entry,
        call_text,
        keyword,
        value,
        checker,
        guard_span,
        raise_span,
        mapping_parameter,
        exception,
        received_builtin_dict,
        origin_confirmed,
        guard_value,
        guard_completed,
        uncaught,
        source_hashes,
    ):
        object.__setattr__(self, "entry", entry)
        object.__setattr__(self, "call_text", call_text)
        object.__setattr__(self, "keyword", keyword)
        object.__setattr__(self, "value", value)
        object.__setattr__(self, "checker", checker)
        object.__setattr__(self, "guard_span", guard_span)
        object.__setattr__(self, "raise_span", raise_span)
        object.__setattr__(self, "mapping_parameter", mapping_parameter)
        object.__setattr__(self, "exception", exception)
        object.__setattr__(self, "received_builtin_dict", received_builtin_dict)
        object.__setattr__(self, "origin_confirmed", origin_confirmed)
        object.__setattr__(self, "guard_value", guard_value)
        object.__setattr__(self, "guard_completed", guard_completed)
        object.__setattr__(self, "uncaught", uncaught)
        object.__setattr__(self, "source_hashes", source_hashes)


## Trusted completed class construction retaining the original keyword capture.
#
## The original invocation used type.__call__, object.__new__ and ordinary
## object attribute access/store. Its original constructor receiver is the
## returned instance, whose plain state retains the same builtin capture dict
## and selected primitive after this source assignment and normal completion.
#
## 类构造正常完成后保留原始关键字捕获的可信记录。原调用使用
## type.__call__、object.__new__ 和普通对象属性读写；原构造器接收
## 者是返回实例，其普通状态在源码赋值及正常完成后仍保留同一内置捕获字典和所选原始值。
class ObservedAttributeRetention(_FrozenRecord):
    _record_fields = (
        "entry",
        "call_text",
        "keyword",
        "value",
        "attribute",
        "store_span",
        "retained_builtin_dict",
        "construction_confirmed",
        "store_completed",
        "completed_normally",
        "source_hashes",
    )
    __match_args__ = (
        "entry",
        "call_text",
        "keyword",
        "value",
        "attribute",
        "store_span",
        "retained_builtin_dict",
        "construction_confirmed",
        "store_completed",
        "completed_normally",
        "source_hashes",
    )

    ## Initialize a ObservedAttributeRetention instance with its declared state.
    ## 使用声明的状态初始化 ObservedAttributeRetention 实例。
    #
    #  @param entry Value stored in the `entry` field
    #  @param call_text Value stored in the `call_text` field
    #  @param keyword Value stored in the `keyword` field
    #  @param value Value stored in the `value` field
    #  @param attribute Value stored in the `attribute` field
    #  @param store_span Value stored in the `store_span` field
    #  @param retained_builtin_dict Value stored in the `retained_builtin_dict` field
    #  @param construction_confirmed Value stored in the `construction_confirmed` field
    #  @param store_completed Value stored in the `store_completed` field
    #  @param completed_normally Value stored in the `completed_normally` field
    #  @param source_hashes Value stored in the `source_hashes` field
    def __init__(
        self,
        entry,
        call_text,
        keyword,
        value,
        attribute,
        store_span,
        retained_builtin_dict,
        construction_confirmed,
        store_completed,
        completed_normally,
        source_hashes,
    ):
        object.__setattr__(self, "entry", entry)
        object.__setattr__(self, "call_text", call_text)
        object.__setattr__(self, "keyword", keyword)
        object.__setattr__(self, "value", value)
        object.__setattr__(self, "attribute", attribute)
        object.__setattr__(self, "store_span", store_span)
        object.__setattr__(self, "retained_builtin_dict", retained_builtin_dict)
        object.__setattr__(self, "construction_confirmed", construction_confirmed)
        object.__setattr__(self, "store_completed", store_completed)
        object.__setattr__(self, "completed_normally", completed_normally)
        object.__setattr__(self, "source_hashes", source_hashes)


## Trusted execution of a source predicate on the selected argument's carrier.
#
## The caller independently establishes that this original call entered entry,
## the original element/presence reached selection in the checker's exact builtin
## container, this predicate completed, and the entry body completed normally.
## No runtime object graphs or argument values are accepted in this record.
#
## 对所选实参的承载容器执行源码谓词的可信记录。调用方独立确认原调用进入 entry、原始元素
## 或存在性到达检查器精确内置容器中的选择位置、谓词执行完成且入口函数体正常完成。此记录不接受
## 运行时对象图或实参值。
class ObservedContainerPredicate(_FrozenRecord):
    _record_fields = (
        "entry",
        "call_text",
        "parameter_name",
        "old_position",
        "checker",
        "predicate_span",
        "container_parameter",
        "container_kind",
        "selection",
        "container_size",
        "key_variable",
        "predicate_value",
        "origin_confirmed",
        "predicate_completed",
        "completed_normally",
        "source_hashes",
    )
    __match_args__ = (
        "entry",
        "call_text",
        "parameter_name",
        "old_position",
        "checker",
        "predicate_span",
        "container_parameter",
        "container_kind",
        "selection",
        "container_size",
        "key_variable",
        "predicate_value",
        "origin_confirmed",
        "predicate_completed",
        "completed_normally",
        "source_hashes",
    )

    ## Initialize a ObservedContainerPredicate instance with its declared state.
    ## 使用声明的状态初始化 ObservedContainerPredicate 实例。
    #
    #  @param entry Value stored in the `entry` field
    #  @param call_text Value stored in the `call_text` field
    #  @param parameter_name Value stored in the `parameter_name` field
    #  @param old_position Value stored in the `old_position` field
    #  @param checker Value stored in the `checker` field
    #  @param predicate_span Value stored in the `predicate_span` field
    #  @param container_parameter Value stored in the `container_parameter` field
    #  @param container_kind Value stored in the `container_kind` field
    #  @param selection Value stored in the `selection` field
    #  @param container_size Value stored in the `container_size` field
    #  @param key_variable Value stored in the `key_variable` field
    #  @param predicate_value Value stored in the `predicate_value` field
    #  @param origin_confirmed Value stored in the `origin_confirmed` field
    #  @param predicate_completed Value stored in the `predicate_completed` field
    #  @param completed_normally Value stored in the `completed_normally` field
    #  @param source_hashes Value stored in the `source_hashes` field
    def __init__(
        self,
        entry,
        call_text,
        parameter_name,
        old_position,
        checker,
        predicate_span,
        container_parameter,
        container_kind,
        selection,
        container_size,
        key_variable,
        predicate_value,
        origin_confirmed,
        predicate_completed,
        completed_normally,
        source_hashes,
    ):
        object.__setattr__(self, "entry", entry)
        object.__setattr__(self, "call_text", call_text)
        object.__setattr__(self, "parameter_name", parameter_name)
        object.__setattr__(self, "old_position", old_position)
        object.__setattr__(self, "checker", checker)
        object.__setattr__(self, "predicate_span", predicate_span)
        object.__setattr__(self, "container_parameter", container_parameter)
        object.__setattr__(self, "container_kind", container_kind)
        object.__setattr__(self, "selection", selection)
        object.__setattr__(self, "container_size", container_size)
        object.__setattr__(self, "key_variable", key_variable)
        object.__setattr__(self, "predicate_value", predicate_value)
        object.__setattr__(self, "origin_confirmed", origin_confirmed)
        object.__setattr__(self, "predicate_completed", predicate_completed)
        object.__setattr__(self, "completed_normally", completed_normally)
        object.__setattr__(self, "source_hashes", source_hashes)


## Trusted original-call completion with the same captured primitive value.
#
## The actual source frame received keyword/value and returned an exact builtin
## dict normally at return_span. This attestation alone proves no consumption;
## a matching PCResolve retention fact is additionally required.
#
## 原调用以相同捕获原始值完成的可信记录。实际源码帧接收关键字和值，并在
## return_span 正常返回精确内置字典；该证明本身不证明消耗，还需要匹配的
## PCResolve 保留事实。
class ObservedNormalReturn(_FrozenRecord):
    _record_fields = (
        "entry",
        "call_text",
        "keyword",
        "value",
        "return_span",
        "returned_builtin_dict",
        "source_hashes",
    )
    __match_args__ = (
        "entry",
        "call_text",
        "keyword",
        "value",
        "return_span",
        "returned_builtin_dict",
        "source_hashes",
    )

    ## Initialize a ObservedNormalReturn instance with its declared state.
    ## 使用声明的状态初始化 ObservedNormalReturn 实例。
    #
    #  @param entry Value stored in the `entry` field
    #  @param call_text Value stored in the `call_text` field
    #  @param keyword Value stored in the `keyword` field
    #  @param value Value stored in the `value` field
    #  @param return_span Value stored in the `return_span` field
    #  @param returned_builtin_dict Value stored in the `returned_builtin_dict` field
    #  @param source_hashes Value stored in the `source_hashes` field
    def __init__(
        self, entry, call_text, keyword, value, return_span, returned_builtin_dict, source_hashes
    ):
        object.__setattr__(self, "entry", entry)
        object.__setattr__(self, "call_text", call_text)
        object.__setattr__(self, "keyword", keyword)
        object.__setattr__(self, "value", value)
        object.__setattr__(self, "return_span", return_span)
        object.__setattr__(self, "returned_builtin_dict", returned_builtin_dict)
        object.__setattr__(self, "source_hashes", source_hashes)


## Original call and optional trusted, finite facts for that call only.
#
## known_values supplies primitive constants under source parameter names or
## receiver attribute paths, e.g. (("self.closed", False),). These are caller
## evidence, not expressions to execute. None is distinct from an unknown value.
## bound_receiver overrides the indexed method convention for unbound calls.
## known_targets confirms implementations at exact library call locations;
## copying a nominal PCResolve candidate is not an independent confirmation.
## known_conditions supplies independently established predicate outcomes at
## exact source spans. observed_keyword_checks supplies an explicit original
## call trace checkpoint; these runtime facts never enter scan/producer caches.
## observed_normal_returns confirms original-call completion for a matching
## conditional source retention proof; completion alone never implies handling.
## callsite optionally identifies the exact original source call. Matching
## PCResolve caller facts may recover bounded literals under explicit source
## assumptions; missing/mismatched source keeps syntax-only assessment.
## execution_directory supplies the process working directory for relative
## caller-side file paths
#
## 原调用及仅适用于该调用的可选可信有限事实。known_values
## 按源码参数名或接收者属性路径提供原始常量，作为调用方证据而不执行；None
## 不同于未知值。bound_receiver
## 为非绑定调用覆盖索引方法约定。known_targets
## 在精确调用位置确认实现，复制名义候选不构成独立确认。known_conditions
## 提供精确源码范围内独立确定的谓词结果。observed_keyword_checks 提供
## 原调用轨迹检查点，这些运行时事实不进入扫描或生产者缓存。observed_normal_r
## eturns 确认匹配条件式源码保留证明的原调用完成，本身不意味着已处理。callsite
## 可标识精确原始调用；在明确源码假设下可从匹配的 PCResolve 调用方事实恢复有限字面
## 量，源码缺失或不匹配时保持仅基于语法的评估。execution_directory
## 指定调用方相对文件路径使用的进程工作目录。
class CallContext(_FrozenRecord):
    _record_fields = (
        "expression",
        "bound_receiver",
        "known_values",
        "callsite",
        "known_targets",
        "known_conditions",
        "observed_keyword_checks",
        "observed_normal_returns",
        "observed_container_predicates",
        "observed_attribute_retentions",
        "observed_capture_rejections",
        "observed_fixed_bindings",
        "execution_directory",
    )
    bound_receiver = None
    known_values = ()
    callsite = None
    known_targets = ()
    known_conditions = ()
    observed_keyword_checks = ()
    observed_normal_returns = ()
    observed_container_predicates = ()
    observed_attribute_retentions = ()
    observed_capture_rejections = ()
    observed_fixed_bindings = ()
    execution_directory = None
    __match_args__ = (
        "expression",
        "bound_receiver",
        "known_values",
        "callsite",
        "known_targets",
        "known_conditions",
        "observed_keyword_checks",
        "observed_normal_returns",
        "observed_container_predicates",
        "observed_attribute_retentions",
        "observed_capture_rejections",
        "observed_fixed_bindings",
        "execution_directory",
    )

    ## Initialize a CallContext instance with its declared state.
    ## 使用声明的状态初始化 CallContext 实例。
    #
    #  @param expression Value stored in the `expression` field
    #  @param bound_receiver Value stored in the `bound_receiver` field
    #  @param known_values Value stored in the `known_values` field
    #  @param callsite Value stored in the `callsite` field
    #  @param known_targets Value stored in the `known_targets` field
    #  @param known_conditions Value stored in the `known_conditions` field
    #  @param observed_keyword_checks Value stored in the `observed_keyword_checks` field
    #  @param observed_normal_returns Value stored in the `observed_normal_returns` field
    #  @param observed_container_predicates Caller observations of container tests
    #  @param observed_attribute_retentions Caller observations of retained argument attributes
    #  @param observed_capture_rejections Value stored in the `observed_capture_rejections` field
    #  @param observed_fixed_bindings Value stored in the `observed_fixed_bindings` field
    #  @param execution_directory Value stored in the `execution_directory` field
    def __init__(
        self,
        expression,
        bound_receiver=None,
        known_values=(),
        callsite=None,
        known_targets=(),
        known_conditions=(),
        observed_keyword_checks=(),
        observed_normal_returns=(),
        observed_container_predicates=(),
        observed_attribute_retentions=(),
        observed_capture_rejections=(),
        observed_fixed_bindings=(),
        execution_directory=None,
    ):
        object.__setattr__(self, "expression", expression)
        object.__setattr__(self, "bound_receiver", bound_receiver)
        object.__setattr__(self, "known_values", known_values)
        object.__setattr__(self, "callsite", callsite)
        object.__setattr__(self, "known_targets", known_targets)
        object.__setattr__(self, "known_conditions", known_conditions)
        object.__setattr__(self, "observed_keyword_checks", observed_keyword_checks)
        object.__setattr__(self, "observed_normal_returns", observed_normal_returns)
        object.__setattr__(self, "observed_container_predicates", observed_container_predicates)
        object.__setattr__(self, "observed_attribute_retentions", observed_attribute_retentions)
        object.__setattr__(self, "observed_capture_rejections", observed_capture_rejections)
        object.__setattr__(self, "observed_fixed_bindings", observed_fixed_bindings)
        object.__setattr__(self, "execution_directory", execution_directory)
        self.__post_init__()

    ## Validate and normalize the immutable call-context fields
    ## 校验并规范化不可变调用上下文字段
    #
    #  @exception ValueError If supplied facts, observations or execution directory are invalid
    def __post_init__(self):
        if self.execution_directory is not None:
            try:
                directory = Path(self.execution_directory)
            except (TypeError, ValueError):
                raise ValueError("execution_directory must be an absolute path or None")
            if not directory.is_absolute():
                raise ValueError("execution_directory must be an absolute path or None")
            object.__setattr__(self, "execution_directory", directory)
        if self.bound_receiver is not None and type(self.bound_receiver) is not bool:
            raise ValueError("bound_receiver must be bool or None")
        names = [name for name, _ in self.known_values]
        if len(set(names)) != len(names) or any(
            not all(part.isidentifier() for part in name.split(".")) for name in names
        ):
            raise ValueError("known_values requires unique parameter or attribute paths")
        if any(
            type(value) not in (str, bytes, int, float, bool, type(None))
            for _, value in self.known_values
        ):
            raise ValueError("known_values accepts only primitive constants")

        # Exact callsite coordinates are the keys for supplied targets and conditions.
        # 以精确的调用点坐标标识提供的目标和条件。
        spans = [span for span, _ in self.known_targets]
        if len(set(spans)) != len(spans):
            raise ValueError("known_targets requires unique library call locations")
        conditions = [span for span, _ in self.known_conditions]
        if any(
            not isinstance(span, SourceSpan) or type(value) is not bool
            for span, value in self.known_conditions
        ) or len(set(conditions)) != len(conditions):
            raise ValueError("known_conditions requires unique source spans and bool outcomes")

        # Observation families establish different premises. A single call may use only one.
        # 不同观测类型对应不同的证明前提，每次调用只能使用其中一类。
        observation_types = (
            ("observed_keyword_checks", ObservedKeywordCheck),
            ("observed_normal_returns", ObservedNormalReturn),
            ("observed_container_predicates", ObservedContainerPredicate),
            ("observed_attribute_retentions", ObservedAttributeRetention),
            ("observed_capture_rejections", ObservedCaptureRejection),
            ("observed_fixed_bindings", ObservedFixedBinding),
        )
        present = 0
        for name, record_type in observation_types:
            records = getattr(self, name)
            if len(records) > 8 or any(not isinstance(value, record_type) for value in records):
                raise ValueError(name + " requires bounded observation records")
            present += bool(records)
        if present > 1:
            raise ValueError("Supply one observation family for an assessment")


## A diagnostic explaining an analysis limit, rather than a VPP finding.
#
## 解释分析限制的诊断，不属于 VPP 发现。
class AnalysisBoundary(_FrozenRecord):
    _record_fields = (
        "code",
        "message",
        "function",
        "callsite",
        "root_function",
        "parameter_name",
        "parameter_kind",
    )
    function = None
    callsite = None
    root_function = None
    parameter_name = None
    parameter_kind = None
    __match_args__ = (
        "code",
        "message",
        "function",
        "callsite",
        "root_function",
        "parameter_name",
        "parameter_kind",
    )

    ## Initialize a AnalysisBoundary instance with its declared state.
    ## 使用声明的状态初始化 AnalysisBoundary 实例。
    #
    #  @param code Value stored in the `code` field
    #  @param message Value stored in the `message` field
    #  @param function Value stored in the `function` field
    #  @param callsite Value stored in the `callsite` field
    #  @param root_function Value stored in the `root_function` field
    #  @param parameter_name Value stored in the `parameter_name` field
    #  @param parameter_kind Value stored in the `parameter_kind` field
    def __init__(
        self,
        code,
        message,
        function=None,
        callsite=None,
        root_function=None,
        parameter_name=None,
        parameter_kind=None,
    ):
        object.__setattr__(self, "code", code)
        object.__setattr__(self, "message", message)
        object.__setattr__(self, "function", function)
        object.__setattr__(self, "callsite", callsite)
        object.__setattr__(self, "root_function", root_function)
        object.__setattr__(self, "parameter_name", parameter_name)
        object.__setattr__(self, "parameter_kind", parameter_kind)


## A binding, use, drop or selected condition supporting an assessment.
#
## 支持评估的绑定、使用、丢弃或选定条件。
class ParameterEvidence(_FrozenRecord):
    _record_fields = ("function", "reason", "detail", "callsite", "target")
    callsite = None
    target = None
    __match_args__ = ("function", "reason", "detail", "callsite", "target")

    ## Initialize a ParameterEvidence instance with its declared state.
    ## 使用声明的状态初始化 ParameterEvidence 实例。
    #
    #  @param function Value stored in the `function` field
    #  @param reason Value stored in the `reason` field
    #  @param detail Value stored in the `detail` field
    #  @param callsite Value stored in the `callsite` field
    #  @param target Value stored in the `target` field
    def __init__(self, function, reason, detail, callsite=None, target=None):
        object.__setattr__(self, "function", function)
        object.__setattr__(self, "reason", reason)
        object.__setattr__(self, "detail", detail)
        object.__setattr__(self, "callsite", callsite)
        object.__setattr__(self, "target", target)


## Handling state and supporting evidence for one changed argument in a call.
#
## 调用中一个变更实参的处理状态及其证据。
class ParameterAssessment(_FrozenRecord):
    _record_fields = (
        "target_api",
        "change",
        "call_text",
        "state",
        "reason",
        "evidence",
        "boundaries",
        "resolved_api",
        "callsite",
    )
    evidence = ()
    boundaries = ()
    resolved_api = None
    callsite = None
    __match_args__ = (
        "target_api",
        "change",
        "call_text",
        "state",
        "reason",
        "evidence",
        "boundaries",
        "resolved_api",
        "callsite",
    )

    ## Initialize a ParameterAssessment instance with its declared state.
    ## 使用声明的状态初始化 ParameterAssessment 实例。
    #
    #  @param target_api Value stored in the `target_api` field
    #  @param change Value stored in the `change` field
    #  @param call_text Value stored in the `call_text` field
    #  @param state Value stored in the `state` field
    #  @param reason Value stored in the `reason` field
    #  @param evidence Value stored in the `evidence` field
    #  @param boundaries Value stored in the `boundaries` field
    #  @param resolved_api Value stored in the `resolved_api` field
    #  @param callsite Value stored in the `callsite` field
    def __init__(
        self,
        target_api,
        change,
        call_text,
        state,
        reason,
        evidence=(),
        boundaries=(),
        resolved_api=None,
        callsite=None,
    ):
        object.__setattr__(self, "target_api", target_api)
        object.__setattr__(self, "change", change)
        object.__setattr__(self, "call_text", call_text)
        object.__setattr__(self, "state", state)
        object.__setattr__(self, "reason", reason)
        object.__setattr__(self, "evidence", evidence)
        object.__setattr__(self, "boundaries", boundaries)
        object.__setattr__(self, "resolved_api", resolved_api)
        object.__setattr__(self, "callsite", callsite)


## Report one indexed source function and its variadic channels.
## 报告一个已索引源码函数及其可变参数通道。
class VariadicFunction(_FrozenRecord):
    _record_fields = ("function", "parameters", "implementation")
    implementation = None
    __match_args__ = ("function", "parameters", "implementation")

    ## Initialize a VariadicFunction instance with its declared state.
    ## 使用声明的状态初始化 VariadicFunction 实例。
    #
    #  @param function Value stored in the `function` field
    #  @param parameters Value stored in the `parameters` field
    #  @param implementation Value stored in the `implementation` field
    def __init__(self, function, parameters, implementation=None):
        object.__setattr__(self, "function", function)
        object.__setattr__(self, "parameters", parameters)
        object.__setattr__(self, "implementation", implementation)


## One source or proven builtin-protocol hop in an API's forwarding path.
#
## API 转发路径中的一个源码或已证明的内置协议步骤。
class ForwardingStep(_FrozenRecord):
    _record_fields = (
        "function",
        "parameter_name",
        "callee_expression",
        "callsite",
        "target",
        "target_status",
        "conditions",
    )
    target_status = "resolved"
    __match_args__ = (
        "function",
        "parameter_name",
        "callee_expression",
        "callsite",
        "target",
        "target_status",
        "conditions",
    )

    ## Initialize a ForwardingStep instance with its declared state.
    ## 使用声明的状态初始化 ForwardingStep 实例。
    #
    #  @param function Value stored in the `function` field
    #  @param parameter_name Value stored in the `parameter_name` field
    #  @param callee_expression Value stored in the `callee_expression` field
    #  @param callsite Value stored in the `callsite` field
    #  @param target Value stored in the `target` field
    #  @param target_status Value stored in the `target_status` field
    #  @param conditions Value stored in the `conditions` field
    def __init__(
        self,
        function,
        parameter_name,
        callee_expression,
        callsite,
        target,
        target_status="resolved",
        conditions=_FACTORY_DEFAULT,
    ):
        object.__setattr__(self, "function", function)
        object.__setattr__(self, "parameter_name", parameter_name)
        object.__setattr__(self, "callee_expression", callee_expression)
        object.__setattr__(self, "callsite", callsite)
        object.__setattr__(self, "target", target)
        object.__setattr__(self, "target_status", target_status)
        if conditions is _FACTORY_DEFAULT:
            conditions = tuple()
        object.__setattr__(self, "conditions", conditions)


## A root variadic parameter reaches an incompatible expansion signature.
#
## 根可变参数到达不兼容的展开签名。
class ForwardingFinding(_FrozenRecord):
    _record_fields = (
        "function",
        "parameter_name",
        "parameter_kind",
        "callee_expression",
        "callsite",
        "target",
        "reason_code",
        "path",
        "target_status",
        "target_candidates",
        "receiver_type_evidence",
        "conditions",
    )
    target_status = "resolved"
    __match_args__ = (
        "function",
        "parameter_name",
        "parameter_kind",
        "callee_expression",
        "callsite",
        "target",
        "reason_code",
        "path",
        "target_status",
        "target_candidates",
        "receiver_type_evidence",
        "conditions",
    )

    ## Initialize a ForwardingFinding instance with its declared state.
    ## 使用声明的状态初始化 ForwardingFinding 实例。
    #
    #  @param function Value stored in the `function` field
    #  @param parameter_name Value stored in the `parameter_name` field
    #  @param parameter_kind Value stored in the `parameter_kind` field
    #  @param callee_expression Value stored in the `callee_expression` field
    #  @param callsite Value stored in the `callsite` field
    #  @param target Value stored in the `target` field
    #  @param reason_code Value stored in the `reason_code` field
    #  @param path Value stored in the `path` field
    #  @param target_status Value stored in the `target_status` field
    #  @param target_candidates Value stored in the `target_candidates` field
    #  @param receiver_type_evidence Value stored in the `receiver_type_evidence` field
    #  @param conditions Value stored in the `conditions` field
    def __init__(
        self,
        function,
        parameter_name,
        parameter_kind,
        callee_expression,
        callsite,
        target,
        reason_code,
        path=_FACTORY_DEFAULT,
        target_status="resolved",
        target_candidates=_FACTORY_DEFAULT,
        receiver_type_evidence=_FACTORY_DEFAULT,
        conditions=_FACTORY_DEFAULT,
    ):
        object.__setattr__(self, "function", function)
        object.__setattr__(self, "parameter_name", parameter_name)
        object.__setattr__(self, "parameter_kind", parameter_kind)
        object.__setattr__(self, "callee_expression", callee_expression)
        object.__setattr__(self, "callsite", callsite)
        object.__setattr__(self, "target", target)
        object.__setattr__(self, "reason_code", reason_code)
        if path is _FACTORY_DEFAULT:
            path = tuple()
        object.__setattr__(self, "path", path)
        object.__setattr__(self, "target_status", target_status)
        if target_candidates is _FACTORY_DEFAULT:
            target_candidates = tuple()
        object.__setattr__(self, "target_candidates", target_candidates)
        if receiver_type_evidence is _FACTORY_DEFAULT:
            receiver_type_evidence = tuple()
        object.__setattr__(self, "receiver_type_evidence", receiver_type_evidence)
        if conditions is _FACTORY_DEFAULT:
            conditions = tuple()
        object.__setattr__(self, "conditions", conditions)


## One root channel's findings and recorded limits in a scan snapshot.
#
## 扫描快照中一个根通道的发现和记录的限制。
class VariadicCoverage(_FrozenRecord):
    _record_fields = (
        "function",
        "parameter_name",
        "parameter_kind",
        "status",
        "finding_count",
        "boundary_codes",
        "implementation",
    )
    finding_count = 0
    boundary_codes = ()
    implementation = None
    __match_args__ = (
        "function",
        "parameter_name",
        "parameter_kind",
        "status",
        "finding_count",
        "boundary_codes",
        "implementation",
    )

    ## Initialize a VariadicCoverage instance with its declared state.
    ## 使用声明的状态初始化 VariadicCoverage 实例。
    #
    #  @param function Value stored in the `function` field
    #  @param parameter_name Value stored in the `parameter_name` field
    #  @param parameter_kind Value stored in the `parameter_kind` field
    #  @param status Value stored in the `status` field
    #  @param finding_count Value stored in the `finding_count` field
    #  @param boundary_codes Value stored in the `boundary_codes` field
    #  @param implementation Value stored in the `implementation` field
    def __init__(
        self,
        function,
        parameter_name,
        parameter_kind,
        status,
        finding_count=0,
        boundary_codes=(),
        implementation=None,
    ):
        object.__setattr__(self, "function", function)
        object.__setattr__(self, "parameter_name", parameter_name)
        object.__setattr__(self, "parameter_kind", parameter_kind)
        object.__setattr__(self, "status", status)
        object.__setattr__(self, "finding_count", finding_count)
        object.__setattr__(self, "boundary_codes", boundary_codes)
        object.__setattr__(self, "implementation", implementation)


## Positive VPP findings and diagnostics for one scan scope.
#
## 一个扫描范围内的正向 VPP 发现和诊断。
class ScanReport(_FrozenRecord):
    _record_fields = (
        "source",
        "functions_scanned",
        "variadic_functions",
        "findings",
        "boundaries",
        "analyzer_schema_version",
        "target_api",
        "resolved_api",
        "coverage",
    )
    analyzer_schema_version = None
    target_api = None
    resolved_api = None
    coverage = ()
    __match_args__ = (
        "source",
        "functions_scanned",
        "variadic_functions",
        "findings",
        "boundaries",
        "analyzer_schema_version",
        "target_api",
        "resolved_api",
        "coverage",
    )

    ## Initialize a ScanReport instance with its declared state.
    ## 使用声明的状态初始化 ScanReport 实例。
    #
    #  @param source Value stored in the `source` field
    #  @param functions_scanned Value stored in the `functions_scanned` field
    #  @param variadic_functions Value stored in the `variadic_functions` field
    #  @param findings Value stored in the `findings` field
    #  @param boundaries Value stored in the `boundaries` field
    #  @param analyzer_schema_version Value stored in the `analyzer_schema_version` field
    #  @param target_api Value stored in the `target_api` field
    #  @param resolved_api Value stored in the `resolved_api` field
    #  @param coverage Value stored in the `coverage` field
    def __init__(
        self,
        source,
        functions_scanned,
        variadic_functions,
        findings,
        boundaries=_FACTORY_DEFAULT,
        analyzer_schema_version=None,
        target_api=None,
        resolved_api=None,
        coverage=(),
    ):
        object.__setattr__(self, "source", source)
        object.__setattr__(self, "functions_scanned", functions_scanned)
        object.__setattr__(self, "variadic_functions", variadic_functions)
        object.__setattr__(self, "findings", findings)
        if boundaries is _FACTORY_DEFAULT:
            boundaries = tuple()
        object.__setattr__(self, "boundaries", boundaries)
        object.__setattr__(self, "analyzer_schema_version", analyzer_schema_version)
        object.__setattr__(self, "target_api", target_api)
        object.__setattr__(self, "resolved_api", resolved_api)
        object.__setattr__(self, "coverage", coverage)

    ## Whether this scan found a VPP; false does not prove full coverage
    ## 判断扫描是否发现VPP；False不代表分析覆盖完整
    #
    #  @return Whether at least one finding was recorded
    @property
    def has_vpp(self):
        return bool(self.findings)

    ## Compatibility alias for the positive findings collection
    ## 提供兼容旧调用方的潜在问题只读别名
    #
    #  @return The report's tuple of positive findings
    @property
    def potential_pitfalls(self):
        return self.findings
