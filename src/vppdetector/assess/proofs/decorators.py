## @package vppdetector.assess.proofs.decorators
#  Proof checks for source-decorator behavior and body preservation.
#
#
#  Combine source proof checks to decide whether the underlying body can be followed when a
#  callable is decorated.
#  组合源码证明检查，判断可调用对象被装饰时能否继续跟进底层函数体。



import hashlib
from pathlib import Path

from ...facts.calls import identity_from_target
from ..proofs._cached_imports import decorator_import_binding
from ..proofs._callable_object_decorators import source_callable_object_decorator_binding
from ..proofs._decorator_exceptions import exception_raise_binding
from ..proofs._fresh_decoration import binding as fresh_decoration_binding
from ..proofs._fresh_decoration import documentation_format as isolated_documentation_format
from ..proofs._wrapper_forwarding import binding as wrapper_forwarding_binding


## Check whether one source decorator preserves the called function's behavior.
## 检查源码装饰器是否保留被调用函数的行为。
#
#  @param proof Proof ledger receiving established evidence
#  @param source_index Index used to resolve source definitions
#  @param function Function whose decorator is being checked
#  @param analysis Producer analysis for the function
#  @param positional_count Known positional argument count, when available
#  @return True when preservation is proven
def decoration_preserved(proof, source_index, function, analysis, positional_count=None):
    forwarding = (
        wrapper_forwarding_binding(source_index, analysis, function, positional_count)
        if positional_count is not None
        else None
    )
    if forwarding is not None:
        proof.note(
            function,
            "source_wrapper_argument_forwarding",
            "This actual call follows the proved same-args-and-kwargs wrapper path; "
            + "; ".join(forwarding["assumptions"]),
            function.node.decorator_list[0],
        )
        return True

    # Use the general effect proof when exact wrapper forwarding has not established the body.
    # 精确包装器转发未能证明函数体时，改用通用的效果证明。
    summaries = [
        item
        for item in analysis.functions
        if identity_from_target(item["function"]) == function.identity
    ]
    if len(function.node.decorator_list) != 1 or len(summaries) != 1:
        return False
    effects = summaries[0].get("decorator_effects", ())
    if len(effects) != 1:
        return False
    fact, isolated = _decoration_fact(
        proof, source_index, function, analysis, summaries[0], effects[0]
    )
    if fact is True:
        return True
    if fact is None:
        return False
    decorator = function.node.decorator_list[0]
    if not _valid_decoration_binding(function, fact, decorator):
        return False

    if any(
        not _supported_effect(proof, source_index, function, analysis, fact, effect, isolated)
        for effect in fact.get("effects", ())
    ):
        return False
    if not _source_snapshot_matches(function, fact):
        return False
    proof.note(
        function,
        "source_decorator_binding",
        "Original body/binding preserved on normal decoration completion; "
        + "; ".join(fact["assumptions"]),
        decorator,
    )
    return True


## Select the strongest source-backed decorator effect available.
## 选择当前可用的最强源码装饰器效果事实。
#
#  @param proof Proof ledger receiving established evidence
#  @param source_index Index used to resolve source definitions
#  @param function Function whose decorator is being checked
#  @param analysis Producer analysis for the function
#  @param summary Producer summary for the function
#  @param effect Decorator effect from the summary
#  @return Selected fact and whether it came from isolated analysis
def _decoration_fact(proof, source_index, function, analysis, summary, effect):
    fact = effect
    isolated = False
    if fact.get("body_binding_status") == "preserved":
        return fact, isolated
    fresh_fact = fresh_decoration_binding(source_index, analysis, function, summary)
    if fresh_fact is not None:
        return fresh_fact, True
    source_binding = source_callable_object_decorator_binding(analysis, function, effect)
    if source_binding is None:
        return None, False
    proof.note(
        function,
        "source_callable_object_decorator_preserves_function",
        "The source-bound callable-object decorator returns the original "
        "function and only changes its __doc__ metadata. "
        + "; ".join(source_binding["assumptions"]),
        function.node.decorator_list[0],
    )
    return True, False


## Validate that a decorator fact identifies this exact source binding.
## 校验装饰器事实是否指向当前精确的源码绑定。
#
#  @param function Function being checked
#  @param fact Candidate decorator fact
#  @param decorator Decorator expression from the function definition
#  @return True when the fact satisfies the source and completion contract
def _valid_decoration_binding(function, fact, decorator):
    expression = fact.get("expression", {})
    return not (
        identity_from_target(fact.get("function", {})) != function.identity
        or Path(expression.get("file_path", "")) != function.identity.file_path
        or any(
            expression.get(name) != getattr(decorator, name)
            for name in ("lineno", "col_offset", "end_lineno", "end_col_offset")
        )
        or fact.get("identity_status") != "preserved"
        or fact.get("body_binding_status") != "preserved"
        or fact.get("basis") != "source_snapshot"
        or fact.get("completion") != "normal_return"
        or fact.get("runtime_target_confirmed") is not False
        or fact.get("boundaries")
        or not fact.get("assumptions")
        or not fact.get("evidence")
        or not fact.get("target")
    )


## Check whether one reported decorator effect is within the supported model.
## 检查一项装饰器效果是否属于受支持的模型范围。
#
#  @param proof Proof ledger receiving established evidence
#  @param source_index Index used to resolve source definitions
#  @param function Decorated function
#  @param analysis Producer analysis for the function
#  @param fact Validated decorator fact
#  @param effect Effect record being checked
#  @param isolated Whether the fact came from isolated source analysis
#  @return True when the effect is supported
def _supported_effect(
    proof,
    source_index,
    function,
    analysis,
    fact,
    effect,
    isolated,
):
    kind = effect.get("operation"), effect.get("impact")
    target = effect.get("target")
    if target == "input_function":
        return _input_function_effect(fact, effect, kind)
    if isinstance(target, dict):
        return kind == ("helper_call", "analyzed_source")
    if target == "documentation_cache":
        return _documentation_cache_effect(fact, effect, kind, isolated)
    if target == "source_module":
        return (
            decorator_import_binding(
                source_index, analysis, function, fact, effect
            )
            is not None
        )
    if target == "decorator_instance":
        return _decorator_instance_effect(fact, effect, kind)
    if target in ("inspect.cleandoc", "textwrap.dedent"):
        return _stdlib_text_effect(fact, effect, kind)
    if target in ("str.split", "str.format", "str.endswith"):
        return _finite_text_method_effect(target, fact, effect, kind)
    if target == "str.__getitem__":
        return _text_slice_effect(effect, kind)
    if target == "len":
        return _string_length_effect(analysis, fact, effect, kind)
    if target in ("KeyError", "TypeError", "ValueError", "AttributeError"):
        return _exception_effect(proof, source_index, fact, effect, kind, analysis)
    if target == "str.join":
        return _join_effect(effect, kind)
    return False


## Validate an effect that reads from the decorated input function.
## 校验读取被装饰输入函数的一项效果。
#
#  @param fact Validated decorator fact
#  @param effect Effect record being checked
#  @param kind Effect operation and impact pair
#  @return True when the effect is supported
def _input_function_effect(fact, effect, kind):
    if kind == ("attribute_write", "module_metadata"):
        shapes = effect.get("value_shapes")
        return (
            effect.get("element_path") == ["__module__"]
            and effect.get("protocol") == "builtin_function_module_attribute"
            and isinstance(shapes, list)
            and bool(shapes)
            and all(shape in ("str", "NoneType") for shape in shapes)
            and effect.get("execution_fields_unchanged") is True
            and effect.get("runtime_write_confirmed") is False
            and "builtin_function_module_attribute" in fact["assumptions"]
        )
    return kind == ("attribute_write", "documentation") and effect.get("element_path") == [
        "__doc__"
    ]


## Validate a narrowly modeled documentation-cache effect.
## 校验受限建模的文档缓存效果。
#
#  @param fact Validated decorator fact
#  @param effect Effect record being checked
#  @param kind Effect operation and impact pair
#  @param isolated Whether the fact came from isolated source analysis
#  @return True when the effect is supported
def _documentation_cache_effect(fact, effect, kind, isolated):
    basic = kind in (
        ("construction", "data_only"),
        ("setdefault", "data_only"),
        ("mapping_lookup", "data_protocol"),
    )
    return basic or isolated and isolated_documentation_format(fact, effect)


## Validate an effect on the source-bound decorator instance.
## 校验作用于源码绑定装饰器实例的效果。
#
#  @param fact Validated decorator fact
#  @param effect Effect record being checked
#  @param kind Effect operation and impact pair
#  @return True when the effect is supported
def _decorator_instance_effect(fact, effect, kind):
    construction = fact.get("construction") or {}
    path = effect.get("element_path", ())
    scalar_shapes = {"str", "int", "bool", "float", "NoneType"}
    return (
        kind == ("attribute_write", "data_only")
        and construction.get("lifetime") == "single_decoration"
        and len(path) == 1
        and path[0].isidentifier()
        and not path[0].startswith("__")
        and bool(effect.get("before_shapes"))
        and set(effect["before_shapes"]) <= scalar_shapes
        and bool(effect.get("after_shapes"))
        and set(effect["after_shapes"]) <= scalar_shapes
        and not effect.get("conditions")
    )


## Validate a modeled standard-library text operation.
## 校验受模型支持的标准库文本操作。
#
#  @param fact Validated decorator fact
#  @param effect Effect record being checked
#  @param kind Effect operation and impact pair
#  @return True when the effect is supported
def _stdlib_text_effect(fact, effect, kind):
    return (
        kind == ("builtin_call", "data_only")
        and effect.get("protocol") == "stdlib_text_normalization"
        and effect.get("input_shapes") == [["str"]]
        and effect.get("output_shape") == "str"
        and effect.get("completion") == "normal_return"
        and "standard_library_text_protocols_hold" in fact["assumptions"]
    )


## Validate a text-method effect with finite source-derived inputs.
## 校验输入由源码有限确定的文本方法效果。
#
#  @param target Resolved source target of the text operation
#  @param fact Validated decorator fact
#  @param effect Effect record being checked
#  @param kind Effect operation and impact pair
#  @return True when the effect is supported
def _finite_text_method_effect(target, fact, effect, kind):
    shapes = effect.get("argument_shapes")
    if (
        kind != ("builtin_call", "data_only")
        or effect.get("protocol") != "finite_builtin_text"
        or effect.get("receiver_shape") != "str"
        or effect.get("completion") != "normal_return"
        or not isinstance(shapes, list)
        or any(shape != ["str"] for shape in shapes)
    ):
        return False
    if target == "str.split":
        return (
            shapes == [["str"]]
            and effect.get("output_shape") == "list_of_str"
            and effect.get("restriction") == "explicit_nonempty_separator"
        )
    if target == "str.format":
        return (
            effect.get("output_shape") == "str"
            and effect.get("restriction") == "no_attribute_or_item_fields"
        )
    return (
        shapes == [["str"]]
        and effect.get("output_shape") == "bool"
        and effect.get("restriction") == "literal_string_suffix"
    )


## Validate a bounded text-slicing effect.
## 校验有界文本切片效果。
#
#  @param effect Effect record being checked
#  @param kind Effect operation and impact pair
#  @return True when the effect is supported
def _text_slice_effect(effect, kind):
    bounds = effect.get("bounds")
    return (
        kind == ("builtin_call", "data_only")
        and effect.get("protocol") == "finite_builtin_text_slice"
        and effect.get("receiver_shape") == "str"
        and effect.get("output_shape") == "str"
        and effect.get("completion") == "normal_return"
        and isinstance(bounds, list)
        and len(bounds) == 3
        and all(type(value) in (int, type(None)) for value in bounds)
        and bounds[2] != 0
    )


## Validate a string-length effect using analyzed source values.
## 使用分析所得源码值校验字符串长度效果。
#
#  @param analysis Producer analysis for the decorated function
#  @param fact Validated decorator fact
#  @param effect Effect record being checked
#  @param kind Effect operation and impact pair
#  @return True when the effect is supported
def _string_length_effect(analysis, fact, effect, kind):
    required = {
        "standard_builtin_namespace_preserved",
        "no_unmodeled_indirect_builtin_mutation",
    }
    return (
        kind == ("builtin_call", "data_only")
        and effect.get("protocol") == "exact_builtin_string_length"
        and effect.get("input_shapes") == [["str"]]
        and effect.get("output_shape") == "int"
        and effect.get("completion") == "normal_return"
        and fact.get("source_hashes") == analysis.inputs.get("sha256")
        and required.issubset(fact["assumptions"])
    )


## Validate a supported exception effect from the decorator body.
## 校验装饰器函数体中受支持的异常效果。
#
#  @param proof Proof ledger receiving established evidence
#  @param source_index Index used to resolve source definitions
#  @param fact Validated decorator fact
#  @param effect Effect record being checked
#  @param kind Effect operation and impact pair
#  @param analysis Producer analysis for the function
#  @return True when the effect is supported
def _exception_effect(proof, source_index, fact, effect, kind, analysis):
    shapes = effect.get("argument_shapes")
    required = {
        "standard_builtin_namespace_preserved",
        "no_unmodeled_indirect_builtin_mutation",
    }
    return (
        kind == ("raise", "control_only")
        and effect.get("protocol") == "builtin_exception_raise"
        and effect.get("completion") == "exceptional_exit"
        and isinstance(shapes, list)
        and all(
            isinstance(shape, list)
            and bool(shape)
            and all(item in ("str", "int", "bool", "float", "NoneType") for item in shape)
            for shape in shapes
        )
        and fact.get("source_hashes") == analysis.inputs.get("sha256")
        and required.issubset(fact["assumptions"])
        and exception_raise_binding(source_index, fact, effect)
    )


## Validate the supported finite string-join effect.
## 校验受支持的有限字符串拼接效果。
#
#  @param effect Effect record being checked
#  @param kind Effect operation and impact pair
#  @return True when the effect is supported
def _join_effect(effect, kind):
    return (
        kind == ("builtin_call", "data_only")
        and effect.get("receiver_shape") == "str"
        and effect.get("sequence_shape") in ("list", "tuple")
        and "element_shapes" in effect
        and all(shape == ["str"] for shape in effect["element_shapes"])
    )


## Confirm that the decorator fact matches the current source bytes.
## 确认装饰器事实与当前源码字节一致。
#
#  @param function Function whose source snapshot is checked
#  @param fact Validated decorator fact
#  @return True when the source hash and identity still match
def _source_snapshot_matches(function, fact):
    hashes = fact.get("source_hashes", {})
    if str(function.identity.file_path) not in hashes:
        return False
    try:
        for path, digest in hashes.items():
            # Match the producer's decoded, universal-newline source snapshot.
            # 与生产者解码并统一换行后的源码快照匹配。
            with Path(path).open(encoding="utf-8-sig") as stream:
                actual = hashlib.sha256(stream.read().encode("utf-8")).hexdigest()
            if actual != digest:
                return False
    except (OSError, UnicodeError):
        return False
    return True
