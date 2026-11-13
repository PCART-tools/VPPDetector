## @package vppdetector._wrapper_forwarding
#  Validate call-conditioned forwarding through source wrappers.
#  校验经过源码包装函数的调用条件转发。

import ast

from ._fresh_decoration import observation_guard
from ._program_facts import identity_from_target, source_constructor_entry_binding
from .models import FunctionIdentity


_FIELDS = ("lineno", "col_offset", "end_lineno", "end_col_offset")
_ASSUMPTIONS = {
    "source_snapshot_bindings_hold",
    "source_native_function_wrapper_creation",
    "standard_library_signature_metadata_protocol",
    "standard_library_partial_protocol",
    "standard_library_default_wraps_metadata_protocol",
    "standard_builtin_namespace_preserved",
    "no_unmodeled_indirect_builtin_mutation",
    "source_registry_native_function_keys_only",
    "no_external_registry_mutation",
    "no_unmodeled_indirect_function_mutation",
}


## Check whether a source helper has a normal path without an explicit raise
## 检查源码辅助函数是否存在不含显式抛出的正常路径
#
#  @param statements Statements in a source function body
#  @return Result of the `normal_completion` check
def _normal_completion(statements):
    for statement in statements:
        if isinstance(statement, ast.Raise):
            return False
        if isinstance(statement, ast.Return):
            return True
        if isinstance(statement, ast.If):
            if not _normal_completion(statement.body) and not _normal_completion(statement.orelse):
                return False
    return True


## Validate a source guard helper before following the wrapped call
## 跟随包装调用前校验源码保护分支的辅助函数
#
#  @param context Reusable analysis context for the selected source snapshot
#  @param factory_identity Source identity of the wrapper factory
#  @param guard Guard statement executed before forwarding
#  @return Result of the `guard_helper` validation
def _guard_helper_can_complete(context, factory_identity, guard):
    if (not isinstance(guard, ast.If) or len(guard.body) != 1
            or not isinstance(guard.body[0], ast.Expr)
            or not isinstance(guard.body[0].value, ast.Call)):
        return False
    callee = guard.body[0].value.func
    if not isinstance(callee, (ast.Name, ast.Attribute)):
        return False
    requested = FunctionIdentity(factory_identity.module, ast.unparse(callee))
    helper = context.index.find(requested) or context.index.resolve_imported(requested)
    return bool(helper and not any(isinstance(node, ast.Raise)
                                   for node in ast.walk(helper.node))
                and _normal_completion(helper.node.body))


## Return a forwarding fact only for its supported actual positional count
## 仅在实际位置参数数量符合支持条件时返回转发事实
#
#  @param context Reusable analysis context for the selected source snapshot
#  @param analysis PCResolve analysis result being validated or consumed
#  @param function Indexed source function under analysis
#  @param positional_count Number of positional arguments supplied
#  @return Validated forwarding fact, or None if the proof is incomplete
def binding(context, analysis, function, positional_count):
    if type(positional_count) is not int or positional_count < 0:
        return None
    summaries = [
        item
        for item in analysis.functions
        if identity_from_target(item.get("function")) == function.identity
    ]
    if len(summaries) != 1:
        return None
    records = summaries[0].get("source_wrapper_forwarding")
    identity_factory_chain = False
    if not records and function.query_class is not None:
        entry = source_constructor_entry_binding(analysis, function.query_class)
        if (entry is not None
                and identity_from_target(entry.get('target')) == function.identity
                and 'source_callable_object_identity_decorator' in entry.get('assumptions', ())
                and 'source_identity_decorator_over_source_factory_wrapper'
                    in entry.get('assumptions', ())):
            wrapper = entry.get('constructor_wrapper_forwarding')
            records = [wrapper] if isinstance(wrapper, dict) else ()
            identity_factory_chain = bool(records)
    if (
        not isinstance(records, (list, tuple))
        or len(records) != 1
        or not isinstance(records[0], dict)
    ):
        return None
    fact = records[0]
    decorators = function.node.decorator_list
    if len(decorators) == 1:
        factory_decorator = decorators[0]
    elif len(decorators) == 2 and identity_factory_chain:
        factory_decorator = decorators[-1]
    else:
        factory_decorator = None
    forwarding, claims = fact.get("forwarding"), fact.get("assumptions")
    if (
        fact.get("kind") != "source_function_factory_wrapper_creation"
        or fact.get("status") != "source_bound"
        or fact.get("result_kind") != "native_function"
        or fact.get("identity_status") != "replaced"
        or fact.get("body_binding_status") != "unmodeled"
        or fact.get("completion") != "normal_return_only"
        or fact.get("runtime_factory_executed") is not False
        or identity_from_target(fact.get("function")) != function.identity
        or not isinstance(forwarding, dict)
        or forwarding.get("kind") != "source_wrapper_argument_forwarding"
        or identity_from_target(forwarding.get("forwarded_function")) != function.identity
        or forwarding.get("argument_scope") != "same_args_and_kwargs"
        or forwarding.get("other_paths") != "forwarded_on_normal_return"
        or forwarding.get("normal_return_paths")
        != "all_explicit_returns_forward_original_args_kwargs"
        or not isinstance(claims, (list, tuple))
        or any(not isinstance(value, str) for value in claims)
        or not _ASSUMPTIONS.issubset(claims)
        or observation_guard(context, analysis, fact) is None
        or factory_decorator is None
    ):
        return None
    maximum = forwarding.get("maximum_positional_count")
    if maximum is not None and (type(maximum) is not int or maximum < 0):
        return None

    ## Validate the producer witness required by the enclosing proof
    ## 校验所属证明所需的生产者见证
    #
    #  @param value Producer source witness record to validate
    #  @param identity Source-level identity used for lookup
    #  @param node AST node whose coordinates are compared
    #  @return Whether the witness matches the source identity and node
    def witness(value, identity, node):
        return (
            isinstance(value, dict)
            and value.get("file_path") == str(identity.file_path)
            and all(
                type(value.get(field)) is int and value[field] == getattr(node, field)
                for field in _FIELDS
            )
        )

    if not witness(
        fact.get("factory_evidence"), function.identity, factory_decorator
    ):
        return None

    factory_identity = identity_from_target(fact.get("factory"))
    factory = context.index.find(factory_identity) if factory_identity is not None else None
    if factory is None:
        return None

    wrappers = [
        node
        for node in factory.node.body
        if isinstance(node, ast.FunctionDef)
        and witness(fact.get("wrapper_evidence"), factory_identity, node)
    ]
    if len(wrappers) != 1:
        return None
    wrapper = wrappers[0]
    args, body = wrapper.args, wrapper.body
    if (
        args.posonlyargs
        or args.args
        or args.kwonlyargs
        or not args.vararg
        or not args.kwarg
        or len(wrapper.decorator_list) != 1
    ):
        return None

    if maximum is not None:
        if len(body) != 2 or not isinstance(body[0], ast.If) or body[0].orelse:
            return None
        test = body[0].test
        if (
            not isinstance(test, ast.Compare)
            or len(test.ops) != 1
            or not isinstance(test.ops[0], ast.Gt)
            or not isinstance(test.left, ast.Call)
            or not isinstance(test.left.func, ast.Name)
            or test.left.func.id != "len"
            or test.left.keywords
            or len(test.left.args) != 1
            or not isinstance(test.left.args[0], ast.Name)
            or test.left.args[0].id != args.vararg.arg
            or not isinstance(test.comparators[0], ast.Name)
        ):
            return None
        if positional_count > maximum and not _guard_helper_can_complete(
                context, factory_identity, body[0]):
            return None
        body = body[1:]
    if (
        len(body) != 1
        or not isinstance(body[0], ast.Return)
        or not isinstance(body[0].value, ast.Call)
    ):
        return None

    call = body[0].value
    if (
        not witness(forwarding.get("call_evidence"), factory_identity, call)
        or not isinstance(call.func, ast.Name)
        or call.func.id in (args.vararg.arg, args.kwarg.arg)
        or len(call.args) != 1
        or not isinstance(call.args[0], ast.Starred)
        or not isinstance(call.args[0].value, ast.Name)
        or call.args[0].value.id != args.vararg.arg
        or len(call.keywords) != 1
        or call.keywords[0].arg is not None
        or not isinstance(call.keywords[0].value, ast.Name)
        or call.keywords[0].value.id != args.kwarg.arg
    ):
        return None

    metadata = fact.get("metadata_wrappers")
    if (
        not isinstance(metadata, (list, tuple))
        or len(metadata) != 1
        or not isinstance(metadata[0], dict)
    ):
        return None
    record = metadata[0]
    if (
        record.get("kind") != "standard_fresh_function_metadata_wrapper"
        or record.get("status") != "source_bound"
        or record.get("wrapped_kind") != "fresh_source_function"
        or record.get("wrapper_kind") != "fresh_source_function"
        or record.get("completion") != "normal_return_only"
        or record.get("future_method_effects") != "unmodeled"
        or not witness(
            record.get("decorator_evidence"), factory_identity, wrapper.decorator_list[0]
        )
        or not isinstance(record.get("source_hashes"), dict)
        or not record["source_hashes"]
        or any(
            fact["source_hashes"].get(path) != digest
            for path, digest in record["source_hashes"].items()
        )
        or not isinstance(record.get("assumptions"), (list, tuple))
        or any(not isinstance(value, str) for value in record["assumptions"])
        or not set(record["assumptions"]).issubset(claims)
    ):
        return None
    return fact
