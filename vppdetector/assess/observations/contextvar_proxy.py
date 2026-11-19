## @package vppdetector.assess.observations.contextvar_proxy
#  Prove the behavior of an unbound ContextVar proxy from source.
#
#
#  Check the proxy boolean method, descriptor fallback and installed getter before treating an
#  unbound proxy as false.
#  在将未绑定代理视为假值之前校验代理布尔方法、描述符回退和已安装的读取器。



import ast

from .contextvar_support import (
    _has_execution_exit,
    _module_binding_count,
    _module_imports,
    _module_tree,
    _source_member_fact,
    _stable_source_member,
)


## Resolve the bool descriptor that stores a source literal false fallback.
## 解析保存了源码字面量 False 回退函数的布尔描述符。
#
#  @param context Analysis context used to validate descriptor members
#  @param proxy_module Module defining the proxy and descriptor
#  @param proxy_path Source path of that module
#  @param proxy_tree Parsed module syntax
#  @param descriptor Descriptor construction in the bool member assignment
#  @return Descriptor name and stable initializer and getter facts, or None
def _false_fallback_descriptor(context, proxy_module, proxy_path, proxy_tree, descriptor):
    descriptor_name = descriptor.func.id if isinstance(descriptor.func, ast.Name) else None
    if descriptor_name is None:
        return None
    descriptor_classes = [
        item
        for item in ast.walk(proxy_tree)
        if isinstance(item, ast.ClassDef) and item.name == descriptor_name
    ]
    descriptor_class = descriptor_classes[0] if len(descriptor_classes) == 1 else None
    if descriptor_class is None or descriptor_class.keywords:
        return None
    descriptor_init_fact = _stable_source_member(
        context, proxy_module, descriptor_name, "__init__", proxy_path
    )
    descriptor_get_fact = _stable_source_member(
        context, proxy_module, descriptor_name, "__get__", proxy_path
    )
    if not descriptor_init_fact or not descriptor_get_fact:
        return None
    fallback = next((item.value for item in descriptor.keywords if item.arg == "fallback"), None)
    if (
        not descriptor.args
        or not isinstance(descriptor.args[0], ast.Name)
        or descriptor.args[0].id != "bool"
        or not isinstance(fallback, ast.Lambda)
        or not isinstance(fallback.body, ast.Constant)
        or fallback.body.value is not False
    ):
        return None

    # The descriptor must store its false fallback where the getter can actually read it.
    # 描述符必须将返回假值的回退函数保存在读取器实际访问的位置。
    init_methods = [
        item
        for item in descriptor_class.body
        if isinstance(item, ast.FunctionDef) and item.name == "__init__"
    ]
    if (
        len(init_methods) != 1
        or init_methods[0].decorator_list
        or _has_execution_exit(init_methods[0].body)
    ):
        return None
    fallback_writes = [
        item
        for item in ast.walk(init_methods[0])
        if isinstance(item, (ast.Assign, ast.AnnAssign))
        and any(
            isinstance(target, ast.Attribute)
            and target.attr == "fallback"
            and isinstance(target.value, ast.Name)
            and target.value.id == "self"
            for target in (item.targets if isinstance(item, ast.Assign) else [item.target])
        )
    ]
    if (
        len(fallback_writes) != 1
        or not isinstance(fallback_writes[0].value, ast.Name)
        or fallback_writes[0].value.id != "fallback"
    ):
        return None
    return descriptor_name, descriptor_init_fact, descriptor_get_fact


## Validate the descriptor's RuntimeError path from lookup to fallback.
## 校验描述符从对象查找到回退函数的 RuntimeError 路径。
#
#  @param adapter Producer adapter providing the exception fact
#  @param proxy_module Module defining the descriptor
#  @param proxy_path Source path of the descriptor module
#  @param descriptor_name Descriptor class whose __get__ is checked
#  @return Validated exception fallback fact, or None if the path is unproven
def _descriptor_exception_fallback(adapter, proxy_module, proxy_path, descriptor_name):
    fallback_fact = adapter.source_method_exception_fallback(
        proxy_module, descriptor_name, "__get__", proxy_path, "RuntimeError"
    )
    instance_name = (
        fallback_fact.get("receiver_parameter") if isinstance(fallback_fact, dict) else None
    )
    lookup_method_name = (
        fallback_fact.get("lookup_member") if isinstance(fallback_fact, dict) else None
    )
    expected_protected_call = (
        ast.dump(
            ast.parse(f"{instance_name}._get_current_object()", mode="eval").body,
            include_attributes=False,
        )
        if instance_name
        else None
    )
    expected_fallback = (
        ast.dump(
            ast.parse(f"self.fallback({instance_name})", mode="eval").body, include_attributes=False
        )
        if instance_name
        else None
    )
    expected_bound_fallback = (
        ast.dump(
            ast.parse(f"self.fallback.__get__({instance_name}, owner)", mode="eval").body,
            include_attributes=False,
        )
        if instance_name
        else None
    )
    if (
        not isinstance(fallback_fact, dict)
        or fallback_fact.get("class", {}).get("module") != proxy_module
        or fallback_fact.get("class", {}).get("qualname") != descriptor_name
        or fallback_fact.get("protected_call") != expected_protected_call
        or not isinstance(fallback_fact.get("protected_span"), dict)
        or fallback_fact.get("fallback_expression")
        not in (expected_fallback, expected_bound_fallback)
    ):
        return None
    if not isinstance(instance_name, str) or not isinstance(lookup_method_name, str):
        return None
    return fallback_fact


## Check that the ContextVar getter translates the unbound read and is installed once.
## 检查 ContextVar getter 是否转换未绑定读取的异常并且仅被安装一次。
#
#  @param proxy_init Proxy initializer containing the assignment
#  @param branch ContextVar dispatch branch
#  @param getter Local function selected from that branch
#  @param local_name Initializer parameter holding the ContextVar
#  @param lookup_method_name Member reached by the descriptor lookup
#  @return None for unsupported try shape, otherwise whether the installed getter is proven
def _installed_contextvar_getter(proxy_init, branch, getter, local_name, lookup_method_name):
    getter_tries = [item for item in getter.body if isinstance(item, ast.Try)]
    if len(getter_tries) != 1 or len(getter_tries[0].handlers) != 1:
        return None
    getter_try = getter_tries[0]
    handler = getter_try.handlers[0]
    read = (
        getter_try.body[0].value
        if len(getter_try.body) == 1
        and isinstance(getter_try.body[0], ast.Assign)
        and len(getter_try.body[0].targets) == 1
        and isinstance(getter_try.body[0].targets[0], ast.Name)
        else None
    )
    has_normal_return = len(getter.body) == 2 and isinstance(getter.body[1], ast.Return)
    read_is_context_get = (
        isinstance(read, ast.Call)
        and isinstance(read.func, ast.Attribute)
        and read.func.attr == "get"
        and isinstance(read.func.value, ast.Name)
        and read.func.value.id == local_name
        and not read.args
        and not read.keywords
        and not getter_try.orelse
        and not getter_try.finalbody
    )
    translated = (
        isinstance(handler.type, ast.Name)
        and handler.type.id == "LookupError"
        and len(handler.body) == 1
        and isinstance(handler.body[0], ast.Raise)
        and isinstance(handler.body[0].exc, ast.Call)
        and isinstance(handler.body[0].exc.func, ast.Name)
        and handler.body[0].exc.func.id == "RuntimeError"
    )
    assigned_getter = any(
        isinstance(item, ast.Call)
        and isinstance(item.func, ast.Attribute)
        and item.func.attr in ("setattr", "__setattr__")
        and len(item.args) >= 3
        and isinstance(item.args[0], ast.Name)
        and item.args[0].id == "self"
        and isinstance(item.args[1], ast.Constant)
        and item.args[1].value == lookup_method_name
        and isinstance(item.args[2], ast.Name)
        and item.args[2].id == getter.name
        for item in ast.walk(proxy_init)
    ) or any(
        isinstance(item, ast.Assign)
        and any(
            isinstance(target, ast.Attribute)
            and target.attr == lookup_method_name
            and isinstance(target.value, ast.Name)
            and target.value.id == "self"
            for target in item.targets
        )
        and isinstance(item.value, ast.Name)
        and item.value.id == getter.name
        for item in ast.walk(proxy_init)
    )

    # Check getter writes separately to rule out replacement of the selected getter.
    # 单独检查读取器的赋值，排除选定读取器被其他写入替换的情况。
    getter_writes = [
        item
        for item in ast.walk(proxy_init)
        if (
            isinstance(item, ast.Assign)
            and any(
                isinstance(target, ast.Attribute)
                and target.attr == lookup_method_name
                and isinstance(target.value, ast.Name)
                and target.value.id == "self"
                for target in item.targets
            )
        )
        or (
            isinstance(item, ast.Call)
            and isinstance(item.func, ast.Attribute)
            and item.func.attr in ("setattr", "__setattr__")
            and len(item.args) >= 2
            and isinstance(item.args[0], ast.Name)
            and item.args[0].id == "self"
            and isinstance(item.args[1], ast.Constant)
            and item.args[1].value == lookup_method_name
        )
    ]
    return (
        read_is_context_get
        and has_normal_return
        and translated
        and assigned_getter
        and len(getter_writes) == 1
        and getter in ast.walk(branch)
    )


## Prove that the proxy evaluates to false when its ContextVar is unbound.
## 证明代理在 ContextVar 未绑定时的布尔值为 False。
#
#  @param context Analysis context providing source and producer facts
#  @param proxy_module Module containing the proxy
#  @param proxy_class Identity selecting the proxy class by name and line
#  @return Ordered proof fields on success, False or None when unproven
def _proxy_bool_is_unbound_false(context, proxy_module, proxy_class):
    proxy_path, proxy_tree = _module_tree(context, proxy_module)
    if proxy_path is None or proxy_tree is None:
        return False
    classes = [
        item
        for item in ast.walk(proxy_tree)
        if isinstance(item, ast.ClassDef)
        and item.lineno == proxy_class.lineno
        and item.name == proxy_class.qualname
    ]
    if len(classes) != 1 or classes[0].keywords:
        return False
    class_node = classes[0]
    proxy_init_fact = _stable_source_member(
        context, proxy_module, proxy_class.qualname, "__init__", proxy_path
    )
    bool_fact = _source_member_fact(
        context, proxy_module, proxy_class.qualname, "__bool__", proxy_path
    )
    if (
        not proxy_init_fact
        or not isinstance(bool_fact, dict)
        or bool_fact.get("status") != "stable"
        or bool_fact.get("member_kind") != "assignment"
        or not isinstance(bool_fact.get("member_expression"), str)
        or not bool_fact.get("source_hashes")
    ):
        return False
    try:
        bool_value = ast.parse(bool_fact["member_expression"], mode="eval").body
    except SyntaxError:
        return False
    if not isinstance(bool_value, ast.Call):
        return False
    imports = _module_imports(context, proxy_module, proxy_path, proxy_tree)
    if any(
        _module_binding_count(proxy_tree, name) != 0
        for name in ("bool", "isinstance", "LookupError", "RuntimeError", "object")
    ):
        return False
    descriptor = _false_fallback_descriptor(
        context, proxy_module, proxy_path, proxy_tree, bool_value
    )
    if descriptor is None:
        return False
    descriptor_name, descriptor_init_fact, descriptor_get_fact = descriptor
    fallback_fact = _descriptor_exception_fallback(
        context.adapter, proxy_module, proxy_path, descriptor_name
    )
    if fallback_fact is None:
        return False

    # The descriptor lookup must name the same member that the initializer installs.
    # 描述符查找的成员必须与初始化器安装的成员一致。
    proxy_init = next(
        (
            item
            for item in class_node.body
            if isinstance(item, ast.FunctionDef) and item.name == "__init__"
        ),
        None,
    )
    if proxy_init is None:
        return False
    contextvar_aliases = {
        name for name, target in imports.items() if target == "contextvars.ContextVar"
    }
    if (
        len(contextvar_aliases) != 1
        or _module_binding_count(proxy_tree, next(iter(contextvar_aliases))) != 1
    ):
        return False
    local_name = proxy_init.args.args[1].arg if len(proxy_init.args.args) > 1 else None
    if local_name is None:
        return False
    contextvar_branches = [
        branch
        for branch in ast.walk(proxy_init)
        if isinstance(branch, ast.If)
        and isinstance(branch.test, ast.Call)
        and isinstance(branch.test.func, ast.Name)
        and branch.test.func.id == "isinstance"
        and len(branch.test.args) == 2
        and isinstance(branch.test.args[0], ast.Name)
        and branch.test.args[0].id == local_name
        and isinstance(branch.test.args[1], ast.Name)
        and branch.test.args[1].id in contextvar_aliases
    ]
    if len(contextvar_branches) != 1:
        return False
    branch = contextvar_branches[0]
    dispatch_index = next(
        (
            index
            for index, statement in enumerate(proxy_init.body)
            if any(item is branch for item in ast.walk(statement))
        ),
        None,
    )
    getters = [item for item in branch.body if isinstance(item, ast.FunctionDef)]
    if (
        dispatch_index is None
        or any(_has_execution_exit([statement]) for statement in proxy_init.body[:dispatch_index])
        or len(getters) != 1
        or _has_execution_exit(branch.body)
    ):
        return False
    getter_proof = _installed_contextvar_getter(
        proxy_init, branch, getters[0], local_name, fallback_fact["lookup_member"]
    )
    if getter_proof is None:
        return False
    if getter_proof:
        return {
            "bool_member": bool_fact,
            "proxy_init_member": proxy_init_fact,
            "descriptor_init_member": descriptor_init_fact,
            "descriptor_get_member": descriptor_get_fact,
            "descriptor_fallback": fallback_fact,
        }
    return None
