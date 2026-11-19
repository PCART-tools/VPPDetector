## @package vppdetector.assess.fresh
#  Resolve source-backed fresh-receiver member lookups.
#
#
#  Check the class hierarchy and attribute effects before selecting a method or member on a newly
#  constructed receiver.
#  在选择新建接收者的方法或成员前校验类层次和属性效果。



import ast

from .._records import FrozenRecord
from ..facts.calls import identity_from_target
from .proofs._fresh_receiver import method_binding as fresh_method_binding
from .values import _allocation_effects, _ReceiverClassEvidence, _ReceiverOwner


## Apply Python's private-member name mangling for one class.
## 按 Python 的私有成员规则转换类成员名称。
#
#  @param class_qualname Qualified name of the class containing the member
#  @param member_name Member name as written in source
#  @return Runtime member name after name mangling when applicable
def _python_member_name(class_qualname, member_name):
    class_name = class_qualname.rsplit(".", 1)[-1].lstrip("_")
    if class_name and member_name.startswith("__") and not member_name.endswith("__"):
        return "_" + class_name + member_name
    return member_name


## Convert producer hierarchy entries into the names used for member lookup.
## 将生产者层次记录转换为成员查找所需的名称。
#
#  @param hierarchy Producer entries or already converted receiver owners
#  @return Validated owners, or an empty tuple when the hierarchy is unproven
def _receiver_hierarchy(hierarchy):
    if not isinstance(hierarchy, (list, tuple)) or not hierarchy:
        return ()
    owners = []
    for owner in hierarchy:
        if (
            isinstance(owner, _ReceiverOwner)
            and isinstance(owner.module, str)
            and isinstance(owner.qualname, str)
        ):
            owners.append(owner)
        elif (
            isinstance(owner, dict)
            and isinstance(owner.get("module"), str)
            and isinstance(owner.get("qualname"), str)
        ):
            owners.append(_ReceiverOwner(owner["module"], owner["qualname"]))
        else:
            return ()
    return tuple(owners)


## Keep the verified fresh-receiver facts together across nested calls.
## 在嵌套调用间集中传递已验证的新接收者事实。
class FreshReceiverState(FrozenRecord):
    _record_fields = (
        "fresh",
        "exclusions",
        "own_attributes",
        "receiver_class",
        "hierarchy",
        "allocation",
    )
    __match_args__ = _record_fields

    ## Store the source-backed receiver facts used by nested interpretation
    ## 保存嵌套解释过程使用的源码接收者事实
    #
    #  @param fresh Whether a fresh receiver origin is established
    #  @param exclusions Attributes excluded from fresh-member propagation
    #  @param own_attributes Attributes known to exist on the instance
    #  @param receiver_class Validated class evidence for member lookup
    #  @param hierarchy Validated owners searched during member lookup
    #  @param allocation Isolated allocation effects for this receiver
    def __init__(
        self,
        fresh=False,
        exclusions=frozenset(),
        own_attributes=frozenset(),
        receiver_class=None,
        hierarchy=(),
        allocation=None,
    ):
        object.__setattr__(self, "fresh", fresh)
        object.__setattr__(self, "exclusions", exclusions)
        object.__setattr__(self, "own_attributes", own_attributes)
        object.__setattr__(self, "receiver_class", receiver_class)
        object.__setattr__(self, "hierarchy", hierarchy)
        object.__setattr__(self, "allocation", allocation)


NO_FRESH_RECEIVER = FreshReceiverState()


## Represent a resolved fresh receiver method and its binding context.
## 表示新接收者上已解析的方法及其绑定上下文。
class FreshMethod(FrozenRecord):
    _record_fields = ("target", "receiver")
    __match_args__ = _record_fields

    ## Pair one resolved method target with its receiver facts
    ## 将已解析的方法目标与其接收者事实组合保存
    #
    #  @param target Indexed source identity of the method
    #  @param receiver Verified receiver state required for method execution
    def __init__(self, target, receiver):
        object.__setattr__(self, "target", target)
        object.__setattr__(self, "receiver", receiver)


## Represent a proven missing member or an unsupported member kind.
## 表示已证明不存在的成员或不支持的成员类型。
class FreshNonMethod(FrozenRecord):
    _record_fields = ("kind",)
    __match_args__ = _record_fields

    ## Record why a fresh-receiver lookup is not a method binding.
    ## 记录新接收者成员查找为何不是方法绑定。
    #
    #  @param kind Missing or unsupported member category
    def __init__(self, kind):
        object.__setattr__(self, "kind", kind)


## Resolve members on source-backed fresh receivers.
## 解析具有源码依据的新建接收者成员。
class FreshReceiverOperations:
    ## Resolve one member on the validated fresh receiver.
    ## 在已校验的新接收者上解析一个成员。
    #
    #  @param method_name Source member name to resolve
    #  @return Resolved method or a conservative non-method result
    def fresh_lookup(self, method_name):
        analysis = self.analysis
        if analysis is None:
            return None
        positional = self.function.node.args.posonlyargs + self.function.node.args.args
        if (
            not self.function.is_bound_method
            or not positional
            or positional[0].arg != "self"
            or not isinstance(method_name, str)
            or method_name.startswith("__")
        ):
            return None

        # Call-site incoming facts are not lookup facts for arbitrary attributes;
        # obtain the receiver class from a source-bound call into this method.
        # 调用点输入事实不能证明任意属性查找；接收者类型必须来自源码绑定到该方法的调用。
        incoming = [
            edge
            for edge in analysis.calls
            if edge.target is not None
            and identity_from_target(edge.target) == self.function.identity
            and bool(getattr(edge, "instance_method_bindings", ()))
        ]
        if len(incoming) == 1:
            binding = fresh_method_binding(analysis, incoming[0], self.context.index)
            if binding is None:
                return None
            receiver_class = binding.receiver_class
            own_attributes = set(binding.own_attributes)
            hierarchy = _receiver_hierarchy(
                analysis.inputs.get("entry_binding", {}).get("hierarchy", ())
            )
            allocation = binding.allocation_effects
        elif self.receiver.fresh:
            # A nested method frame can have no incoming edge in its own
            # PCResolve summary. Carry the exact own-attribute set from the
            # source-bound method descriptor that created this fresh frame.
            # 嵌套方法帧在自身 PCResolve 摘要中可能没有入边；
            # 因此从源码绑定方法描述符传入精确的自有属性集合。
            receiver_class = self.receiver.receiver_class
            hierarchy = self.receiver.hierarchy
            allocation = self.receiver.allocation or {}
            if not isinstance(receiver_class, _ReceiverClassEvidence) or not hierarchy:
                return None
            own_attributes = set(self.receiver.own_attributes)
        else:
            return None
        if not isinstance(receiver_class, _ReceiverClassEvidence):
            return None
        checked_receiver_class = receiver_class
        if not hierarchy:
            return None

        effects = _allocation_effects(allocation)
        if effects is None:
            return None
        if effects.lookup_error is not None:
            error_type, arguments = effects.lookup_error
            raise error_type(*arguments)

        # Look up declarations in the producer-proven hierarchy, then apply allocation-time effects.
        # 在生产者已证明的类层次中查找声明，再应用分配阶段的效果。
        found = []
        by_name = {}
        for owner in hierarchy:
            module, qualname = owner.module, owner.qualname
            prefix = qualname + "."
            owner_functions = [
                item
                for item in self.context.index.functions
                if item.identity.module == module
                and item.identity.qualname.startswith(prefix)
                and "." not in item.identity.qualname[len(prefix) :]
            ]
            found.extend(owner_functions)
            owner_name = qualname.rsplit(".", 1)[-1]
            for item in owner_functions:
                member_name = item.identity.qualname.rsplit(".", 1)[-1]
                by_name.setdefault(_python_member_name(owner_name, member_name), []).append(item)

        decorated_members = effects.decorated_members
        alias_targets = dict(effects.aliases)
        if method_name in own_attributes:
            return FreshNonMethod("instance_attribute")
        if method_name in decorated_members:
            target_name = alias_targets.get(method_name)
            if not isinstance(target_name, str):
                return FreshNonMethod("unknown_member")
            aliases = [
                item for item in found if item.identity.qualname.rsplit(".", 1)[-1] == target_name
            ]
            if len(aliases) != 1 or aliases[0].node.decorator_list:
                return FreshNonMethod("unknown_member")
            receiver = FreshReceiverState(
                True, frozenset(decorated_members), frozenset(own_attributes),
                checked_receiver_class, hierarchy, effects
            )
            return FreshMethod(aliases[0].identity, receiver)

        candidates = by_name.get(method_name, ())
        if not candidates:
            if method_name in alias_targets:
                aliases = [
                    item
                    for item in found
                    if item.identity.qualname.rsplit(".", 1)[-1] == alias_targets[method_name]
                ]
                if len(aliases) != 1 or aliases[0].node.decorator_list:
                    return None
                receiver = FreshReceiverState(
                    True, frozenset(decorated_members), frozenset(own_attributes),
                    checked_receiver_class, hierarchy, effects
                )
                return FreshMethod(aliases[0].identity, receiver)
            if method_name in decorated_members:
                return FreshNonMethod("unknown_member")
            return FreshNonMethod("missing")
        if len(candidates) != 1 or not isinstance(candidates[0].node, ast.FunctionDef):
            return None
        target = candidates[0]
        if target.node.decorator_list:
            # Decorated/descriptor results need their own binding proof.
            # 装饰器或描述符产生的结果必须单独证明绑定关系。
            if effects.forwarding_error is not None:
                error_type, arguments = effects.forwarding_error
                raise error_type(*arguments)
            alias_target_names = [
                target
                for attribute, target in effects.forwarding_aliases
                if attribute == method_name
            ]
            if len(alias_target_names) != 1:
                return None
            matches = [
                item
                for item in found
                if item.identity.qualname.rsplit(".", 1)[-1] == alias_target_names[0]
            ]
            if len(matches) != 1 or matches[0].node.decorator_list:
                return None
            target = matches[0]
        receiver = FreshReceiverState(
            True, frozenset(decorated_members), frozenset(own_attributes),
            checked_receiver_class, hierarchy, effects
        )
        return FreshMethod(target.identity, receiver)
