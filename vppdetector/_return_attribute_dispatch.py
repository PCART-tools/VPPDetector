"""Resolve a source method call whose return selects typed owner attributes."""

from __future__ import annotations

import ast
import re
import tokenize

from ._program_facts import direct_calls, identity_from_target
from .models import FunctionIdentity
from .source import build_source_index


def _class_node(index, identity):
    path = identity.file_path
    if path is None:
        return None
    try:
        with tokenize.open(path) as stream:
            tree = ast.parse(stream.read(), filename=str(path))
    except (OSError, UnicodeError, SyntaxError):
        return None
    names = identity.qualname.split('.')
    scope = tree.body
    found = None
    for name in names:
        matches = [node for node in scope if isinstance(node, ast.ClassDef)
                   and node.name == name]
        if len(matches) != 1:
            return None
        found = matches[0]
        scope = found.body
    return found


def _type_doc(class_node, parameter):
    doc = ast.get_docstring(class_node) or ''
    pattern = re.compile(r'^\s*([A-Za-z_]\w*)\s*:\s*(\S.*)$')
    for line in doc.splitlines():
        match = pattern.match(line)
        if match and match.group(1) == parameter:
            value = match.group(2).strip().strip('`').lstrip('~')
            value = value.split(',', 1)[0].strip().split(' or ', 1)[0].strip('`~ ')
            if value and all(part.isidentifier() for part in value.split('.')):
                return value
            return None
    return None


def _field_parameter(class_node, field):
    assignments = []
    initializer = None
    for item in class_node.body:
        if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)) and item.name == '__init__':
            initializer = item
        if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for child in ast.walk(item):
                targets = (child.targets if isinstance(child, ast.Assign) else
                           [child.target] if isinstance(child, ast.AnnAssign) else [])
                for target in targets:
                    if (isinstance(target, ast.Attribute) and target.attr == field
                            and isinstance(target.value, ast.Name)
                            and target.value.id == 'self'):
                        assignments.append((item.name, child.value))
    if (initializer is None or len(assignments) != 1
            or assignments[0][0] != '__init__'
            or not isinstance(assignments[0][1], ast.Name)):
        return None
    parameter = assignments[0][1].id
    parameters = initializer.args.posonlyargs + initializer.args.args + initializer.args.kwonlyargs
    return parameter if any(item.arg == parameter for item in parameters) else None


def _class_hierarchy(index, identity, seen=()):
    if identity in seen or len(seen) > 16:
        return None
    node = _class_node(index, identity)
    if node is None:
        return None
    result = [(identity, node)]
    for base in node.bases:
        if not isinstance(base, (ast.Name, ast.Attribute)):
            return None
        parent = index.resolve_class(FunctionIdentity(identity.module, ast.unparse(base)))
        if parent is None:
            return None
        ancestors = _class_hierarchy(index, parent, seen + (identity,))
        if ancestors is None:
            return None
        result.extend(ancestors)
    return result


def _called_class(index, identity, expression):
    if not isinstance(expression, ast.Call):
        return None
    target = expression.func
    if isinstance(target, ast.Name):
        qualname = index.imports.get(identity.module, {}).get(target.id)
        if qualname is None:
            qualname = identity.module + '.' + target.id
    elif isinstance(target, ast.Attribute) and isinstance(target.value, ast.Name):
        module = index.imports.get(identity.module, {}).get(target.value.id)
        if module is None:
            return None
        qualname = module + '.' + target.attr
    else:
        return None
    module, _, class_name = qualname.rpartition('.')
    return index.resolve_class(FunctionIdentity(module, class_name))


def _field_class(index, owner_identity, field):
    hierarchy = _class_hierarchy(index, owner_identity)
    if not hierarchy:
        return None
    candidates = []
    for class_identity, class_node in hierarchy:
        for item in class_node.body:
            if not isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for child in ast.walk(item):
                targets = (child.targets if isinstance(child, ast.Assign) else
                           [child.target] if isinstance(child, ast.AnnAssign) else [])
                writes = [target for target in targets if isinstance(target, ast.Attribute)
                          and target.attr == field and isinstance(target.value, ast.Name)
                          and target.value.id == 'self']
                if not writes:
                    continue
                value = child.value
                candidate = _called_class(index, class_identity, value)
                if candidate is None or len(writes) != 1:
                    return None
                candidates.append(candidate)
    if candidates and all(item == candidates[0] for item in candidates):
        return candidates[0]
    return None


def _method_in_hierarchy(index, class_identity, name):
    hierarchy = _class_hierarchy(index, class_identity)
    if not hierarchy:
        return None
    implementations = [index.find(FunctionIdentity(
        identity.module, identity.qualname + '.' + name)) for identity, _ in hierarchy]
    selected = [item for item in implementations if item is not None]
    return selected[0] if selected else None


def returned_attribute_method(context, caller, analysis, call_node):
    """Follow one exact source-return attribute chain to a unique method body."""
    if (not isinstance(call_node.func, ast.Attribute)
            or not isinstance(call_node.func.value, ast.Call)
            or not isinstance(call_node.func.value.func, ast.Attribute)
            or not isinstance(call_node.func.value.func.value, ast.Name)
            or call_node.func.value.func.value.id != 'self'):
        return None
    helper_call = call_node.func.value
    helper_edge = next((edge for edge in direct_calls(analysis, caller.identity)
        if (edge.lineno, edge.col_offset, edge.end_lineno, edge.end_col_offset)
        == (helper_call.lineno, helper_call.col_offset,
            helper_call.end_lineno, helper_call.end_col_offset)), None)
    if helper_edge is None or helper_edge.target is None:
        return None
    helper = context.index.find(identity_from_target(helper_edge.target))
    if helper is None or helper.is_overload:
        return None
    owner_name, separator, _ = helper.identity.qualname.rpartition('.')
    if not separator:
        return None
    owner_identity = context.index.resolve_class(
        FunctionIdentity(helper.identity.module, owner_name))
    owner_node = _class_node(context.index, owner_identity) if owner_identity else None
    returned_fields = []
    for node in ast.walk(helper.node):
        if not isinstance(node, ast.Return) or not isinstance(node.value, ast.Attribute):
            continue
        expression = node.value
        if (isinstance(expression.value, ast.Attribute)
                and isinstance(expression.value.value, ast.Name)
                and expression.value.value.id == 'self'):
            returned_fields.append((expression.value.attr, expression.attr))
    if (owner_identity is None or owner_node is None or not returned_fields
            or any(field != returned_fields[0][0] for field, _ in returned_fields)):
        return None
    receiver_field = returned_fields[0][0]
    receiver_parameter = _field_parameter(owner_node, receiver_field)
    if receiver_parameter is None:
        return None
    documented_type = _type_doc(owner_node, receiver_parameter)
    if documented_type is None:
        return None
    type_module, _, type_name = documented_type.rpartition('.')
    if not type_module:
        return None
    type_identity = FunctionIdentity(type_module, type_name)
    index = context.index
    receiver_class = index.resolve_class(type_identity)
    if receiver_class is None:
        try:
            index = build_source_index(context.index.source, target_api=type_identity)
        except (OSError, ValueError, TypeError):
            return None
        receiver_class = index.resolve_class(type_identity)
        if receiver_class is None:
            matches = [identity for identity in index.classes
                       if identity.qualname == type_name
                       and identity.module.startswith(type_module + '.')]
            receiver_class = matches[0] if len(matches) == 1 else None
    if receiver_class is None:
        return None
    method_targets = []
    for _, field in returned_fields:
        field_class = _field_class(index, receiver_class, field)
        if field_class is None:
            return None
        target = _method_in_hierarchy(index, field_class, call_node.func.attr)
        if target is None or target.is_overload:
            return None
        method_targets.append(target.identity)
    return method_targets[0] if all(item == method_targets[0] for item in method_targets) else None
