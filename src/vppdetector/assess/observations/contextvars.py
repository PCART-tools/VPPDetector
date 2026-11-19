## @package vppdetector.assess.observations.contextvars
#  Derive caller-specific conditions from ContextVar observations.
#
#
#  Validate callsite inputs and derive condition overrides from source-backed unbound ContextVar
#  evidence.
#  校验调用点输入，并根据源码支持的未绑定 ContextVar 证据推导条件覆盖值。



import ast
import hashlib
from pathlib import Path

from ...models import FunctionIdentity, SourceSpan
from .contextvar_packages import _package_sets_contextvar
from .contextvar_proxy import _proxy_bool_is_unbound_false
from .contextvar_support import (
    _assignment,
    _assignment_statement,
    _module_binding_count,
    _module_imports,
    _module_tree,
    _raw_source_hashes_match,
)

_FIELDS = ("lineno", "col_offset", "end_lineno", "end_col_offset")


## Validate source-bound caller inputs and their current source contents.
## 校验已绑定源码的调用方输入及其当前源码内容。
#
#  @param context Analysis context owning producer facts
#  @param call Caller invocation with its source location
#  @param node Call AST node represented by the producer fact
#  @return Validated fact, expected callsite data and source hashes, or None
def _validated_callsite_inputs(context, call, node):
    if call.callsite is None:
        return None
    fact = context.adapter.caller_inputs(call.callsite)
    if (not isinstance(fact, dict)
            or fact.get('kind') != 'source_callsite_inputs'
            or fact.get('schema_version') != 'caller-inputs-0.1'
            or fact.get('status') != 'source_bound'
            or fact.get('scope') != 'argument_reads_on_normal_module_prefix'
            or fact.get('runtime_values_observed') is not False):
        return None
    assumptions = fact.get('assumptions')
    if (not isinstance(assumptions, list)
            or 'no_external_module_global_mutation' not in assumptions
            or not isinstance(fact.get('boundaries'), list)
            or any(not isinstance(item, dict) or item.get('reason')
                   == 'caller_prefix_call_effect_unconfirmed'
                   for item in fact.get('boundaries', []))):
        return None
    callsite_path = str(call.callsite.file_path)
    expected_callsite = {'file_path': callsite_path, **{
        name: getattr(call.callsite, name) for name in _FIELDS}}
    source_hashes = fact.get('source_hashes')
    if (fact.get('call_evidence') != expected_callsite
            or fact.get('call_syntax') != ast.dump(node, include_attributes=False)
            or not isinstance(source_hashes, dict)
            or not isinstance(source_hashes.get(callsite_path), str)
            or len(source_hashes[callsite_path]) != 64):
        return None

    # The callsite fact must still match the current source contents.
    # 调用点事实必须仍对应实际源码内容
    try:
        for path, digest in source_hashes.items():
            if (
                not isinstance(path, str)
                or not isinstance(digest, str)
                or hashlib.sha256(
                    Path(path).read_text(encoding='utf-8-sig').encode('utf-8')
                ).hexdigest() != digest
            ):
                return None
    except (OSError, UnicodeError):
        return None
    contexts = fact.get('context_managers')
    if contexts is None:
        contexts = []
    if (not isinstance(contexts, list)
            or any(not isinstance(item, dict) or item.get('kind') != 'context_manager'
                   or item.get('call_evidence') != expected_callsite
                   or not isinstance(item.get('manager'), dict)
                   or item['manager'].get('target') != 'builtins.open'
                   for item in contexts)):
        return None
    return fact, expected_callsite, source_hashes


## Resolve caller-side conditions for the selected ContextVar state.
## 解析所选 ContextVar 状态的调用方条件。
#
#  @param context Analysis context owning source facts
#  @param call Caller invocation
#  @param node Call AST node
#  @param entry Resolved API entry
#  @return Conditions keyed by branch source span, or an empty dict when unproven
def caller_contextvar_conditions(context, call, node, entry):
    validated = _validated_callsite_inputs(context, call, node)
    if validated is None:
        return {}
    fact, expected_callsite, source_hashes = validated

    # Switch from validating caller facts to matching guards in the indexed API source.
    # 校验调用方事实后，在已索引的 API 源码中匹配守卫。
    aliases = context.index.imports.get(entry.identity.module, {})
    api_path, api_tree = _module_tree(context, entry.identity.module)
    if api_path is None or api_tree is None:
        return {}
    conditions = {}
    parameters = {item.arg for item in (entry.node.args.posonlyargs
                  + entry.node.args.args + entry.node.args.kwonlyargs)}
    parameters.update(item.arg for item in (entry.node.args.vararg, entry.node.args.kwarg)
                      if item is not None)

    pending, branches = list(entry.node.body), []
    while pending:
        statement = pending.pop()
        if isinstance(statement, ast.If):
            branches.append(statement)
        if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef,
                                 ast.Lambda)):
            continue
        pending.extend(ast.iter_child_nodes(statement))
    for branch in branches:
        if not isinstance(branch, ast.If) or not isinstance(branch.test, ast.Name):
            continue
        if (branch.test.id in parameters
                or any(isinstance(item, ast.Name) and item.id == branch.test.id
                       and isinstance(item.ctx, ast.Store)
                       for item in ast.walk(entry.node))):
            continue
        if _module_binding_count(api_tree, branch.test.id) != 1:
            continue
        target = aliases.get(branch.test.id)
        if not isinstance(target, str) or '.' not in target:
            continue
        global_module, global_name = target.rsplit('.', 1)
        global_path, global_tree = _module_tree(context, global_module)
        if global_path is None or global_tree is None:
            continue
        proxy_value = _assignment(global_tree, global_name)
        if not isinstance(proxy_value, ast.Call) or not isinstance(proxy_value.func, ast.Name):
            continue
        global_imports = _module_imports(context, global_module, global_path, global_tree)
        proxy_target = global_imports.get(proxy_value.func.id)
        if not isinstance(proxy_target, str) or '.' not in proxy_target:
            continue
        proxy_module, proxy_qualname = proxy_target.rsplit('.', 1)
        proxy_path, proxy_tree = _module_tree(context, proxy_module)
        proxy_classes = ([item for item in ast.walk(proxy_tree)
                          if isinstance(item, ast.ClassDef) and item.name == proxy_qualname]
                         if proxy_tree is not None else [])
        proxy_proof = None
        if proxy_path is not None and proxy_tree is not None and len(proxy_classes) == 1:
            proxy_proof = _proxy_bool_is_unbound_false(
                context, proxy_module,
                FunctionIdentity(proxy_module, proxy_qualname, proxy_path,
                                 proxy_classes[0].lineno))
        if (proxy_path is None or proxy_tree is None or len(proxy_classes) != 1
                or _module_binding_count(global_tree, global_name) != 1
                or _module_binding_count(global_tree, proxy_value.func.id) != 1
                or _module_binding_count(proxy_tree, proxy_qualname) != 1
                or not isinstance(proxy_proof, dict)):
            continue
        bool_fact = proxy_proof['bool_member']
        fallback_fact = proxy_proof['descriptor_fallback']
        if not proxy_value.args or not isinstance(proxy_value.args[0], ast.Name):
            continue
        contextvar_assignment = _assignment(global_tree, proxy_value.args[0].id)
        if (not isinstance(contextvar_assignment, ast.Call)
                or not isinstance(contextvar_assignment.func, ast.Name)):
            continue
        contextvar_target = global_imports.get(contextvar_assignment.func.id)
        if (contextvar_target != 'contextvars.ContextVar'
                or _module_binding_count(global_tree, proxy_value.args[0].id) != 1
                or _module_binding_count(global_tree, contextvar_assignment.func.id) != 1
                or len(contextvar_assignment.args) != 1
                or contextvar_assignment.keywords):
            continue
        packages = {global_module.split('.')[0], proxy_module.split('.')[0]}
        identity = (global_module, proxy_value.args[0].id)
        import_effect = context.contextvar_packages.initialization(
            packages, identity, lambda: _package_sets_contextvar(context, packages, identity))
        if (not isinstance(import_effect, dict)
                or import_effect.get('state') != 'no_contextvar_write'
                or not _raw_source_hashes_match(import_effect.get('source_hashes'))):
            continue
        global_binding = _assignment_statement(global_tree, global_name)
        contextvar_name = proxy_value.args[0].id
        contextvar_binding = _assignment_statement(global_tree, contextvar_name)
        if global_binding is None or contextvar_binding is None:
            continue
        if branch.test.end_lineno is None or branch.test.end_col_offset is None:
            continue
        condition_span = SourceSpan(
            entry.identity.file_path,
            branch.test.lineno,
            branch.test.col_offset,
            branch.test.end_lineno,
            branch.test.end_col_offset,
        )
        conditions[condition_span] = {
            'reason': 'source_contextvar_proxy_unbound',
            'detail': 'PCResolve source-bound the exact module-level call prefix; no earlier '
                      'call effect or non-open context manager can bind this ContextVar, and '
                      'no reachable import-time .set call was found in the proxy packages under '
                      'the recorded source assumptions. The ContextVar has no default and '
                      'the source-backed bool protocol returns False when it is unbound.',
            'target': FunctionIdentity(proxy_module, proxy_qualname, proxy_path,
                                       proxy_classes[0].lineno),
            'source_proof': {
                'callsite': {'span': expected_callsite,
                             'source_hashes': source_hashes},
                'contextvar': {
                    'module': global_module, 'name': contextvar_name,
                    'source_span': {'lineno': contextvar_binding.lineno,
                                    'col_offset': contextvar_binding.col_offset,
                                    'end_lineno': contextvar_binding.end_lineno,
                                    'end_col_offset': contextvar_binding.end_col_offset},
                    'source_hashes': import_effect['source_hashes'],
                },
                'proxy_global': {
                    'module': global_module, 'name': global_name,
                    'source_span': {'lineno': global_binding.lineno,
                                    'col_offset': global_binding.col_offset,
                                    'end_lineno': global_binding.end_lineno,
                                    'end_col_offset': global_binding.end_col_offset},
                },
                'bool_member': {'member_span': bool_fact['member_span'],
                                'source_hashes': bool_fact['source_hashes'],
                                'assumptions': bool_fact.get('assumptions', [])},
                'proxy_init_member': {
                    'member_span': proxy_proof['proxy_init_member']['member_span'],
                    'source_hashes': proxy_proof['proxy_init_member']['source_hashes'],
                    'assumptions': proxy_proof['proxy_init_member'].get('assumptions', []),
                },
                'descriptor_init_member': {
                    'member_span': proxy_proof['descriptor_init_member']['member_span'],
                    'source_hashes': proxy_proof['descriptor_init_member']['source_hashes'],
                    'assumptions': proxy_proof['descriptor_init_member'].get('assumptions', []),
                },
                'descriptor_get_member': {
                    'member_span': proxy_proof['descriptor_get_member']['member_span'],
                    'source_hashes': proxy_proof['descriptor_get_member']['source_hashes'],
                    'assumptions': proxy_proof['descriptor_get_member'].get('assumptions', []),
                },
                'descriptor_fallback': {
                    'protected_span': fallback_fact['protected_span'],
                    'fallback_span': fallback_fact['source_span'],
                    'source_hashes': fallback_fact['source_hashes'],
                    'assumptions': fallback_fact.get('assumptions', []),
                },
                'import_initialization': import_effect,
                'assumptions': sorted(set(
                    fact_assumption
                    for proof_fact in (fact, bool_fact, proxy_proof['proxy_init_member'],
                                       proxy_proof['descriptor_init_member'],
                                       proxy_proof['descriptor_get_member'], fallback_fact)
                    for fact_assumption in proof_fact.get('assumptions', []))
                    | set(import_effect.get('assumptions', []))),
            },
        }
    return conditions
