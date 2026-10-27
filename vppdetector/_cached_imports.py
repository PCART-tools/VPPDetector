## @package vppdetector._cached_imports
#  Validate source evidence for cached imports.
#  校验缓存导入相关的源码证据。

"""Match source cached-import facts; availability and cache premises stay explicit."""

from __future__ import annotations

import ast
from pathlib import Path

from pcresolve.import_facts import resolve_relative_module

from ._program_facts import identity_from_target


## Read one exact reached from-import under the producer's cache conditions
## 按生产者缓存条件读取精确到达的导入绑定
#
#  @param analysis PCResolve analysis result being validated or consumed.
#  @param function Indexed source function under analysis.
#  @param statement Value named `statement` supplied by the enclosing analysis.
#  @return Result of the `cached_import_binding` operation.
def cached_import_binding(analysis, function, statement):
    if (not isinstance(statement, ast.ImportFrom) or statement.level
            or not statement.module or any(alias.name == '*' for alias in statement.names)):
        return None
    summaries = [item for item in analysis.functions
                 if identity_from_target(item.get('function')) == function.identity]
    if len(summaries) != 1:
        return None
    fields = ('lineno', 'col_offset', 'end_lineno', 'end_col_offset')
    records = [record for record in summaries[0].get('cached_local_imports', ())
               if isinstance(record, dict) and isinstance(record.get('evidence'), dict)
               and all(record['evidence'].get(key) == getattr(statement, key) for key in fields)]
    if len(records) != 1:
        return None
    record = records[0]
    bindings = [{'name': alias.asname or alias.name, 'module': statement.module,
                 'attribute': alias.name} for alias in statement.names]
    hashes = record.get('source_hashes')

    # 缓存导入事实依赖源码快照和模块缓存保持，不能视为运行时导入验证
    required = {'source_snapshot_bindings_hold', 'standard_builtin_import_binding',
                'initialized_source_module_cache_preserved',
                'no_external_monkeypatch_or_import_hook', 'no_unmodeled_indirect_module_mutation'}
    if (record.get('kind') != 'source_cached_import_binding'
            or record.get('status') != 'bound_on_normal_cached_import_return'
            or record.get('runtime_import_confirmed') is not False
            or identity_from_target(record.get('function')) != function.identity
            or record.get('bindings') != bindings
            or record.get('effects') != 'module_execution_not_required_if_cache_preserved'
            or record['evidence'].get('file_path') != str(function.identity.file_path)
            or not isinstance(record.get('assumptions'), list)
            or not required.issubset(record['assumptions'])
            or not isinstance(record.get('conditions'), list)
            or not isinstance(hashes, dict) or len(hashes) < 2
            or str(function.identity.file_path) not in hashes
            or any(not digest or analysis.inputs.get('sha256', {}).get(path) != digest
                   for path, digest in hashes.items())
            or not record.get('initialization_evidence')):
        return None
    for witness in record['initialization_evidence']:
        if (not isinstance(witness, dict)
                or witness.get('file_path') != str(function.identity.file_path)
                or any(type(witness.get(key)) is not int for key in fields)
                or witness['lineno'] >= function.node.lineno):
            return None
    return record


## Validate a cached import inside a closed decorator proof, without executing it
## 在封闭装饰器证明中验证缓存导入，不执行导入代码
#
#  @param context Reusable analysis context for the selected source snapshot.
#  @param analysis PCResolve analysis result being validated or consumed.
#  @param function Indexed source function under analysis.
#  @param fact Producer fact being validated or interpreted.
#  @param effect Value named `effect` supplied by the enclosing analysis.
#  @return Result of the `decorator_import_binding` operation.
def decorator_import_binding(context, analysis, function, fact, effect):
    record = effect.get('binding')
    if not isinstance(record, dict):
        return None
    callback = identity_from_target(record.get('function'))
    selected = context.index.find(callback) if callback is not None else None
    fields = ('lineno', 'col_offset', 'end_lineno', 'end_col_offset')
    witness = record.get('evidence')
    if (selected is None or not isinstance(witness, dict)
            or witness.get('file_path') != str(callback.file_path)
            or effect.get('function') != record.get('function')
            or not isinstance(effect.get('evidence'), dict)
            or any(effect['evidence'].get(key) != witness.get(key) for key in fields)
            or effect['evidence'].get('file_path') != witness['file_path']):
        return None

    imports = [node for node in ast.walk(selected.node) if isinstance(node, ast.ImportFrom)
               and all(getattr(node, key) == witness.get(key) for key in fields)]
    if (len(imports) != 1 or imports[0].level or not imports[0].module
            or not imports[0].names or any(alias.name == '*' for alias in imports[0].names)):
        return None
    statement = imports[0]
    bindings = [{'name': alias.asname or alias.name, 'module': statement.module,
                 'attribute': alias.name} for alias in statement.names]
    required = {'source_snapshot_bindings_hold', 'standard_builtin_import_binding',
                'initialized_source_module_cache_preserved',
                'no_external_monkeypatch_or_import_hook',
                'no_unmodeled_indirect_module_mutation', 'standard_builtin_namespace_preserved'}
    hashes, assumptions = record.get('source_hashes'), record.get('assumptions')

    initialization = record.get('initialization_evidence')
    if (record.get('kind') != 'source_cached_import_binding'
            or record.get('status') != 'bound_on_normal_cached_import_return'
            or record.get('runtime_import_confirmed') is not False
            or record.get('effects') != 'module_execution_not_required_if_cache_preserved'
            or record.get('bindings') != bindings
            or not isinstance(record.get('conditions'), (list, tuple))
            or record.get('conditions') != effect.get('conditions')
            or effect.get('operation') != 'cached_import' or effect.get('target') != 'source_module'
            or effect.get('impact') != 'conditional_import_binding'
            or effect.get('completion') != 'normal_cached_import_return'
            or identity_from_target(record.get('initialization_function')) != function.identity
            or not isinstance(hashes, dict) or hashes != analysis.inputs.get('sha256')
            or not hashes or str(callback.file_path) not in hashes
            or str(function.identity.file_path) not in hashes
            or any(fact.get('source_hashes', {}).get(path) != digest
                   for path, digest in hashes.items())
            or not isinstance(assumptions, (list, tuple))
            or any(not isinstance(item, str) for item in assumptions)
            or not required.issubset(assumptions)
            or not required.issubset(fact.get('assumptions', ()))
            or not isinstance(initialization, (list, tuple)) or not initialization):
        return None

    # Match initialization witnesses to actual top-level import syntax. This
    # checks evidence identity, not the producer's import/cache semantics again.
    # 将初始化见证与实际顶层导入语法匹配，只核对证据身份，不重复推断生产者的导入或缓存语义。
    try:
        tree = ast.parse(Path(function.identity.file_path).read_text(encoding='utf-8-sig'))
    except (OSError, UnicodeError, SyntaxError, RecursionError):
        return None
    for source in initialization:
        if (not isinstance(source, dict)
                or source.get('file_path') != str(function.identity.file_path)
                or any(type(source.get(key)) is not int for key in fields)
                or source['lineno'] >= function.node.lineno
                or not any(isinstance(node, (ast.Import, ast.ImportFrom))
                           and all(getattr(node, key) == source[key] for key in fields)
                           for node in tree.body)):
            return None

    lookups = record.get('package_lookups')
    if not isinstance(lookups, (list, tuple)):
        return None
    seen = set()
    required_lookup = {'source_snapshot_bindings_hold', 'standard_builtin_namespace_preserved',
                       'standard_library_lru_cache_protocol',
                       'source_getattr_dispatch_table_preserved',
                       'no_external_monkeypatch_or_import_hook',
                       'no_unmodeled_indirect_builtin_mutation'}
    for lookup in lookups:
        if not isinstance(lookup, dict):
            return None
        definition = identity_from_target(lookup.get('definition'))
        factory = identity_from_target(lookup.get('factory'))
        properties, claims = lookup.get('property_names'), lookup.get('assumptions')
        if (lookup.get('kind') != 'source_module_getattr_missing'
                or lookup.get('status') != 'missing_on_dispatch'
                or lookup.get('basis') != 'source_snapshot'
                or lookup.get('exception') != 'AttributeError'
                or lookup.get('runtime_lookup_confirmed') is not False
                or not isinstance(lookup.get('module'), str)
                or not isinstance(lookup.get('attribute'), str)
                or lookup['module'] + '.' + lookup['attribute'] != statement.module
                or not isinstance(properties, (list, tuple)) or len(properties) > 128
                or any(not isinstance(name, str) for name in properties)
                or lookup['attribute'] in properties
                or definition is None or definition.module != lookup['module']
                or definition.qualname != '__getattr__'
                or context.index.resolve_class(definition) != definition
                or factory is None or context.index.find(factory) is None
                or lookup.get('source_hashes') != hashes
                or not isinstance(claims, (list, tuple))
                or any(not isinstance(claim, str) for claim in claims)
                or not required_lookup.issubset(claims)
                or not required_lookup.issubset(assumptions)
                or not required_lookup.issubset(fact.get('assumptions', ()))
                or (lookup['module'], lookup['attribute']) in seen):
            return None
        seen.add((lookup['module'], lookup['attribute']))
    for source in initialization:
        initialized = next(node for node in tree.body
                           if isinstance(node, (ast.Import, ast.ImportFrom))
                           and all(getattr(node, key) == source[key] for key in fields))
        if not isinstance(initialized, ast.ImportFrom):
            continue
        parent = resolve_relative_module(function.identity.module,
            function.identity.file_path.name == '__init__.py',
            initialized.module, initialized.level)
        for alias in initialized.names:
            if parent + '.' + alias.name != statement.module:
                continue
            customized = any(identity.module == parent and identity.qualname == '__getattr__'
                             for identity in context.index.classes)
            customized = customized or context.index.find(
                type(function.identity)(parent, '__getattr__')) is not None
            if customized and (parent, alias.name) not in seen:
                return None
    return record
