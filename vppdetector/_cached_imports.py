"""Match source cached-import facts; availability and cache premises stay explicit."""

from __future__ import annotations

import ast

from ._program_facts import identity_from_target


def cached_import_binding(analysis, function, statement):
    """Read one exact reached from-import under the producer's cache conditions."""
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
