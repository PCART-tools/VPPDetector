"""Validate source-bound caller arguments without evaluating caller expressions."""

from __future__ import annotations

import ast
import hashlib
import math
from pathlib import Path

from .models import SourceSpan

_FIELDS = ('lineno', 'col_offset', 'end_lineno', 'end_col_offset')
_ASSUMPTIONS = {'source_snapshot_bindings_hold', 'standard_module_global_lookup',
                'no_external_module_global_mutation'}


def _span(record, path):
    return (isinstance(record, dict) and record.get('file_path') == path
            and all(type(record.get(key)) is int for key in _FIELDS)
            and record['lineno'] > 0 and record['col_offset'] >= 0
            and record['end_col_offset'] >= 0
            and (record['end_lineno'], record['end_col_offset'])
            > (record['lineno'], record['col_offset']))


def _state(value, budget, depth=0):
    budget[0] -= 1
    if budget[0] < 0 or depth > 16 or not isinstance(value, dict):
        raise ValueError('Unbounded caller literal')
    kind = value.get('kind')
    if kind == 'scalar':
        name = value.get('type')
        item = value.get('value')
        if name == 'bytes':
            raw = value.get('value_hex')
            if not isinstance(raw, str) or len(raw) % 2:
                raise ValueError('Invalid bytes')
            item = bytes.fromhex(raw)
            if item.hex() != raw:
                raise ValueError('Invalid bytes encoding')
        elif (type(item) not in (str, int, float, bool, type(None))
              or type(item).__name__ != name
              or 'value' not in value or type(item) is float and not math.isfinite(item)):
            raise ValueError('Invalid scalar')
        return {'kind': 'literal', 'value': item}
    if kind in ('list', 'tuple') and isinstance(value.get('items'), list):
        return {'kind': kind, 'items': [_state(item, budget, depth + 1)
                                       for item in value['items']]}
    raise ValueError('Unsupported caller value')


def caller_arguments(adapter, call, node, target, entry):
    """Return typed slot values only for this exact source call and API binding."""
    if (not isinstance(call.callsite, SourceSpan)
            or not all(type(getattr(call.callsite, key)) is int for key in _FIELDS)):
        return None
    site = call.callsite
    path = str(site.file_path)
    try:
        fact = adapter.caller_inputs(site)
        identities = (target, entry.identity, entry.query_class, entry.query_alias)
        names = {f'{identity.module}.{identity.qualname}' for identity in identities
                 if identity is not None}
        if (not isinstance(fact, dict) or fact.get('kind') != 'source_callsite_inputs'
                or fact.get('status') != 'source_bound'
                or fact.get('scope') != 'argument_reads_on_normal_module_prefix'
                or fact.get('runtime_values_observed') is not False
                or fact.get('boundaries') != [] or fact.get('target') not in names
                or fact.get('call_syntax') != ast.dump(node, include_attributes=False)
                or not isinstance(fact.get('assumptions'), list)
                or not all(isinstance(item, str) for item in fact['assumptions'])
                or not _ASSUMPTIONS.issubset(fact['assumptions'])
                or not _span(fact.get('call_evidence'), path)
                or any(fact['call_evidence'][key] != getattr(site, key) for key in _FIELDS)):
            return None
        with Path(path).open(encoding='utf-8-sig') as stream:
            digest = hashlib.sha256(stream.read().encode('utf-8')).hexdigest()
        if fact.get('source_hashes') != {path: digest}:
            return None
        binding = fact.get('target_binding_evidence')
        if (not isinstance(binding, list) or not binding or any(
                not _span(item, path) or (item['end_lineno'], item['end_col_offset'])
                > (site.lineno, site.col_offset) for item in binding)):
            return None
        if any(isinstance(arg, ast.Starred) for arg in node.args) or any(
                kw.arg is None for kw in node.keywords):
            return None
        slots = [(('position', i), arg) for i, arg in enumerate(node.args)]
        slots.extend((('keyword', kw.arg), kw.value) for kw in node.keywords)
        records = fact.get('arguments')
        if not isinstance(records, list) or len(records) != len(slots):
            return None
        result, budget = {}, [2000]
        for record, (slot, argument) in zip(records, slots):
            if (not isinstance(record, dict) or record.get('argument') != dict([slot])
                    or record.get('status') not in ('source_literal', 'unproven')):
                return None
            evidence = record.get('evidence')
            if (not isinstance(evidence, list) or not evidence
                    or any(not _span(item, path) for item in evidence)
                    or any(evidence[0][key] != getattr(argument, key) for key in _FIELDS)):
                return None
            if record['status'] == 'source_literal':
                result[slot] = _state(record.get('value'), budget)
            elif 'value' in record:
                return None
        return result, tuple(fact['assumptions'])
    except (AttributeError, OSError, UnicodeError, ValueError, TypeError, KeyError):
        return None
