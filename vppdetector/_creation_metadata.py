"""Validate metadata-query premises embedded in source class creation effects."""

_CLAIM = "source_class_creation_callable_metadata_queries"
_FIELDS = ("lineno", "col_offset", "end_lineno", "end_col_offset")
_INPUT_PROTOCOLS = {
    "inspect.signature": "native_signature_resolution_without_user_callbacks",
    "inspect.getdoc": "native_documentation_resolution_without_user_callbacks",
}
_PROTOCOLS = set(_INPUT_PROTOCOLS) | {"native_metadata_length", "native_string_prefix"}
_REQUIRED = {
    "source_snapshot_bindings_hold",
    "standard_library_callable_metadata_protocols",
    "standard_builtin_namespace_preserved",
    "no_unmodeled_indirect_builtin_mutation",
    "no_external_monkeypatch_or_import_hook",
    "no_unmodeled_indirect_module_mutation",
    "no_unmodeled_indirect_function_mutation",
    "builtin_function_creation_and_metadata",
    "fresh_source_class_function_before_class_decorators",
    "native_callable_metadata_input_protocols_discharged",
    _CLAIM,
}
_OBSERVERS = {
    "source_snapshot_bindings_hold",
    "standard_sys_frame_metadata_protocol",
    "source_frame_metadata_non_escape",
    "no_unmodeled_indirect_frame_or_gc_observation",
    "no_external_frame_or_gc_observation",
    "no_external_monkeypatch_or_import_hook",
    "source_module_initialization_completed_before_query",
    "no_unmodeled_indirect_module_mutation",
    "no_unmodeled_indirect_function_mutation",
}


def _strings(value):
    return isinstance(value, (list, tuple)) and all(isinstance(item, str) for item in value)


def _identity(value, hashes):
    return (
        isinstance(value, dict)
        and all(
            isinstance(value.get(key), str) and value[key]
            for key in ("module", "qualname", "file_path")
        )
        and value["file_path"] in hashes
        and type(value.get("lineno")) is int
        and value["lineno"] >= 1
    )


def _witness(value, owner):
    return (
        isinstance(value, dict)
        and value.get("file_path") == owner.get("file_path")
        and all(type(value.get(key)) is int and value[key] >= 0 for key in _FIELDS)
        and value["lineno"] >= owner["lineno"]
        and tuple(value[key] for key in _FIELDS[:2]) < tuple(value[key] for key in _FIELDS[2:])
    )


def _contained(inner, outer):
    return (
        inner["file_path"] == outer["file_path"]
        and tuple(inner[key] for key in _FIELDS[:2]) >= tuple(outer[key] for key in _FIELDS[:2])
        and tuple(inner[key] for key in _FIELDS[2:]) <= tuple(outer[key] for key in _FIELDS[2:])
    )


def _observer(call, hashes):
    guard = call.get("observation_guard")
    if (
        not isinstance(guard, dict)
        or guard.get("source_hashes") != hashes
        or not _strings(guard.get("assumptions"))
        or not _OBSERVERS.issubset(guard["assumptions"])
        or not set(guard["assumptions"]).issubset(call["assumptions"])
    ):
        return False
    namespace = guard.get("namespace_guard")
    if (
        not isinstance(namespace, dict)
        or namespace.get("scope") != "bounded_source_callable_namespaces"
        or namespace.get("runtime_reflective_writes") != []
        or namespace.get("execution_field_writes") != []
        or not isinstance(namespace.get("module_initializers"), (list, tuple))
    ):
        return False
    for record in namespace["module_initializers"]:
        if (
            not isinstance(record, dict)
            or not isinstance(record.get("file_path"), str)
            or record["file_path"] not in hashes
            or not isinstance(record.get("module"), str)
            or record.get("phase") not in ("module_initialization", "new_export_only")
            or any(type(record.get(key)) is not int or record[key] < 0 for key in _FIELDS)
        ):
            return False
    records = guard.get("frame_metadata")
    if not isinstance(records, (list, tuple)) or len(records) > 1000:
        return False
    for record in records:
        if (
            not isinstance(record, dict)
            or not _identity(record.get("function"), hashes)
            or record.get("kind") != "source_frame_metadata_use"
            or record.get("status") != "source_bound"
            or record.get("scope") != "native_frame_metadata_only"
            or record.get("factory") not in (
                "sys._getframe", "sys._current_frames", "traceback.walk_stack"
            )
            or record.get("factory") == "traceback.walk_stack"
            and "standard_traceback_frame_iteration_protocol" not in guard["assumptions"]
            or record.get("runtime_observation_confirmed") is not False
            or not isinstance(record.get("variable"), str)
            or not record["variable"]
            or not _strings(record.get("fields"))
            or not set(record["fields"]).issubset(
                {"f_back", "f_code", "f_globals", "f_lineno", "f_lasti"}
            )
            or record.get("global_keys") != (
                ["__name__"] if "f_globals" in record["fields"] else []
            )
            or not _witness(record.get("evidence"), record["function"])
        ):
            return False
    return True


def _query(call, entry, hashes):
    query = call.get("query")
    if (
        not isinstance(query, dict)
        or query.get("kind") != "source_callable_metadata_query"
        or query.get("status") != "requires_native_callable_metadata"
        or query.get("completion") != "normal_return_only"
        or query.get("effect_scope") != "synchronous_query_only"
        or query.get("runtime_execution_confirmed") is not False
        or "result" in query
        or query.get("target") != entry["target"]
        or query.get("source_hashes") != hashes
        or not _strings(query.get("assumptions"))
        or not (
            _REQUIRED
            - {
                "builtin_function_creation_and_metadata",
                "fresh_source_class_function_before_class_decorators",
                "native_callable_metadata_input_protocols_discharged",
                _CLAIM,
            }
        ).issubset(query["assumptions"])
        or not set(query["assumptions"]).issubset(call["assumptions"])
        or not _strings(query.get("result_shapes"))
        or not query["result_shapes"]
        or list(query["result_shapes"]) != sorted(set(query["result_shapes"]))
        or not set(query["result_shapes"]).issubset({"str", "int", "bool", "float", "NoneType"})
        or query["result_shapes"] != call.get("result_shapes")
        or query.get("definition_evidence") != entry["definition_evidence"]
    ):
        return None
    effects = query.get("input_effects")
    if (
        not isinstance(effects, dict)
        or effects.get("source_writes") != []
        or effects.get("source_exposures") != []
        or type(effects.get("native_cache_retention")) is not bool
    ):
        return None
    protocols, records = set(), query.get("protocol_calls")
    if not isinstance(records, (list, tuple)) or not 1 <= len(records) <= 2000:
        return None
    for record in records:
        if (
            not isinstance(record, dict)
            or not isinstance(record.get("protocol"), str)
            or record["protocol"] not in _PROTOCOLS
            or not _witness(record.get("evidence"), query["target"])
            or not _contained(record["evidence"], query["definition_evidence"])
        ):
            return None
        if record["protocol"] in _INPUT_PROTOCOLS:
            protocols.add(_INPUT_PROTOCOLS[record["protocol"]])
    if not protocols:
        return None
    cached = effects["native_cache_retention"]
    construction = query.get("construction")
    if cached:
        if (
            not isinstance(construction, dict)
            or construction.get("kind") != "standard_library_staticmethod_cache_creation"
            or construction.get("status") != "source_bound"
            or construction.get("result_kind") != "native_staticmethod"
            or construction.get("completion") != "normal_return_only"
            or construction.get("future_body_effects") != "unmodeled"
            or construction.get("runtime_creation_confirmed") is not False
            or construction.get("owner_class") != entry["owner_class"]
            or construction.get("function_name") != entry["target"]["qualname"].rsplit(".", 1)[-1]
            or construction.get("source_hashes") != hashes
            or "maxsize" not in construction
            or construction["maxsize"] is not None
            and type(construction["maxsize"]) is not int
            or type(construction.get("typed")) is not bool
            or not _strings(construction.get("assumptions"))
            or not {
                "standard_library_staticmethod_cache_creation",
                "standard_library_default_wraps_metadata_protocol",
                "builtin_staticmethod_descriptor",
                "standard_builtin_namespace_preserved",
                "no_unmodeled_indirect_builtin_mutation",
                "source_snapshot_bindings_hold",
                "no_external_monkeypatch_or_import_hook",
                "no_unmodeled_indirect_module_mutation",
                "no_unmodeled_indirect_function_mutation",
            }.issubset(construction["assumptions"])
            or not set(construction["assumptions"]).issubset(query["assumptions"])
            or not isinstance(construction.get("evidence"), (list, tuple))
            or len(construction["evidence"]) != 2
            or any(
                not _witness(witness, entry["owner_class"])
                or not _contained(witness, entry["class_evidence"])
                for witness in construction["evidence"]
            )
        ):
            return None
        protocols.add("native_callable_hash_equality_without_user_callbacks")
    elif construction is not None:
        return None
    preconditions = query.get("input_preconditions")
    if (
        not isinstance(preconditions, dict)
        or not isinstance(preconditions.get("parameter"), str)
        or not preconditions["parameter"]
        or preconditions.get("kind") != "native_python_function_or_method"
        or preconditions.get("protocols") != sorted(protocols)
    ):
        return None
    return sorted(protocols)


def creation_metadata_premises(hook, supporting_source_hashes=None):
    """Require each metadata query's conditional input and actual source binding."""
    primary = hook.get('source_hashes')
    supporting = {} if supporting_source_hashes is None else supporting_source_hashes
    if (not isinstance(primary, dict) or not isinstance(supporting, dict)
            or set(primary) & set(supporting)
            or any(not isinstance(path, str) or not isinstance(digest, str)
                   or len(digest) != 64 or any(char not in '0123456789abcdef' for char in digest)
                   for path, digest in supporting.items())):
        return False
    if not _signature_creations(hook, {**primary, **supporting}):
        return False
    records = hook.get("callable_metadata_queries")
    claimed = _CLAIM in hook.get("assumptions", ())
    if records is None:
        return not claimed
    if not claimed or not isinstance(records, (list, tuple)) or not 1 <= len(records) <= 256:
        return False
    hashes = hook["source_hashes"]
    if not _identity(hook.get("receiver_class"), hashes) or not _witness(
        hook.get("class_evidence"), hook["receiver_class"]
    ):
        return False
    callers = [hook["target"]] + [call["target"] for call in hook.get("method_calls", ())]
    seen = set()
    for call in records:
        if (
            not isinstance(call, dict)
            or call.get("kind") != "source_bound_callable_metadata_query"
            or call.get("status") != "source_bound"
            or call.get("completion") != "normal_return_only"
            or call.get("runtime_execution_confirmed") is not False
            or "result" in call
            or call.get("source_hashes") != hashes
            or not _strings(call.get("assumptions"))
            or not _REQUIRED.issubset(call["assumptions"])
            or not set(call["assumptions"]).issubset(hook["assumptions"])
            or not _identity(call.get("caller"), hashes)
            or call["caller"] not in callers
            or call.get("receiver_class") != hook["receiver_class"]
            or call.get("phase") != "before_class_decorators"
            or not isinstance(call.get("parameter"), str)
            or not call["parameter"]
            or call["caller"] == hook["target"]
            and call["parameter"] != hook["parameter"]
            or not _witness(call.get("call_evidence"), call["caller"])
        ):
            return False
        entry = call.get("entry_binding")
        if (
            not isinstance(entry, dict)
            or entry.get("kind") != "source_native_class_member_query"
            or entry.get("status") != "source_bound"
            or entry.get("completion") != "normal_attribute_lookup_only"
            or entry.get("runtime_target_confirmed") is not False
            or entry.get("source_hashes") != hashes
            or not _strings(entry.get("assumptions"))
            # Observer-result projection has its own conditional input and
            # lifetime premises. It cannot inherit this scalar-query reader.
            or "private_query_results" in entry
            or "source_private_observer_result_projection" in entry.get("assumptions", ())
            or not {
                "source_native_class_member_query_binding",
                "builtin_type_class_creation_protocol",
                "source_snapshot_bindings_hold",
                "no_external_monkeypatch_or_import_hook",
                "no_unmodeled_indirect_class_mutation",
            }.issubset(entry["assumptions"])
            or not set(entry["assumptions"]).issubset(call["assumptions"])
            or not _identity(entry.get("target"), hashes)
            or not _identity(entry.get("owner_class"), hashes)
            or entry["target"]["qualname"].rpartition(".")[0] != entry["owner_class"]["qualname"]
            or entry["target"]["module"] != entry["owner_class"]["module"]
            or entry["target"]["file_path"] != entry["owner_class"]["file_path"]
            or not _witness(entry.get("class_evidence"), entry["owner_class"])
            or entry["class_evidence"]["lineno"] != entry["owner_class"]["lineno"]
            or not _witness(entry.get("definition_evidence"), entry["target"])
            or entry["definition_evidence"]["lineno"] != entry["target"]["lineno"]
            or not _contained(entry["definition_evidence"], entry["class_evidence"])
        ):
            return False
        protocols = _query(call, entry, hashes)
        binding = call.get("input_binding")
        if (
            protocols is None
            or not isinstance(binding, dict)
            or binding.get("kind") != "fresh_source_class_function"
            or binding.get("status") != "source_bound"
            or binding.get("receiver_class") != hook["receiver_class"]
            or binding.get("phase") != "before_class_decorators"
            or binding.get("input_kind") != "native_python_function"
            or binding.get("runtime_input_confirmed") is not False
            or binding.get("signature_metadata") != "native_fresh_function"
            or binding.get("hash_equality") != "builtin_function_identity"
            or binding.get("protocols") != protocols
            or binding.get("documentation_shape") not in ("str", "NoneType")
            or "native_documentation_resolution_without_user_callbacks" in protocols
            and (
                binding.get("documentation_shape") != "str"
                or "source_function_docstrings_preserved" not in call["assumptions"]
            )
            or not isinstance(binding.get("attribute"), str)
            or not binding["attribute"]
            or binding["attribute"].startswith("__")
            or binding["attribute"] in hook["attributes"]
            or not _identity(binding.get("target"), hashes)
            or binding["target"]["qualname"]
            != hook["receiver_class"]["qualname"] + "." + binding["attribute"]
            or binding["target"]["module"] != hook["receiver_class"]["module"]
            or binding["target"]["file_path"] != hook["receiver_class"]["file_path"]
            or not _witness(binding.get("definition_evidence"), binding["target"])
            or binding["definition_evidence"]["lineno"] != binding["target"]["lineno"]
            or not _contained(binding["definition_evidence"], hook["class_evidence"])
            or not _observer(call, hashes)
        ):
            return False
        site = (
            tuple(call["caller"][key] for key in ("module", "qualname", "file_path", "lineno")),
            tuple(call["call_evidence"][key] for key in _FIELDS),
        )
        if site in seen:
            return False
        seen.add(site)
    return True


def _dynamic_signature_parameters(hook, proof, hashes):
    dynamic = proof.get('dynamic_parameters')
    if not isinstance(dynamic, (list, tuple)) or not 1 <= len(dynamic) <= 256:
        return False
    queries = [item for item in hook.get('class_metadata_queries', ())
               if isinstance(item, dict) and item.get('kind') == 'source_bound_class_metadata_query'
               and item.get('caller') == proof.get('caller')
               and item.get('result_shape') == 'native_string_list']
    if not queries:
        return False
    for segment in dynamic:
        input_query = segment.get('input_query') if isinstance(segment, dict) else None
        if (not isinstance(segment, dict)
                or segment.get('kind') != 'native_keyword_only_parameter_segment'
                or not isinstance(input_query, dict)
                or input_query.get('kind') != 'source_bound_class_metadata_query'
                or input_query.get('status') != 'source_bound'
                or input_query.get('caller') != proof.get('caller')
                or input_query.get('result_shape') != 'native_string_list'
                or input_query not in queries
                or segment.get('names') != 'unresolved_native_strings'
                or segment.get('parameter_kind') != 'KEYWORD_ONLY'
                or segment.get('completion') != 'normal_return_only'
                or segment.get('validation') != 'name_validity_and_duplicates_may_raise'
                or not _witness(segment.get('evidence'), proof['caller'])):
            return False
        filters = segment.get('filters')
        if not isinstance(filters, (list, tuple)) or not filters:
            return False
        for item in filters:
            table = item.get('table_binding') if isinstance(item, dict) else None
            if (not isinstance(item, dict)
                    or item.get('operation') != 'native_string_not_in_literal_sequence'
                    or not isinstance(item.get('excluded_names'), (list, tuple))
                    or not item['excluded_names']
                    or any(not isinstance(name, str) for name in item['excluded_names'])
                    or not isinstance(table, dict)
                    or table.get('kind') != 'source_class_literal_string_sequence'
                    or table.get('attribute') != '_PROPERTIES_EXCLUDED_FROM_SET'
                    or table.get('phase') != 'class_creation_entry'
                    or table.get('required_preservation') != 'complete_current_call'
                    or table.get('values') != item['excluded_names']
                    or not _identity(table.get('source_class'), hashes)
                    or not _identity(table.get('receiver_class'), hashes)
                    or not _witness(table.get('binding_evidence'), table['source_class'])
                    or not _witness(table.get('value_evidence'), table['source_class'])
                    or not isinstance(table.get('source_hashes'), dict)
                    or not table['source_hashes']
                    or any(hashes.get(path) != digest
                           for path, digest in table['source_hashes'].items())
                    or not _strings(table.get('assumptions'))
                    or not set(table['assumptions']).issubset(proof.get('assumptions', ()) )):
                return False
    return True


def _signature_creations(hook, complete_source_hashes=None):
    records = hook.get('signature_creations')
    claim = 'standard_library_inspect_signature_creation'
    if records is None:
        return claim not in hook.get('assumptions', ())
    if not isinstance(records, (list, tuple)) or not 1 <= len(records) <= 256:
        return False
    hashes = hook['source_hashes'] if complete_source_hashes is None else complete_source_hashes
    callers = [hook['target']] + [call['target'] for call in hook.get('method_calls', ())]
    required = {'source_snapshot_bindings_hold', claim,
                'standard_library_inspect_parameter_creation',
                'standard_builtin_namespace_preserved',
                'no_unmodeled_indirect_builtin_mutation', 'no_unmodeled_indirect_module_mutation',
                'no_external_monkeypatch_or_import_hook'}
    for proof in records:
        if (not isinstance(proof, dict) or proof.get('kind') != 'source_native_signature_creation'
                or proof.get('status') != 'source_bound'
                or proof.get('result_kind') != 'native_inspect_signature'
                or proof.get('completion') != 'normal_return_only'
                or proof.get('runtime_creation_confirmed') is not False
                or proof.get('source_hashes') != hashes
                or not _strings(proof.get('assumptions'))
                or not required <= set(proof['assumptions'])
                or not set(proof['assumptions']) <= set(hook['assumptions'])
                or not _identity(proof.get('caller'), hashes) or proof['caller'] not in callers
                or not _witness(proof.get('call_evidence'), proof['caller'])):
            return False
        parameters, defaults = proof.get('parameter_evidence'), proof.get('default_bindings')
        dynamic = proof.get('dynamic_parameters', ())
        dynamic_input = proof.get('input_binding') == 'source_dynamic_native_metadata'
        if (not isinstance(parameters, (list, tuple)) or len(parameters) > 2000
                or any(not _witness(item, proof['caller'])
                       or not _contained(item, proof['call_evidence']) for item in parameters)
                or not isinstance(defaults, (list, tuple)) or len(defaults) > len(parameters)
                or proof.get('value_operations') != (
                    'storage_only' if defaults else 'native_literal_data')
                or proof.get('input_binding') != (
                    'source_dynamic_native_metadata' if dynamic_input else
                    'source_marker_native_metadata' if defaults else 'literal_native_metadata')
                or bool(dynamic) != dynamic_input
                or dynamic_input and not _dynamic_signature_parameters(hook, proof, hashes)):
            return False
        for marker in defaults:
            if (not isinstance(marker, dict)
                    or marker.get('kind') != 'source_marker_metadata_default'
                    or marker.get('signature_use') != 'opaque_reference_storage'
                    or marker.get('runtime_creation_confirmed') is not False
                    or marker.get('source_hashes') != hook['source_hashes']
                    or not isinstance(marker.get('binding_name'), str)
                    or not marker['binding_name'].isidentifier()
                    or not _identity(marker.get('source_class'), hashes)):
                return False
            owner = marker['source_class']
            allocation = marker.get('allocation')
            if (not isinstance(allocation, dict)
                    or allocation.get('protocol') != 'builtin_object_new_and_init_no_arguments'
                    or not _witness(marker.get('binding_evidence'), owner)
                    or not _witness(allocation.get('evidence'), owner)
                    or not _contained(allocation['evidence'], marker['binding_evidence'])
                    or owner['module'] != proof['caller']['module']):
                return False
    return True
