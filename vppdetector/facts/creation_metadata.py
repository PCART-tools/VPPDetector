## @package vppdetector.facts.creation_metadata
#  Validation for captured source class creation metadata.
#
#
#  Check individual class metadata queries against hook witnesses, then validate their combined
#  effects.
#  依据钩子见证校验各类元数据查询，再核对这些查询的汇总效果。



from .._records import FrozenRecord
from .callable_metadata import _observer
from .locations import _location


## Validate common source evidence within one metadata proof.
## 验证单次元数据证明中的通用源码证据。
#
class _MetadataChecks(FrozenRecord):
    _record_fields = ("available", "claims", "source_hashes")
    __match_args__ = ("available", "claims", "source_hashes")

    ## Initialize a _MetadataChecks instance with its declared state.
    ## 使用声明的状态初始化 _MetadataChecks 实例。
    #
    #  @param available Value stored in the `available` field
    #  @param claims Value stored in the `claims` field
    #  @param source_hashes Value stored in the `source_hashes` field
    def __init__(self, available, claims, source_hashes):
        object.__setattr__(self, "available", available)
        object.__setattr__(self, "claims", claims)
        object.__setattr__(self, "source_hashes", source_hashes)

    ## Read the source identity used by the enclosing proof
    ## 读取所属证明使用的源码身份
    #
    #  @param value Producer source identity record to validate
    #  @return Whether the identity fields and source path are valid
    def identity(self, value):
        return (
            isinstance(value, dict)
            and all(
                isinstance(value.get(key), str) and value[key]
                for key in ("module", "qualname", "file_path")
            )
            and type(value.get("lineno")) is int
            and value["lineno"] >= 1
            and value["file_path"] in self.available
        )

    ## Validate the source reference attached to the producer record
    ## 校验生产者记录附带的源码引用
    #
    #  @param value Producer source reference record to validate
    #  @return Whether the source reference has valid fields and an available file
    def source_reference(self, value):
        return (
            isinstance(value, dict)
            and all(
                isinstance(value.get(key), str) and value[key]
                for key in ("module", "qualname", "file_path")
            )
            and type(value.get("lineno")) is int
            and value["lineno"] >= 0
            and value["file_path"] in self.available
        )

    ## Check source hashes against the current indexed snapshot
    ## 将源码哈希与当前索引快照核对
    #
    #  @param value Producer fact containing source hashes to compare
    #  @return Whether all recorded source hashes match the available snapshot
    def hashes_match(self, value):
        hashes = value.get("source_hashes") if isinstance(value, dict) else None
        return (
            isinstance(hashes, dict)
            and bool(hashes)
            and all(
                isinstance(path, str) and self.available.get(path) == digest
                for path, digest in hashes.items()
            )
        )

    ## Validate the producer witness required by the enclosing proof
    ## 校验所属证明所需的生产者见证
    #
    #  @param value Producer source witness record to validate
    #  @param owner Optional source owner whose file and coordinates constrain the witness
    #  @return Whether the source span matches an available file and optional owner
    def witness(self, value, owner=None):
        return (
            isinstance(value, dict)
            and value.get("file_path") in self.available
            and (owner is None or value.get("file_path") == owner.get("file_path"))
            and all(type(item) is int and item >= 0 for item in _location(value))
            and value["lineno"] >= (owner.get("lineno", 1) if owner else 1)
            and _location(value)[:2] < _location(value)[2:]
        )

    ## Check that the recorded assumptions match the supported proof
    ## 检查记录的假设是否符合受支持的证明
    #
    #  @param value Producer fact containing assumptions to validate
    #  @return Whether the recorded assumptions are a subset of the supported claims
    def assumptions_match(self, value):
        assumptions = value.get("assumptions") if isinstance(value, dict) else None
        return (
            isinstance(assumptions, (list, tuple))
            and all(isinstance(item, str) for item in assumptions)
            and set(assumptions).issubset(self.claims)
        )

    ## Validate a module-initialized source member metadata write
    ## 校验模块初始化时的源码成员元数据写入
    #
    #  @param fact Producer fact being validated or interpreted
    #  @param target Optional producer target record to match
    #  @param attribute Optional attribute name to match
    #  @return Whether the fact proves the requested metadata write
    def module_initialized_member_metadata(
        self,
        fact,
        target=None,
        attribute=None,
    ):
        if (
            not isinstance(fact, dict)
            or fact.get("kind") != "source_module_initialization_member_metadata"
            or fact.get("status") != "source_bound"
            or fact.get("runtime_metadata_confirmed") is not False
            or fact.get("completion") != "normal_module_initialization_only"
            or not isinstance(fact.get("attribute"), str)
            or not fact["attribute"].isidentifier()
            or attribute is not None
            and fact.get("attribute") != attribute
            or not self.identity(fact.get("target"))
            or not self.identity(fact.get("updater"))
            or target is not None
            and fact.get("target") != target
            or not self.witness(fact.get("write_evidence"), fact["updater"])
            or not self.witness(
                fact.get("module_call_evidence"),
                {"file_path": fact["updater"]["file_path"], "lineno": fact["target"]["lineno"]},
            )
            or not self.hashes_match(fact)
            or not self.assumptions_match(fact)
        ):
            return False
        return True

    ## Check private attribute projections against their source premises
    ## 根据源码前提核对私有属性投影
    #
    #  @param entry Producer metadata record containing private query results
    #  @param parent_assumptions Assumptions provided by the enclosing analysis
    #  @return Whether the recorded private projections satisfy their source premises
    def private_projections_match(
        self,
        entry,
        parent_assumptions,
    ):
        projections = entry.get("private_query_results")
        if (
            not isinstance(projections, (list, tuple))
            or not 1 <= len(projections) <= 256
            or "source_private_observer_result_projection" not in parent_assumptions
        ):
            return False
        for projection in projections:
            query = projection.get("query") if isinstance(projection, dict) else None
            guard = projection.get("observation_guard") if isinstance(projection, dict) else None
            assumptions = projection.get("assumptions") if isinstance(projection, dict) else None
            if (
                not isinstance(projection, dict)
                or projection.get("kind") != "private_observer_data_result"
                or projection.get("basis") != "source_snapshot"
                or projection.get("scope") != "observer_class_identity_only"
                or projection.get("runtime_execution_confirmed") is not False
                or not self.identity(projection.get("owner_class"))
                or not self.source_reference(projection.get("caller"))
                or not self.witness(projection.get("call_evidence"), projection.get("caller"))
                or not isinstance(assumptions, (list, tuple))
                or "source_private_observer_result_projection" not in assumptions
                or not set(assumptions).issubset(parent_assumptions)
                or not isinstance(query, dict)
                or query.get("kind") != "source_private_class_metadata_observer"
                or query.get("status") != "requires_native_class_metadata"
                or query.get("runtime_execution_confirmed") is not False
                or query.get("completion") != "normal_return_only"
                or "result" in query
                or query.get("result_shape")
                not in ("native_string_list", "native_string_set_mapping")
                or not self.hashes_match(query)
                or not isinstance(query.get("owner_binding"), dict)
                or query["owner_binding"].get("status") != "requires_source_member_bindings"
                or query.get("owner_class") != projection.get("owner_class")
                or not isinstance(guard, dict)
                or not _observer(
                    {"observation_guard": guard, "assumptions": assumptions}, self.source_hashes
                )
            ):
                return False
        return True


## Validate metadata-query evidence for one class-creation hook.
## 校验一项类创建钩子的元数据查询证据。
#
#  @param analysis Producer analysis containing the hook
#  @param binding Producer binding that owns the hook
#  @param hook Class-creation hook record
#  @param hook_index Position of the hook in its binding
#  @return True when every metadata query matches its source evidence
def _class_creation_metadata_queries_premises(
    analysis,
    binding,
    hook,
    hook_index,
):
    records = hook.get("class_metadata_queries")
    claims = hook.get("assumptions", ())
    if records is None:
        return "source_creation_phase_class_metadata_input" not in claims
    required = {
        "source_snapshot_bindings_hold",
        "builtin_type_class_creation_protocol",
        "source_class_creation_effects",
        "source_creation_phase_class_metadata_input",
        "no_external_monkeypatch_or_import_hook",
        "no_unmodeled_indirect_class_mutation",
    }
    if (
        not isinstance(records, (list, tuple))
        or not 1 <= len(records) <= 256
        or not isinstance(claims, (list, tuple))
        or not required.issubset(claims)
        or not isinstance(hook.get("attributes"), (list, tuple))
        or any(not isinstance(name, str) or not name.isidentifier() for name in hook["attributes"])
    ):
        return False
    source_hashes = analysis.inputs.get("sha256", {})
    supporting = analysis.inputs.get("supporting_source_sha256", {})
    if not isinstance(source_hashes, dict) or not isinstance(supporting, dict):
        return False
    available = {**source_hashes, **supporting}
    hook_hashes = hook.get("source_hashes")
    if hook_hashes != source_hashes:
        return False

    # Only the hook and its recorded helper methods can witness these metadata operations.
    # 仅钩子及其记录中的辅助方法可作为这些元数据操作的见证。
    callers = [hook.get("target")]
    callers.extend(
        call.get("target") for call in hook.get("method_calls", ()) if isinstance(call, dict)
    )
    writes, presences, setter_queries, documentation, module_metadata_updates = [], [], [], [], []
    generated_presences = []
    wrapper_presences = []
    checks = _MetadataChecks(available, claims, source_hashes)

    for record in records:
        if (
            not isinstance(record, dict)
            or record.get("status") != "source_bound"
            or record.get("completion") != "normal_return_only"
            or record.get("runtime_execution_confirmed") is not False
            or record.get("receiver_class") != hook.get("receiver_class")
            or record.get("caller") not in callers
            or not checks.identity(record.get("caller"))
            or not checks.hashes_match(record)
            or not checks.assumptions_match(record)
            or not checks.witness(record.get("call_evidence"), record.get("caller"))
        ):
            return False
        kind = record.get("kind")
        if kind == "source_bound_callable_metadata_presence":
            fact = record.get("metadata_fact")
            if (
                record.get("operation") != "builtin_hasattr"
                or record.get("result") is not True
                or not isinstance(record.get("method_name"), str)
                or not isinstance(record.get("metadata_attribute"), str)
                or not record["metadata_attribute"].isidentifier()
                or not isinstance(fact, dict)
                or fact.get("status") != "source_bound"
                or fact.get("runtime_metadata_confirmed") is not False
                or not checks.hashes_match(fact)
                or not checks.assumptions_match(fact)
                or fact.get("attribute") != record["metadata_attribute"]
            ):
                return False
            fact_kind = fact.get("kind")
            if fact_kind == "source_wrapper_custom_function_metadata":
                if (
                    fact.get("formation_phase") != "class_body_function_decoration"
                    or type(fact.get("value")) not in (str, int, bool, float, type(None))
                    or not checks.identity(fact.get("decorator"))
                    or not checks.identity(fact.get("decorated_function"))
                    or fact.get("decorated_function") != record.get("target")
                    or not isinstance(fact.get("wrapper_name"), str)
                    or not isinstance(fact.get("wrapper_metadata_protocol"), dict)
                    or fact["wrapper_metadata_protocol"].get("status") != "source_bound"
                    or not checks.hashes_match(fact["wrapper_metadata_protocol"])
                    or not checks.assumptions_match(fact["wrapper_metadata_protocol"])
                    or not checks.witness(fact.get("evidence"))
                ):
                    return False
                wrapper_presences.append(record)
            elif fact_kind == "source_wrapper_callable_metadata_presence":
                nested = fact.get("metadata_write")
                protocol = (
                    nested.get("wrapper_metadata_protocol") if isinstance(nested, dict) else None
                )
                if (
                    not isinstance(nested, dict)
                    or nested.get("kind") != "source_wrapper_custom_function_metadata"
                    or nested.get("status") != "source_bound"
                    or fact.get("target") != record.get("target")
                    or nested.get("attribute") != record.get("metadata_attribute")
                    or nested.get("decorated_function") != record.get("target")
                    or nested.get("formation_phase") != "class_body_function_decoration"
                    or type(nested.get("value")) not in (str, int, bool, float, type(None))
                    or not checks.identity(nested.get("decorator"))
                    or not checks.identity(nested.get("decorated_function"))
                    or not isinstance(nested.get("wrapper_name"), str)
                    or not nested["wrapper_name"]
                    or nested.get("runtime_metadata_confirmed") is not False
                    or not checks.hashes_match(nested)
                    or not checks.assumptions_match(nested)
                    or not isinstance(protocol, dict)
                    or protocol.get("status") != "source_bound"
                    or not checks.hashes_match(protocol)
                    or not checks.assumptions_match(protocol)
                    or not set(nested.get("assumptions", ())).issubset(fact.get("assumptions", ()))
                    or not checks.witness(nested.get("evidence"))
                ):
                    return False
                wrapper_presences.append(record)
            elif fact_kind == "source_module_initialization_member_metadata":
                if not checks.module_initialized_member_metadata(
                    fact, record.get("target"), record.get("metadata_attribute")
                ):
                    return False
                generated_presences.append(record)
            elif fact_kind == "source_class_creation_method_metadata_presence":
                nested = fact.get("metadata_write")
                if (
                    not isinstance(nested, dict)
                    or nested.get("kind") != "source_bound_method_metadata_write"
                    or nested not in writes
                    or nested.get("target") != record.get("target")
                    or nested.get("attribute") != record.get("metadata_attribute")
                    or nested.get("receiver_class") != hook.get("receiver_class")
                    or fact.get("target") != record.get("target")
                    or fact.get("attribute") != record.get("metadata_attribute")
                    or fact.get("completion") != "normal_return_only"
                    or fact.get("runtime_metadata_confirmed") is not False
                    or not checks.hashes_match(fact)
                    or not checks.assumptions_match(fact)
                ):
                    return False
                generated_presences.append(record)
            elif fact_kind in (
                "source_module_initialization_method_metadata",
                "source_ancestor_class_creation_method_metadata",
            ):
                nested = (
                    fact.get("metadata_write")
                    if fact_kind == "source_module_initialization_method_metadata"
                    else fact.get("creation_fact")
                )
                if (
                    not isinstance(nested, dict)
                    or nested.get("kind") != "source_bound_method_metadata_write"
                    or nested.get("status") != "source_bound"
                    or nested.get("attribute") != record["metadata_attribute"]
                    or nested.get("target") != record.get("target")
                    or nested.get("runtime_execution_confirmed") is not False
                    or not checks.hashes_match(nested)
                    or not checks.assumptions_match(nested)
                    or not checks.identity(nested.get("target"))
                    or not checks.witness(nested.get("call_evidence"), nested.get("caller"))
                ):
                    return False
                if fact_kind == "source_ancestor_class_creation_method_metadata":
                    ancestors = fact.get("ancestor_creation_hooks")
                    previous = binding.get("class_creation_hooks", ())[:hook_index]
                    if (
                        not isinstance(ancestors, (list, tuple))
                        or list(ancestors) != list(previous)
                        or not any(
                            nested == query
                            for prior in previous
                            for query in prior.get("class_metadata_queries", ())
                            if isinstance(prior, dict)
                        )
                    ):
                        return False
                else:
                    effect = fact.get("module_effect")
                    if (
                        not isinstance(effect, dict)
                        or effect.get("status") != "source_bound"
                        or fact.get("metadata_write") != nested
                        or not checks.hashes_match(effect)
                    ):
                        return False
            else:
                return False
            presences.append(record)
        elif kind == "source_bound_method_metadata_write":
            generated = record.get("generated_member_binding")
            target = record.get("target")
            target_name = (
                target.get("qualname", "").rsplit(".", 1)[-1] if isinstance(target, dict) else None
            )
            if (
                not isinstance(record.get("attribute"), str)
                or not record["attribute"].isidentifier()
                or record.get("value_shape")
                not in (
                    "str",
                    "bool",
                    "int",
                    "float",
                    "NoneType",
                    "source_native_value",
                    "native_inspect_signature",
                    "source_class_qualname_suffix",
                )
                or record.get("runtime_execution_confirmed") is not False
                or not checks.identity(record.get("target"))
                or not isinstance(generated, dict)
                or generated.get("kind") != "source_class_creation_lambda_member"
                or generated.get("status") != "source_bound"
                or generated.get("attribute") != target_name
                or generated.get("receiver_class") != hook.get("receiver_class")
                or record.get("definition_evidence") != generated.get("binding_evidence")
                or not checks.hashes_match(generated)
                or not checks.witness(generated.get("binding_evidence"), hook.get("target"))
            ):
                return False
            writes.append(record)
        elif kind == "source_class_creation_metadata_only":
            updates = record.get("metadata_updates")
            if (
                record.get("effect_scope") != "class_member_metadata_only"
                or not checks.identity(record.get("target"))
                or not isinstance(updates, (list, tuple))
                or not updates
                or any(
                    not checks.module_initialized_member_metadata(update)
                    or update.get("updater") != record.get("target")
                    for update in updates
                )
                or not checks.hashes_match(record)
            ):
                return False
            module_metadata_updates.append(record)
        elif kind == "source_bound_class_metadata_query":
            entry, input_binding = record.get("entry_binding"), record.get("input_binding")
            query = record.get("query")
            projection_claimed = isinstance(
                entry, dict
            ) and "source_private_observer_result_projection" in entry.get("assumptions", ())
            if (
                record.get("result_shape") != "native_string_list"
                or not isinstance(query, dict)
                or query.get("status") != "requires_native_class_metadata"
                or query.get("runtime_execution_confirmed") is not False
                or "result" in query
                or not checks.hashes_match(query)
                or not isinstance(entry, dict)
                or entry.get("kind") != "source_native_class_member_query"
                or entry.get("status") != "source_bound"
                or entry.get("runtime_target_confirmed") is not False
                or not checks.hashes_match(entry)
                or not isinstance(input_binding, dict)
                or input_binding.get("kind") != "fresh_source_class_metadata"
                or input_binding.get("phase") != "class_creation_entry"
                or input_binding.get("creation_dependency") != "source_class_creation_prefix"
                or not isinstance(input_binding.get("matching_members"), (list, tuple))
                or not input_binding["matching_members"]
                or ("private_query_results" in entry) != projection_claimed
                or projection_claimed
                and not checks.private_projections_match(entry, record.get("assumptions", ()))
            ):
                return False
            setter_queries.append(record)
        elif kind == "source_bound_class_documentation_helper":
            if (
                record.get("output_shape") != "str"
                or not isinstance(record.get("observer_methods"), (list, tuple))
                or not record["observer_methods"]
                or not isinstance(record.get("observer_queries"), (list, tuple))
                or not checks.hashes_match(record)
            ):
                return False
            documentation.append(record)
        else:
            return False

    # Validate cross-record obligations after collecting the individual metadata effects.
    # 收集各条元数据效果之后，核验需要多条记录共同满足的条件。
    if module_metadata_updates:
        metadata_targets = [
            fact.get("target")
            for record in module_metadata_updates
            for fact in record.get("metadata_updates", ())
        ]
        return (
            len(module_metadata_updates) == 1
            and len(generated_presences) + len(wrapper_presences) == len(presences)
            and all(
                any(record.get("target") == target for target in metadata_targets)
                for record in generated_presences
            )
            and bool(generated_presences)
            and bool(writes)
            and not setter_queries
            and not documentation
        )
    if (
        generated_presences
        and len(generated_presences) == len(presences)
        and not setter_queries
        and not documentation
    ):
        return bool(writes)
    if writes and setter_queries and not presences and not documentation:
        dynamic_inputs = [
            segment.get("input_query")
            for signature in hook.get("signature_creations", ())
            if isinstance(signature, dict)
            for segment in signature.get("dynamic_parameters", ())
            if isinstance(segment, dict)
        ]
        return all(query in dynamic_inputs for query in setter_queries)
    return bool(presences and writes and setter_queries and documentation)
