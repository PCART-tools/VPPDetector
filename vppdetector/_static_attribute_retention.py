"""Consume source proofs of fresh-constructor attribute retention."""

from __future__ import annotations

import ast
from pathlib import Path

from ._program_facts import identity_from_target, source_constructor_entry_binding


def retained_store(analysis, function, statement, destination):
    """Match an executed scalar store to a closed source retention witness."""
    if function.query_class is None or not isinstance(destination, ast.Attribute):
        return None
    binding = source_constructor_entry_binding(analysis, function.query_class)
    if binding is None or binding.get("phase") != "__init__":
        return None
    receiver = binding["implicit_binding"]["parameter"]
    if not isinstance(destination.value, ast.Name) or destination.value.id != receiver:
        return None
    stores = binding.get("retained_instance_attribute_stores", ())
    if not isinstance(stores, (list, tuple)) or len(stores) > 1000:
        return None
    matching = [fact for fact in stores if isinstance(fact, dict)
                and fact.get("attribute") == destination.attr]
    if len(matching) != 1:
        return None
    fact = matching[0]
    witness = fact.get("store_evidence")
    hashes = fact.get("source_hashes")
    checked = fact.get("checked_methods")
    assumptions = fact.get("assumptions")
    if (fact.get("kind") != "retained_instance_attribute_store"
            or fact.get("status") != "source_bound" or fact.get("basis") != "source_snapshot"
            or fact.get("store_protocol") != "ordinary_instance_dict"
            or fact.get("retention_scope") != "normal_constructor_return_after_store"
            or fact.get("runtime_store_confirmed") is not False
            or fact.get("function") != binding["target"]
            or fact.get("receiver_class") != binding["receiver_class"]
            or fact.get("receiver") != receiver or destination.attr.startswith("__")
            or not isinstance(witness, dict) or not isinstance(hashes, dict) or not hashes
            or not isinstance(checked, (list, tuple)) or not 1 <= len(checked) <= 1000
            or not isinstance(assumptions, (list, tuple))
            or not all(isinstance(item, str) for item in assumptions)
            or not set(binding["assumptions"]).issubset(assumptions)
            or "no_external_frame_introspection" not in assumptions):
        return None
    try:
        methods = [identity_from_target(item) for item in checked]
        if (any(item is None for item in methods) or len(set(methods)) != len(methods)
                or function.identity not in methods
                or any(str(item.file_path) not in hashes for item in methods)
                or not set(binding["source_hashes"]).issubset(hashes)
                or any(not isinstance(path, str) or not isinstance(digest, str)
                       or analysis.inputs["sha256"].get(path) != digest
                       for path, digest in hashes.items())
                or Path(witness.get("file_path", "")) != function.identity.file_path
                or any(witness.get(key) != getattr(statement, key) for key in (
                    "lineno", "col_offset", "end_lineno", "end_col_offset"))):
            return None
    except (AttributeError, KeyError, TypeError, ValueError):
        return None
    return fact
