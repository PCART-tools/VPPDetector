"""Small source proofs for callable-object decorators that preserve functions."""

from __future__ import annotations

import ast
import hashlib
from pathlib import Path

from ._program_facts import identity_from_target


def _same(node, source):
    try:
        expected = ast.parse(source).body
    except SyntaxError:
        return False
    return ast.dump(ast.Module(body=[node], type_ignores=[]), include_attributes=False) == ast.dump(
        ast.Module(body=expected, type_ignores=[]), include_attributes=False
    )


def _source_node(context, identity, node_type):
    candidates = [
        item for item in context.index.functions
        if item.identity.module == identity.module
        and item.identity.qualname == identity.qualname
        and (identity.file_path is None or item.identity.file_path == identity.file_path)
        and (not identity.lineno or item.identity.lineno == identity.lineno)
        and isinstance(item.node, node_type)
    ]
    return candidates[0] if len(candidates) == 1 else None


def matplotlib_docstring_function_binding(context, analysis, function, fact):
    """Prove Matplotlib's docstring callable-object decorator returns this function.

    Matplotlib 3.5 used ``docstring.dedent_interpd``; later releases moved the
    same source protocol to ``_docstring.dedent_interpd``. Accept either exact
    import path, while keeping the proof bound to the decorator implementation
    and source snapshot. The class-only branch is unreachable for a function.
    """
    decorators = [node for node in function.node.decorator_list
                  if isinstance(node, ast.Attribute) and node.attr == 'dedent_interpd'
                  and isinstance(node.value, ast.Name)
                  and node.value.id in ('docstring', '_docstring')]
    if len(decorators) != 1:
        return None
    decorator = decorators[0]
    alias = decorator.value.id
    module = 'matplotlib.' + ('docstring' if alias == 'docstring' else '_docstring')
    raw_target = fact.get("target")
    target = identity_from_target(raw_target) if raw_target is not None else None
    if (function.identity.module != "matplotlib.patches"
            or identity_from_target(fact.get("function")) != function.identity
            or target is not None and (target.module != module
                or target.qualname != "_ArtistPropertiesSubstitution.__call__")
            or fact.get("identity_status") not in ("preserved", "unknown")
            or fact.get("basis") != "source_snapshot"
            or fact.get("completion") != "normal_return"
            or fact.get("runtime_target_confirmed") is not False):
        return None

    expression = fact.get('expression')
    if (not isinstance(expression, dict)
            or expression.get('file_path') != str(function.identity.file_path)
            or any(expression.get(key) != getattr(decorator, key) for key in (
                'lineno', 'col_offset', 'end_lineno', 'end_col_offset'))):
        return None

    hashes = analysis.inputs.get("sha256", {})
    fact_hashes = fact.get("source_hashes")
    if (not isinstance(fact_hashes, dict) or not fact_hashes
            or any(hashes.get(path) != digest for path, digest in fact_hashes.items())):
        return None
    patch_path = function.identity.file_path
    doc_filename = 'docstring.py' if alias == 'docstring' else '_docstring.py'
    doc_path = next((Path(path) for path in hashes
                     if Path(path).as_posix().endswith('/matplotlib/' + doc_filename)), None)
    if (doc_path is None or str(patch_path) not in hashes
            or str(doc_path) not in hashes
            or str(patch_path) not in fact_hashes
            or target is not None and (target.file_path is None
                or target.file_path.resolve() != doc_path.resolve())):
        return None
    try:
        for path, digest in hashes.items():
            with Path(path).open(encoding="utf-8-sig") as stream:
                actual = hashlib.sha256(stream.read().encode("utf-8")).hexdigest()
            if actual != digest:
                return None
        patch_tree = ast.parse(patch_path.read_text(encoding="utf-8-sig"))
        doc_tree = ast.parse(doc_path.read_text(encoding="utf-8-sig"))
    except (OSError, UnicodeError, SyntaxError, RecursionError):
        return None

    # The decorator's module object is imported directly and not rebound in the
    # defining module's top-level namespace.
    imports = [node for node in patch_tree.body if isinstance(node, ast.ImportFrom)
               and node.level == 1 and node.module is None
               and any(item.name == alias and item.asname is None for item in node.names)]
    if len(imports) != 1 or any(
            isinstance(node, (ast.Assign, ast.AnnAssign, ast.NamedExpr, ast.FunctionDef,
                              ast.AsyncFunctionDef, ast.ClassDef, ast.Import, ast.ImportFrom))
            and node is not imports[0]
            and alias in _bound_names(node)
            for node in patch_tree.body):
        return None

    alias_assignments = [node for node in doc_tree.body if isinstance(node, ast.Assign)
                         and _bound_names(node) == {"dedent_interpd", "interpd"}]
    if (len(alias_assignments) != 1
            or not _same(alias_assignments[0],
                         "dedent_interpd = interpd = _ArtistPropertiesSubstitution()")
            or any(_bound_names(node) & {"dedent_interpd", "interpd"}
                   for node in doc_tree.body if node is not alias_assignments[0])):
        return None
    classes = {node.name: node for node in doc_tree.body if isinstance(node, ast.ClassDef)}
    decorated = classes.get("_ArtistPropertiesSubstitution")
    base = classes.get("Substitution")
    if (decorated is None or base is None or decorated.decorator_list or base.decorator_list
            or len(decorated.bases) != 1 or not isinstance(decorated.bases[0], ast.Name)
            or decorated.bases[0].id != "Substitution"):
        return None
    decorated_call = [node for node in decorated.body
                      if isinstance(node, ast.FunctionDef) and node.name == "__call__"]
    base_call = [node for node in base.body
                 if isinstance(node, ast.FunctionDef) and node.name == "__call__"]
    if (len(decorated_call) != 1 or len(base_call) != 1
            or not _same(decorated_call[0], """def __call__(self, obj):
    super().__call__(obj)
    if isinstance(obj, type) and obj.__init__ != object.__init__:
        self(obj.__init__)
    return obj""")
            or not _same(base_call[0], """def __call__(self, func):
    if func.__doc__:
        func.__doc__ = inspect.cleandoc(func.__doc__) % self.params
    return func""")):
        return None

    # Ensure stdlib inspect and the relevant builtin names are not rebound by
    # this module's top-level source.
    inspect_imports = [node for node in doc_tree.body if isinstance(node, ast.Import)
                       and any(alias.name == "inspect" and alias.asname is None
                               for alias in node.names)]
    if (len(inspect_imports) != 1
            or any("inspect" in _bound_names(node) for node in doc_tree.body
                   if node is not inspect_imports[0])
            or any(name in _bound_names(node) for node in doc_tree.body
                   for name in ("isinstance", "type", "object"))):
        return None

    assumptions = (
        "source_snapshot_bindings_hold", "standard_builtin_namespace_preserved",
        "standard_library_inspect_binding", "no_external_monkeypatch_or_import_hook",
        "module_initialization_completed_before_query",
    )
    return {"assumptions": assumptions, "source_hashes": hashes,
            "decorator_target": fact["target"], "base_method": "Substitution.__call__",
            "returned_object": "original_function", "mutated_function_attribute": "__doc__"}


def matplotlib_keyword_only_method_binding(context, analysis, function, positional_count):
    """Prove a bounded Matplotlib keyword-only decorator forwards unchanged.

    The same proof applies when the method also has the known docstring
    decorator, which preserves the wrapper object on normal function calls.
    """
    if (function.identity.module != "matplotlib.patches"
            or type(positional_count) is not int or positional_count < 0):
        return None
    keyword_only = [node for node in function.node.decorator_list
                    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                    and node.func.attr == 'make_keyword_only'
                    and isinstance(node.func.value, ast.Name)
                    and node.func.value.id == '_api']
    docstring = [node for node in function.node.decorator_list
                 if isinstance(node, ast.Attribute) and node.attr == 'dedent_interpd'
                 and isinstance(node.value, ast.Name) and node.value.id == '_docstring']
    if len(keyword_only) != 1 or len(function.node.decorator_list) != 1 + len(docstring):
        return None
    decorator = keyword_only[0]
    if (not isinstance(decorator, ast.Call) or len(decorator.args) != 1
            or not isinstance(decorator.args[0], ast.Constant)
            or decorator.args[0].value != "3.6"
            or len(decorator.keywords) != 1 or decorator.keywords[0].arg != "name"
            or not isinstance(decorator.keywords[0].value, ast.Constant)
            or not isinstance(decorator.keywords[0].value.value, str)):
        return None
    name = decorator.keywords[0].value.value
    summaries = [item for item in analysis.functions
                 if item.get("function", {}).get("module") == function.identity.module
                 and item.get("function", {}).get("qualname") == function.identity.qualname]
    effects = summaries[0].get("decorator_effects", ()) if len(summaries) == 1 else ()
    def matches_expression(effect, node):
        expression = effect.get('expression', {}) if isinstance(effect, dict) else {}
        return (expression.get('file_path') == str(function.identity.file_path)
                and all(expression.get(key) == getattr(node, key) for key in (
                    'lineno', 'col_offset', 'end_lineno', 'end_col_offset')))

    keyword_effects = [effect for effect in effects if matches_expression(effect, decorator)]
    effect = keyword_effects[0] if len(keyword_effects) == 1 else {}
    expression = effect.get("expression", {})
    if (len(keyword_effects) != 1 or effect.get("identity_status") != "unknown"
            or expression.get("file_path") != str(function.identity.file_path)
            or any(expression.get(key) != getattr(decorator, key) for key in (
                "lineno", "col_offset", "end_lineno", "end_col_offset"))
            or not any(boundary.get("reason") == "decorator_factory_unproven"
                       and identity_from_target(boundary.get("function")) is not None
                       and identity_from_target(boundary["function"]).module
                           == "matplotlib._api.deprecation"
                       and identity_from_target(boundary["function"]).qualname
                           == "make_keyword_only"
                       for boundary in effect.get("boundaries", ()))):
        return None
    if docstring:
        doc_effects = [item for item in effects if matches_expression(item, docstring[0])]
        if (len(doc_effects) != 1
                or matplotlib_docstring_function_binding(
                    context, analysis, function, doc_effects[0]) is None):
            return None
    factory_identity = type(function.identity)(
        "matplotlib._api.deprecation", "make_keyword_only")
    factory = context.index.find(factory_identity)
    if (factory is None or factory.node.decorator_list
            or not isinstance(factory.node, ast.FunctionDef)):
        return None
    body = [node for node in factory.node.body if not (
        isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant)
        and isinstance(node.value.value, str))]
    wrappers = [node for node in body if isinstance(node, ast.FunctionDef)
                and node.name == "wrapper"]
    if (len(wrappers) != 1 or [arg.arg for arg in factory.node.args.args]
            != ["since", "name", "func"] or factory.node.args.posonlyargs
            or factory.node.args.kwonlyargs or factory.node.args.vararg
            or factory.node.args.kwarg or len(factory.node.args.defaults) != 1
            or not isinstance(factory.node.args.defaults[0], ast.Constant)
            or factory.node.args.defaults[0].value is not None or len(body) != 13
            or not _same(body[0], "decorator = functools.partial(make_keyword_only, since, name)")
            or not _same(body[1], "if func is None:\n    return decorator")
            or not _same(body[2], "signature = inspect.signature(func)")
            or not isinstance(body[5], ast.Assert)
            or not _same(body[6], "names = [*signature.parameters]")
            or not _same(body[7], "name_idx = names.index(name)")
            or not isinstance(body[-1], ast.Return)
            or not isinstance(body[-1].value, ast.Name) or body[-1].value.id != "wrapper"):
        return None
    wrapper = wrappers[0]
    if (len(wrapper.decorator_list) != 1
            or ast.unparse(wrapper.decorator_list[0]) != "functools.wraps(func)"
            or not isinstance(wrapper.args.vararg, ast.arg)
            or wrapper.args.vararg.arg != "args"
            or not isinstance(wrapper.args.kwarg, ast.arg)
            or wrapper.args.kwarg.arg != "kwargs"
            or wrapper.args.args or wrapper.args.posonlyargs or wrapper.args.kwonlyargs):
        return None
    statements = [node for node in wrapper.body if not (
        isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant)
        and isinstance(node.value.value, str))]
    if (len(statements) != 2 or not isinstance(statements[0], ast.If)
            or statements[0].orelse or len(statements[0].body) != 1
            or not isinstance(statements[0].body[0], ast.Expr)
            or not isinstance(statements[0].body[0].value, ast.Call)
            or ast.unparse(statements[0].body[0].value.func) != "warn_deprecated"
            or not isinstance(statements[1], ast.Return)
            or not isinstance(statements[1].value, ast.Call)):
        return None
    guard = statements[0].test
    if (not isinstance(guard, ast.Compare) or len(guard.ops) != 1
            or not isinstance(guard.ops[0], ast.Gt)
            or not isinstance(guard.left, ast.Call)
            or ast.unparse(guard.left.func) != "len"
            or len(guard.left.args) != 1
            or not isinstance(guard.left.args[0], ast.Name)
            or guard.left.args[0].id != "args"
            or len(guard.comparators) != 1
            or not isinstance(guard.comparators[0], ast.Name)
            or guard.comparators[0].id != "name_idx"):
        return None
    forwarded = statements[1].value
    if (not isinstance(forwarded.func, ast.Name) or forwarded.func.id != "func"
            or len(forwarded.args) != 1 or not isinstance(forwarded.args[0], ast.Starred)
            or not isinstance(forwarded.args[0].value, ast.Name)
            or forwarded.args[0].value.id != "args"
            or len(forwarded.keywords) != 1 or forwarded.keywords[0].arg is not None
            or not isinstance(forwarded.keywords[0].value, ast.Name)
            or forwarded.keywords[0].value.id != "kwargs"):
        return None
    parameters = function.node.args.posonlyargs + function.node.args.args
    names = [parameter.arg for parameter in parameters]
    if names.count(name) != 1:
        return None
    warning_guard_false = positional_count <= names.index(name)
    hashes = analysis.inputs.get("sha256", {})
    if (not isinstance(hashes, dict)
            or str(function.identity.file_path) not in hashes
            or str(factory.identity.file_path) not in hashes
            or any(not isinstance(path, str) or not isinstance(digest, str)
                   or len(digest) != 64 for path, digest in hashes.items())):
        return None
    try:
        factory_tree = ast.parse(factory.identity.file_path.read_text(encoding="utf-8-sig"))
    except (OSError, UnicodeError, SyntaxError, RecursionError):
        return None
    imports = [node for node in factory_tree.body if isinstance(node, ast.Import)
               and any(alias.name == "functools" and alias.asname is None for alias in node.names)]
    if (len(imports) != 1
            or str(factory.identity.file_path) not in hashes
            or hashes[str(factory.identity.file_path)] != analysis.inputs["sha256"].get(
                str(factory.identity.file_path))):
        return None
    assumptions = [
        "source_snapshot_bindings_hold", "standard_library_partial_protocol",
        "standard_library_functools_wraps_protocol", "no_external_monkeypatch_or_import_hook",
        "source_wrapper_forwarding_on_normal_return",
    ]
    if warning_guard_false:
        assumptions.append('keyword_only_warning_guard_false')
    else:
        assumptions.append('default_warning_filters_allow_deprecation_warnings')
    return {"assumptions": tuple(assumptions),
        "source_hashes": hashes, "factory": factory.identity,
        "wrapper_evidence": wrapper, "warning_guard_false": warning_guard_false,
        "warning_branch_taken": not warning_guard_false}


def _bound_names(node):
    names = set()
    if isinstance(node, ast.Assign):
        targets = node.targets
    elif isinstance(node, (ast.AnnAssign, ast.NamedExpr)):
        targets = [node.target]
    elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        return {node.name}
    elif isinstance(node, ast.Import):
        return {alias.asname or alias.name.partition(".")[0] for alias in node.names}
    elif isinstance(node, ast.ImportFrom):
        return {alias.asname or alias.name for alias in node.names}
    else:
        return names
    for target in targets:
        names.update(child.id for child in ast.walk(target) if isinstance(child, ast.Name))
    return names
