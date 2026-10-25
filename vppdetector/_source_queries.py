"""Context-local syntax queries with content and decoding-policy isolation."""

from __future__ import annotations

import ast
import tokenize
from dataclasses import dataclass, field


@dataclass
class SourceStructure:
    tree: ast.AST
    _nodes: tuple = field(default=(), init=False, repr=False)
    _parents: dict = field(default_factory=dict, init=False, repr=False)
    _methods: object = field(default=None, init=False, repr=False)

    def walk(self):
        if not self._nodes:
            self._nodes = tuple(ast.walk(self.tree))
        return self._nodes

    def parents(self):
        if not self._parents:
            self._parents = {child: parent for parent in self.walk()
                             for child in ast.iter_child_nodes(parent)}
        return self._parents

    def method(self, identity):
        if self._methods is None:
            self._methods = {}
            for node in self.walk():
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    self._methods.setdefault((node.name, node.lineno), []).append(node)
        matches = self._methods.get((identity.qualname.rsplit('.', 1)[-1], identity.lineno), ())
        return matches[0] if len(matches) == 1 else None


class SourceQueries:
    """Reuse syntax, never semantic verdicts; reread before every cache lookup."""

    def __init__(self, source_store=None):
        self._versions = {}
        self._source_store = source_store

    def structure(self, path, policy):
        key = str(path), policy
        try:
            tree = None
            if self._source_store is not None:
                from pcresolve.source_snapshot import SourceReadPolicy

                document = self._source_store.read_document(str(path), SourceReadPolicy(policy))
                if document.error is not None:
                    self._versions.pop(key, None)
                    return None
                text, tree = document.text, document.tree
            elif policy == 'tokenize':
                with tokenize.open(path) as stream:
                    text = stream.read()
            else:
                with open(path, encoding=policy) as stream:
                    text = stream.read()
        except (OSError, UnicodeError, SyntaxError):
            self._versions.pop(key, None)
            return None
        cached = self._versions.get(key)
        if cached is not None and cached[0] == text:
            return cached[1]
        try:
            structure = SourceStructure(tree if tree is not None else ast.parse(text))
        except (SyntaxError, UnicodeError):
            structure = None
        self._versions[key] = text, structure
        return structure

    def method(self, path, identity):
        structure = self.structure(path, 'utf-8-sig')
        if structure is None:
            return None
        return structure.method(identity)
