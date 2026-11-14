## @package vppdetector._source_queries
#  Reuse context-local syntax queries under content and decoding checks.
#  在校验源码内容和解码策略后复用上下文内的语法查询。

from __future__ import annotations

import ast
import tokenize
from dataclasses import dataclass, field


## Cache AST traversal, parent relationships and method locations for one source version.
## 缓存同一源码版本的AST遍历、父子关系及方法位置。
@dataclass
class SourceStructure:
    ## Cached syntax structures shared by queries in one analysis context
    ## 在单次分析上下文中复用的语法结构

    tree: ast.AST
    _nodes: tuple = field(default=(), init=False, repr=False)
    _parents: dict = field(default_factory=dict, init=False, repr=False)
    _methods: object = field(default=None, init=False, repr=False)

    ## Return the cached nodes from one AST traversal
    ## 返回一次AST遍历缓存的节点
    #
    #  @return Tuple of nodes in the cached AST traversal
    def walk(self):
        if not self._nodes:

            # Keep one traversal result for later parent and method lookups.
            # 后续父节点和方法查询复用同一次遍历结果。
            self._nodes = tuple(ast.walk(self.tree))
        return self._nodes

    ## Return the parent node for each cached AST child
    ## 返回缓存AST子节点对应的父节点
    #
    #  @return Mapping from each child node to its parent
    def parents(self):
        if not self._parents:
            self._parents = {child: parent for parent in self.walk()
                             for child in ast.iter_child_nodes(parent)}
        return self._parents

    ## Resolve one method only when its name and source line are unique
    ## 仅在方法名和源码行号唯一时解析该方法
    #
    #  @param identity Source-level identity used for lookup
    #  @return Unique matching function node, or None if absent or ambiguous
    def method(self, identity):
        if self._methods is None:
            self._methods = {}
            for node in self.walk():
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    self._methods.setdefault((node.name, node.lineno), []).append(node)

        # A location lookup is valid only when it identifies one method.
        # 只有位置唯一对应一个方法时才返回结果。
        matches = self._methods.get((identity.qualname.rsplit('.', 1)[-1], identity.lineno), ())
        return matches[0] if len(matches) == 1 else None


## Reuse syntax, never semantic verdicts; reread before every cache lookup.
#
#  复用语法而非语义结论，每次查询缓存前重新读取。
class SourceQueries:
    ## Initialize the object state required by the enclosing class
    ## 初始化所属类所需的对象状态
    #
    #  @param source_store Optional validating store; files are read directly when absent
    def __init__(self, source_store=None):
        self._versions = {}
        self._source_store = source_store

    ## Read source under the requested decoding policy and reuse only a matching AST
    ## 按指定解码策略读取源码，并仅复用匹配的AST
    #
    #  @param path Filesystem path of the source being read or checked
    #  @param policy Source decoding and parsing policy
    #  @return SourceStructure for the current text, or None if reading or parsing fails
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

        # Source text and decoding policy jointly define a reusable AST.
        # 源码内容与解码策略共同决定AST能否复用，任何一项变化都重新解析。
        try:
            structure = SourceStructure(tree if tree is not None else ast.parse(text))
        except (SyntaxError, UnicodeError):
            structure = None
        self._versions[key] = text, structure
        return structure

    ## Resolve one method only when its name and source line are unique
    ## 仅在方法名和源码行号唯一时解析该方法
    #
    #  @param path Filesystem path of the source being read or checked
    #  @param identity Source-level identity used for lookup
    #  @return Unique matching function node, or None if source or match is unavailable
    def method(self, path, identity):
        structure = self.structure(path, 'utf-8-sig')
        if structure is None:
            return None
        return structure.method(identity)
