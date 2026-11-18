## @package vppdetector.source.queries
#  Reuse context-local syntax queries under content and decoding checks.
#
#
#  Cache validated module structures and serve syntax, parent and method lookups for a context's
#  fixed source snapshot.
#  缓存已验证的模块结构，为上下文的固定源码快照提供语法、父节点和方法查询。



import ast
import copy
import tokenize
from types import MappingProxyType


## Copy a syntax tree while preserving aliases and isolating mutable metadata.
## 复制语法树，保留别名关系并隔离可变元数据。
#
#  @param tree Source syntax tree to copy
#  @return Independent tree with the same node types and attributes
def _copy_syntax(tree):
    memo = {}

    ## Copy AST nodes and lists as a graph, delegating other metadata to deepcopy.
    ## 按对象图复制 AST 节点与列表，其他元数据交给 deepcopy。
    #
    #  @param value Syntax node, field container, or metadata value
    #  @return Isolated value with shared references preserved
    def clone(value):
        if isinstance(value, ast.AST):
            cached = memo.get(id(value))
            if cached is not None:
                return cached
            result = type(value).__new__(type(value))
            memo[id(value)] = result
            for name, item in vars(value).items():
                setattr(result, name, clone(item))
            return result

        # Use the same memo for lists so the copied tree retains shared references.
        # 列表也使用同一份复制记录，使复制后的语法树保留共享引用。
        if isinstance(value, list):
            cached = memo.get(id(value))
            if cached is not None:
                return cached
            result_list = []
            memo[id(value)] = result_list
            result_list.extend(clone(item) for item in value)
            return result_list
        if type(value) in (str, bytes, int, float, complex, bool, type(None)):
            return value
        return copy.deepcopy(value, memo)

    return clone(tree)


## Cache AST traversal, parent relationships and method locations for one source version.
## 缓存同一源码版本的AST遍历、父子关系及方法位置。
class SourceStructure:
    ## Cached syntax structures shared by queries in one analysis context
    ## 在单次分析上下文中复用的语法结构
    #
    #  @param tree Parsed source module whose structures are indexed
    def __init__(self, tree):
        self.tree = tree
        self._nodes = ()
        self._parents = {}
        self._methods = None

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
    #  @return Read-only mapping from each child node to its parent
    def parents(self):
        if not self._parents:
            self._parents = {
                child: parent for parent in self.walk() for child in ast.iter_child_nodes(parent)
            }
        return MappingProxyType(self._parents)

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
        matches = self._methods.get((identity.qualname.rsplit(".", 1)[-1], identity.lineno), ())
        return matches[0] if len(matches) == 1 else None


## Reuse syntax, never semantic verdicts; reread before every cache lookup.
#
## 复用语法而非语义结论，每次查询缓存前重新读取。
class SourceQueries:
    ## Initialize the object state required by the enclosing class
    ## 初始化所属类所需的对象状态
    #
    #  @param source_store Optional validating store; files are read directly when absent
    def __init__(self, source_store=None):
        self._versions = {}
        self._source_store = source_store

    ## Read source and return the query component's private syntax structure.
    ## 读取源码并返回查询组件内部持有的语法结构。
    #
    #  @param path Filesystem path of the source being read or checked
    #  @param policy Source decoding and parsing policy
    #  @return Private structure, or None if reading or parsing fails
    def _structure(self, path, policy):
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
            elif policy == "tokenize":
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
            parsed = _copy_syntax(tree) if tree is not None else ast.parse(text)
            structure = SourceStructure(parsed)
        except (SyntaxError, UnicodeError):
            structure = None
        self._versions[key] = text, structure
        return structure

    ## Return an isolated syntax structure for the current source text.
    ## 返回当前源码语法结构的独立副本。
    #
    #  @param path Filesystem path of the source being read or checked
    #  @param policy Source decoding and parsing policy
    #  @return Independent structure, or None if reading or parsing fails
    def structure(self, path, policy):
        structure = self._structure(path, policy)
        return SourceStructure(_copy_syntax(structure.tree)) if structure is not None else None

    ## Check whether source syntax can expose the named class to unmodeled code.
    ## 检查源码语法是否可能将指定类暴露给未建模代码。
    #
    #  @param identity Source identity of the class
    #  @return Whether a potentially escaping reference is visible
    def class_binding_may_escape(self, identity):
        if not identity.file_path:
            return False
        structure = self._structure(identity.file_path, "tokenize")
        if structure is None:
            return False
        parents = structure.parents()
        name = identity.qualname.rsplit(".", 1)[-1]
        for node in structure.walk():
            if not isinstance(node, ast.Name) or node.id != name:
                continue
            parent = parents.get(node)
            if isinstance(parent, ast.Call):
                if parent.func is node:
                    # Direct construction does not count as exposing the class object here.
                    # 此处直接构造实例不视为类对象逃逸。
                    continue
                if (
                    node in parent.args
                    and len(parent.args) >= 2
                    and parent.args[1] is node
                    and isinstance(parent.func, ast.Name)
                    and parent.func.id in {"isinstance", "issubclass"}
                ):
                    owner = next(
                        (
                            item
                            for item in structure.walk()
                            if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))
                            and item.end_lineno is not None
                            and item.lineno <= node.lineno <= item.end_lineno
                        ),
                        None,
                    )
                    shadowed = bool(
                        owner
                        and (
                            any(
                                arg.arg == parent.func.id
                                for arg in (
                                    *owner.args.posonlyargs,
                                    *owner.args.args,
                                    *owner.args.kwonlyargs,
                                    *((owner.args.vararg,) if owner.args.vararg else ()),
                                    *((owner.args.kwarg,) if owner.args.kwarg else ()),
                                )
                            )
                            or any(
                                isinstance(item, (ast.Assign, ast.AnnAssign, ast.NamedExpr))
                                and any(
                                    isinstance(target, ast.Name) and target.id == parent.func.id
                                    for target in ast.walk(item)
                                )
                                for item in ast.walk(owner)
                            )
                        )
                    )
                    if not shadowed:
                        continue
                return True
            if isinstance(parent, ast.Attribute) and parent.value is node:
                if parent.attr not in {"__dict__", "__bases__", "__mro__", "__subclasses__"}:
                    # A named member lookup does not retain the class reference.
                    # 具名成员查找不会保留对类对象的引用。
                    continue

            if isinstance(parent, ast.ClassDef) and node in parent.bases:
                # Inheritance alone does not expose the class to arbitrary code.
                # 单凭继承关系不能认定类对象会暴露给任意代码。
                continue
            return True
        return False

    ## Check whether an indexed class has the bounded plain-class syntax.
    ## 检查已索引类是否具有受支持的普通类语法。
    #
    #  @param identity Source identity of the class
    #  @return Whether its source proves the required syntax
    def is_plain_class(self, identity):
        if identity.file_path is None:
            return False
        structure = self._structure(identity.file_path, "utf-8-sig")
        if structure is None:
            return False
        class_name = identity.qualname.rsplit(".", 1)[-1]
        classes = [
            item
            for item in structure.walk()
            if isinstance(item, ast.ClassDef)
            and item.name == class_name
            and item.lineno == identity.lineno
        ]
        if len(classes) != 1 or not isinstance(structure.tree, ast.Module):
            return False
        class_node = classes[0]
        from pcresolve.scope_facts import statement_scope_facts

        module_bindings = statement_scope_facts(structure.tree.body).bound
        return not (
            class_node.decorator_list
            or class_node.keywords
            or any(
                not isinstance(base, ast.Name) or base.id != "object" for base in class_node.bases
            )
            or class_node.bases
            and "object" in module_bindings
            or any(
                isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)) and item.name == "__new__"
                for item in class_node.body
            )
        )

    ## Resolve one method only when its name and source line are unique
    ## 仅在方法名和源码行号唯一时解析该方法
    #
    #  @param path Filesystem path of the source being read or checked
    #  @param identity Source-level identity used for lookup
    #  @return Independent matching function node, or None if source or match is unavailable
    def method(
        self,
        path,
        identity,
    ):
        structure = self._structure(path, "utf-8-sig")
        if structure is None:
            return None
        method = structure.method(identity)
        if method is None:
            return None
        return _copy_syntax(method)
