## @package vppdetector.source.discovery
#  Discover source files and resolve their import-root identities.
#
#
#  Normalize import roots, enumerate Python files and resolve module names and package
#  initializers from source paths.
#  规范化导入根，枚举 Python 文件，并根据源码路径定位模块名和包初始化文件。



from pathlib import Path


## Check whether a path is contained within a source root
## 检查路径是否位于源码根目录内
#
#  @param path Filesystem path of the source being read or checked
#  @param root Source file or directory limiting the lookup
#  @return Whether the path equals the source file or lies under the source directory
def _within_source(path, root):
    if root.is_file():
        return path == root
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


## Check whether a module belongs to an excluded dependency namespace
## 检查模块是否属于排除的依赖命名空间
#
#  @param module Python module name associated with the source
#  @param dependency_modules Module namespaces included as explicit dependencies
#  @return Whether the module equals or is nested under a dependency namespace
def _is_dependency_module(module, dependency_modules):
    return any(
        module == dependency or module.startswith(dependency + ".")
        for dependency in dependency_modules
    )


## Resolve source files belonging to one module name
## 解析指定模块名对应的源码文件
#
#  @param module Python module name associated with the source
#  @param root Source file or directory path defining the primary module lookup scope
#              限定模块主要查找范围的源码文件或目录路径
#  @param import_roots Module roots used to resolve source imports
#  @param dependency_modules Module namespaces included as explicit dependencies
#  @return Sorted tuple of matching source paths, retaining ambiguous candidates
def _module_files(
    module,
    root,
    import_roots,
    dependency_modules=(),
):
    parts = module.split(".")
    if not all(part.isidentifier() for part in parts):
        return ()
    files = set()
    for import_root in import_roots:
        stem = import_root.joinpath(*parts)
        for candidate in (stem.with_suffix(".py"), stem / "__init__.py"):
            if not candidate.is_file():
                continue
            path = candidate.resolve()
            if _within_source(path, root) or _is_dependency_module(module, dependency_modules):
                files.add(path)

    # Preserve ambiguous source candidates for PCResolve, never choose a root
    # or file/package collision as an implicit ownership decision.
    # 将歧义源码候选交给PCResolve处理；不得把导入根或文件/包冲突隐式判为所有权归属。
    return tuple(sorted(files))


## Return package initializer files for an import path
## 返回导入路径对应的包初始化文件
#
#  @param path Filesystem path of the source being read or checked
#  @param root Source file or directory path defining the primary initializer lookup scope
#              限定包初始化文件主要查找范围的源码文件或目录路径
#  @param import_roots Module roots used to resolve source imports
#  @param dependency_modules Module namespaces included as explicit dependencies
#  @param module_name Optional build-local module-name lookup
#  @param resolve_path Optional build-local path resolver
#  @return Iterator of eligible ancestor package initializer paths
def _package_initializers(
    path,
    root,
    import_roots,
    dependency_modules=(),
    *,
    module_name=None,
    resolve_path=None,
):
    module_name = module_name or module_name_for_path
    resolve_path = resolve_path or Path.resolve
    for import_root in import_roots:
        # A standalone file may itself be the inferred import root. There
        # cannot be an ancestor package chain ending at a file path.
        # 单独的源码文件本身可能是推断出的导入根；文件路径不可能再作为祖先包链的末端。
        if path == import_root:
            continue
        try:
            path.relative_to(import_root)
        except ValueError:
            continue
        parent = path.parent
        while parent != import_root:
            candidate = parent / "__init__.py"
            if candidate.is_file():
                resolved = resolve_path(candidate)
                module = module_name(resolved, import_roots)
                if _within_source(resolved, root) or _is_dependency_module(
                    module, dependency_modules
                ):
                    yield resolved
            parent = parent.parent


## Resolve explicit import roots or infer a root from the source layout
## 解析显式导入根目录，或根据源码布局推断根目录
#
#  @param source Library source directory, file, or source context
#  @return Tuple of absolute import roots in their configured order
def normalized_import_roots(source):
    if source.import_roots:
        return tuple(path.resolve() for path in source.import_roots)
    root = source.package_root.resolve()
    if root.is_file():
        return (root.parent,)
    if (root / "__init__.py").is_file():
        return (root.parent,)
    source_root = root / "src"
    if source_root.is_dir():
        return (source_root,)
    return (root,)


## Derive a Python module name from a file and its import roots
## 根据源码文件及导入根目录推导Python模块名
#
#  @param file_path Path of the source file
#  @param import_roots Module roots used to resolve source imports
#  @return Dotted module name, or the file stem if no import root contains the path
def module_name_for_path(file_path, import_roots):
    for import_root in import_roots:
        try:
            relative = file_path.resolve().relative_to(import_root.resolve())
        except ValueError:
            continue
        parts = list(relative.parts)
        if not parts:
            continue

        filename = parts.pop()
        stem = Path(filename).stem
        if stem != "__init__":
            parts.append(stem)
        return ".".join(parts)
    return file_path.stem


## Enumerate Python source files under the requested root
## 枚举指定根目录下的Python源码文件
#
#  @param root Source file to check directly or directory path to enumerate recursively
#              直接检查的源码文件或递归枚举的目录路径
#  @return Iterator over eligible Python paths; a directly supplied .pyi file is included
def _python_files(root):
    if root.is_file():
        if root.suffix in {".py", ".pyi"}:
            yield root
        return
    for path in sorted(root.rglob("*.py")):
        if not any(part in {".git", ".tox", ".venv", "venv", "__pycache__"} for part in path.parts):
            yield path.resolve()
