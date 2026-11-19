## @package vppdetector.facts.scope
#  Small source scope and execution facts.
#
#
#  Identify lexical captures and distinguish immediately interpreted bodies from deferred
#  execution.
#  识别词法捕获，并区分立即解释的函数体和延迟执行。



import ast


## Resolve names captured from an enclosing scope using available producer facts.
## 使用可用的生产者事实解析从外层作用域捕获的名称。
#
#  @param node Function syntax node whose captures are inspected
#  @param enclosing Names available in the enclosing scope
#  @return Captured names reported by the producer
def capture_names(node, enclosing):
    try:
        from pcresolve.scope_facts import transitive_captured_names
    except ImportError:
        from pcresolve.scope_facts import captured_names, function_scope_facts

        scope_facts = function_scope_facts(node)
        capture = captured_names
        return capture(scope_facts, enclosing)
    capture = transitive_captured_names
    return capture(node, enclosing)


## Check whether a function body executes immediately rather than yielding.
## 检查函数体是否立即执行而非产生生成器。
#
#  @param node Source syntax node to inspect
#  @return True for a synchronous function without a yield in its own body
def immediate_body(node):
    if not isinstance(node, ast.FunctionDef):
        return False

    # Nested definitions own their yields. Inspect only the current function's execution.
    # 嵌套定义中的 yield 归其自身所有，只检查当前函数体的执行。
    pending = list(node.body)
    while pending:
        child = pending.pop()
        if isinstance(child, (ast.Yield, ast.YieldFrom)):
            return False
        if not isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
            pending.extend(ast.iter_child_nodes(child))
    return True
