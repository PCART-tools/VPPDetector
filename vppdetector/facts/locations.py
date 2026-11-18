## @package vppdetector.facts.locations
#  Source coordinates in producer facts and syntax nodes.
#
#
#  Convert syntax and producer evidence to comparable source spans for matching facts to code.
#  将语法及生产者证据转换为可比较的源码范围，以匹配事实与代码。



## Read source coordinates from a producer record
## 从生产者记录中读取源码坐标
#
#  @param value Producer source-coordinate record
#  @return Four source coordinates; missing record fields appear as None
def _location(value):
    return tuple(value.get(name) for name in (
        'lineno', 'col_offset', 'end_lineno', 'end_col_offset',
    ))


## Read the source location attached to an AST node
## 读取AST节点上的源码位置
#
#  @param node AST node supplying the source coordinates
#  @return Node start and end line and column coordinates
def _node_location(node):
    return (node.lineno, node.col_offset, node.end_lineno, node.end_col_offset)
