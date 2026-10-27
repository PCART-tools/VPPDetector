## @file legacy_vppdetector.py
#  Original prototype scanner retained for reproducibility.
#  为复现早期研究结果而保留的原型扫描器。

"""Original research-prototype scanner retained for reproducibility.

New integrations should import the :mod:`vppdetector` package instead.
"""

import os
import ast
import copy
import json
import time
import chardet
from Path.getPath import Path
from multiprocessing import Pool
from Tool.tool import cmp


# 根据位置找定义, 并且不能含有*args或kwargs
## Check whether a candidate definition accepts the forwarded variadic arguments.
## 检查候选定义是否接受转发的可变参数实参。
class DefVisitor(ast.NodeVisitor):
    ## Initialize the object state required by the enclosing class
    ## 初始化所属类所需的对象状态
    #
    #  @return None.
    def __init__(self):
        self.target = False

    ## Set the source line used to locate a candidate definition
    ## 设置用于定位候选定义的源码行号
    #
    #  @param position Original or selected positional index.
    #  @return None.
    def setPos(self, position):
        self._position = position

    ## Set which variadic channels the candidate must reject
    ## 设置候选定义需要拒绝的可变参数通道
    #
    #  @param varargFlag Whether positional variadic values are forwarded.
    #  @param kwargFlag Whether keyword variadic values are forwarded.
    #  @return None.
    def setFlag(self, varargFlag, kwargFlag):
        self._varargFlag = varargFlag
        self._kwargFlag = kwargFlag

    ## Inspect a class node while resolving the requested definition
    ## 检查类节点并解析请求的定义
    #
    #  @param node AST node or source expression being analyzed.
    #  @return None.
    def visit_ClassDef(self, node):
        if node.lineno == self._position:
            flag1 = False
            flag2 = False
            for n in ast.iter_child_nodes(node):
                if isinstance(n, ast.FunctionDef):
                    if n.name == "__init__":
                        if self._varargFlag:
                            try:
                                n.args.vararg.arg
                            except:
                                flag1 = True

                        if self._kwargFlag:
                            try:
                                n.args.kwarg.arg
                            except:
                                flag2 = True


                        self.target = flag1 or flag2
                        return

        if not self.target:
            self.generic_visit(node)

    ## Inspect a function node while collecting matching API facts
    ## 检查函数节点并收集匹配的API事实
    #
    #  @param node AST node or source expression being analyzed.
    #  @return None.
    def visit_FunctionDef(self, node):
        if node.lineno == self._position:
            flag1 = False
            flag2 = False
            if self._varargFlag:
                try:
                    node.args.vararg.arg
                except:
                    flag1 = True

            if self._kwargFlag:
                try:
                    node.args.kwarg.arg
                except:
                    flag2 = True

            self.target = flag1 or flag2
            return

        if not self.target:
            self.generic_visit(node)


# 寻找调用的API中含有*args或**kwargs的
## Collect source calls that forward a tracked variadic parameter.
## 收集转发已跟踪可变参数的源码调用。
class CallVisitor:
    ## Initialize the object state required by the enclosing class
    ## 初始化所属类所需的对象状态
    #
    #  @return None.
    def __init__(self):
        self.callDict = {}

    ## Clear the accumulated visitor state before the next query
    ## 在下一次查询前清空访问器累积状态
    #
    #  @return None.
    def clean(self):
        self.callDict.clear()

    ## Set the variadic parameter names followed by the visitor
    ## 设置访问器跟踪的可变参数名称
    #
    #  @param varargName Name of the tracked positional variadic parameter.
    #  @param kwargName Name of the tracked keyword variadic parameter.
    #  @return None.
    def setName(self, varargName, kwargName):
        self._varargName = varargName
        self._kwargName = kwargName

    ## Collect calls that forward the tracked variadic arguments
    ## 收集转发已跟踪可变参数实参的调用
    #
    #  @param node AST node or source expression being analyzed.
    #  @return Result of the `dfsVisit` operation.
    def dfsVisit(self, node):
        if isinstance(node, ast.Call):
            varargFlag = False
            kwargFlag = False
            self.callName = ast.unparse(node.func)
            for arg in node.args:
                paraName = ast.unparse(arg)
                if paraName == f"*{self._varargName}":
                    varargFlag = True
                    break

            for keyword in node.keywords:
                paraName = ast.unparse(keyword)
                if paraName == f"**{self._kwargName}":
                    kwargFlag = True
                    break

            if varargFlag or kwargFlag:
                callName = ast.unparse(node.func)
                if callName not in self.callDict:
                    self.callDict[callName] = (node.lineno, varargFlag, kwargFlag)

                # print(callName, node.lineno)
                return

        for n in ast.iter_child_nodes(node):
            self.dfsVisit(n)


# 根据函数名来找对应的位置，仅在当前文件中查找, API可能是类，也可能是函数
## Locate matching class and function definitions in one source tree.
## 在单个源码树中定位匹配的类和函数定义。
class ClassAndFunctionVisitor(ast.NodeVisitor):
    ## Initialize the object state required by the enclosing class
    ## 初始化所属类所需的对象状态
    #
    #  @return None.
    def __init__(self):
        self.positionLst = []
        self.noFindFlag = False

    ## Clear the accumulated visitor state before the next query
    ## 在下一次查询前清空访问器累积状态
    #
    #  @return None.
    def clean(self):
        self.positionLst.clear()

    ## Set the API name used by subsequent source lookups
    ## 设置后续源码查找所用的API名称
    #
    #  @param name Name to match or validate in the current scope.
    #  @return None.
    def setAPIName(self, name):
        self.APIName = name

    ## Inspect a class node while resolving the requested definition
    ## 检查类节点并解析请求的定义
    #
    #  @param node AST node or source expression being analyzed.
    #  @return None.
    def visit_ClassDef(self, node):
        if node.name == self.APIName:
            self.positionLst.append(node.lineno)
        self.generic_visit(node)

    # 从类中找定义的API
    ## Collect matching methods from class definitions in the source tree
    ## 从源码树中的类定义收集匹配方法
    #
    #  @param root AST root or source root used for lookup.
    #  @return Result of the `visitClasDef` operation.
    def visitClasDef(self, root):
        for node in ast.iter_child_nodes(root):
            if isinstance(node, ast.ClassDef):
                for n in ast.iter_child_nodes(node):
                    if isinstance(n, ast.FunctionDef):
                        if n.name == self.APIName:
                            flag = 1
                            for d in n.decorator_list:
                                if "overload" in ast.unparse(d):
                                    flag = 0
                                    break
                            if flag:
                                self.positionLst.append(n.lineno)

    # 找普通的API
    ## Collect matching module-level function definitions
    ## 收集匹配的模块级函数定义
    #
    #  @param root AST root or source root used for lookup.
    #  @return Result of the `visitFunctionDef` operation.
    def visitFunctionDef(self, root):
        for node in ast.iter_child_nodes(root):
            if isinstance(node, ast.FunctionDef):
                if node.name == self.APIName:
                    flag = 1
                    for d in node.decorator_list:

                        # 若API定义中含有overload装饰器也排除
                        if "overload" in ast.unparse(d):
                            flag = 0
                            break
                    if flag:
                        self.positionLst.append(node.lineno)

    ## Inspect a function node while collecting matching API facts
    ## 检查函数节点并收集匹配的API事实
    #
    #  @param node AST node or source expression being analyzed.
    #  @return None.
    def visit_FunctionDef(self, node):
        if node.name == self.APIName:
            flag = 1
            for d in node.decorator_list:
                if "overload" in ast.unparse(d):
                    flag = 0
                    break
            if flag:
                self.positionLst.append(node.lineno)
        self.generic_visit(node)


## Find variadic functions whose forwarded arguments reach fixed signatures.
## 查找将可变实参转发到固定签名的可变参数函数。
class FunctionDefVisitor(ast.NodeVisitor):
    ## Initialize the object state required by the enclosing class
    ## 初始化所属类所需的对象状态
    #
    #  @return None.
    def __init__(self):
        self.lst = []
        self.defWithVariadicParaLst = []
        self._callVisitor = CallVisitor()
        self._findAPIPosition = ClassAndFunctionVisitor()
        self._callDefVisitor = DefVisitor()
        self.cnt1 = 0
        self.cnt2 = 0
        self.cnt3 = 0
        self._classStack = []
        self._classNodeStack = []

    ## Set the AST root used for source definition lookup
    ## 设置用于源码定义查找的AST根节点
    #
    #  @param root AST root or source root used for lookup.
    #  @return None.
    def setRoot(self, root):
        self._root = root

    ## Set the module prefix used to qualify discovered APIs
    ## 设置为发现的API添加限定名所用的模块前缀
    #
    #  @param prefix Value named `prefix` supplied by the enclosing analysis.
    #  @return None.
    def setPrefix(self, prefix):
        self._prefix =  prefix

    ## Store the API evolution mapping for this legacy visitor
    ## 保存旧版访问器使用的API演变映射
    #
    #  @param evolutionDict Legacy API evolution mapping.
    #  @return None.
    def setEvolutionDict(self, evolutionDict):
        self._evolutionDict = evolutionDict

    ## Clear the accumulated visitor state before the next query
    ## 在下一次查询前清空访问器累积状态
    #
    #  @return None.
    def clean(self):
        self._callVisitor.clean()
        self._findAPIPosition.clean()

    ## Reset the analysis counters between library versions
    ## 在不同库版本之间重置分析计数
    #
    #  @return None.
    def cleanCnt(self):
        self.cnt1 = 0
        self.cnt2 = 0
        self.cnt3 = 0

    ## Find source definitions matching a call name in the selected scope
    ## 在指定作用域中查找与调用名称匹配的源码定义
    #
    #  @param callName Qualified expression naming the called API.
    #  @param node AST node or source expression being analyzed.
    #  @param flag Lookup mode selecting the source scope.
    #  @return Result of the `findCallDef` operation.
    def findCallDef(self, callName, node, flag = 0):
        positionLst = []

        # 寻找callAPI定义的位置（可能会找到多个同名的API）
        self._findAPIPosition.setAPIName(callName)
        if flag == 0:
            self._findAPIPosition.visit(node)
        elif flag == 1:
            self._findAPIPosition.visitClasDef(node)
        else:
            self._findAPIPosition.visitFunctionDef(node)

        positionLst = copy.deepcopy(self._findAPIPosition.positionLst)
        self._findAPIPosition.positionLst.clear()
        return positionLst

    ## Keep definitions that lack a required variadic parameter channel
    ## 筛选缺少所需可变参数通道的定义
    #
    #  @param positionLst Source positions of candidate definitions.
    #  @param varargFlag Whether positional variadic values are forwarded.
    #  @param kwargFlag Whether keyword variadic values are forwarded.
    #  @return Result of the `findNoKwargCallDef` operation.
    def findNoKwargCallDef(self, positionLst, varargFlag, kwargFlag):
        ansLst = []

        # 根据位置查找callAPI的定义
        self._callDefVisitor.setFlag(varargFlag, kwargFlag)
        for pos in positionLst:
            self._callDefVisitor.setPos(pos)
            self._callDefVisitor.visit(self._root)
            if self._callDefVisitor.target:
                ansLst.append(pos)
                self._callDefVisitor.target = False

        return ansLst

    ## Inspect a class node while resolving the requested definition
    ## 检查类节点并解析请求的定义
    #
    #  @param node AST node or source expression being analyzed.
    #  @return None.
    def visit_ClassDef(self, node):

        # 进入一个类定义时，当前类名进栈
        self._classStack.append(node.name)
        self._classNodeStack.append(node)
        self.generic_visit(node)

        # 离开类定义时，从栈中弹出类名和类节点
        self._classStack.pop()
        self._classNodeStack.pop()

    ## Inspect a function node while collecting matching API facts
    ## 检查函数节点并收集匹配的API事实
    #
    #  @param node AST node or source expression being analyzed.
    #  @return None.
    def visit_FunctionDef(self, node):

        # 获取API定义中的参数
        paraLst = []
        for para in node.args.args + node.args.kwonlyargs:
            paraLst.append(ast.unparse(para))

        varargName = ""
        kwargName = ""
        varargFlag = True
        kwargFlag = True
        try:
            varargName = node.args.vararg.arg
        except:
            varargFlag = False

        try:
            kwargName = node.args.kwarg.arg
        except:
            kwargFlag = False

        # step1: 找出参数定义中含有可变参数的API
        if varargFlag or kwargFlag:
            currentClass = '.'.join(self._classStack) if self._classStack else ""
            if currentClass:
                fullPathName = self._prefix + '.' + currentClass + '.' + node.name
            else:
                fullPathName = self._prefix + '.' + node.name
            self.cnt1 += 1
            self.defWithVariadicParaLst.append({fullPathName: node.lineno})

            # step2: 再从函数体内找被传递*args或**kwargs的调用API
            self._callVisitor.setName(varargName, kwargName)
            self._callVisitor.dfsVisit(node)
            self.cnt2 += len(self._callVisitor.callDict)
            for callName, val in self._callVisitor.callDict.items():

                # 如果调用API来自参数，则跳过
                if callName in paraLst:
                    continue

                callPos = val[0]
                varFlag = val[1]
                kwFlag = val[2]

                # 寻找callName定义的位置
                if 'self.' in callName:
                    callName = callName.replace("self.", "")

                if len(self._classNodeStack) > 0:
                    tempNode = self._classNodeStack[-1]

                    # 若是通过self进行调用的，则优先在当前类中查找调用函数的定义
                    callDefPosLst = self.findCallDef(callName, tempNode)

                    # 若当前类找不到，则再从当前文件进行查找，但也只从类中查找
                    if len(callDefPosLst) == 0:
                        callDefPosLst = self.findCallDef(callName, self._root, 1)
                else:

                    # 只查找普通函数
                    callDefPosLst = self.findCallDef(callName, self._root, 2)

                if len(callDefPosLst) > 0:

                    # 再从这些API里筛选出参数定义中不含可变参数的API
                    callDefNoKwargPosLst = self.findNoKwargCallDef(callDefPosLst, varFlag, kwFlag)
                    if len(callDefNoKwargPosLst):
                        tempDict = {fullPathName: node.lineno, callName: (callPos, str(callDefNoKwargPosLst))}
                        if len(callDefNoKwargPosLst) == 1:
                            self.cnt3 += 1
                            self.lst.append(tempDict)

            self.clean()

        self.generic_visit(node)


# 获取文件的编码方式
## Detect the text encoding of a source file
## 检测源码文件的文本编码
#
#  @param filePath Source file path.
#  @return Result of the `getEncoding` operation.
def getEncoding(filePath):

    # 读取二进制文件内容
    with open(filePath, "rb") as f:
        raw_data = f.read()

    # 自动检测文件编码
    result = chardet.detect(raw_data)
    encoding = result['encoding']
    return encoding


# libName = torch1.5.1
# /home/zhang/Packages/Matplotlib/matplotlibxx.xx
## Build the module prefix for a versioned library source path
## 根据带版本的库源码路径生成模块前缀
#
#  @param filePath Source file path.
#  @param libName Configured library name or source-version label.
#  @return Result of the `getPrefix` operation.
def getPrefix(filePath, libName):
    index=-1
    for i in range(len(libName)):
        if libName[i].isdigit():
            index=i
            break

    # rstrip在去除的时候是不考虑字符的顺序的，比如"xxxxapi.py".rstrip(',pyi')就会出错
    # s=filePath.split(f"{projName}")[-1].replace('/','.').rstrip('.pyi').rstrip('.py')
    s=filePath.split(f"{libName}")[-1].replace('/','.')
    pos=s.rfind('.')
    s=s[0:pos]
    prefix=libName[0:index] + s
    return prefix


## Return the numeric version suffix from a library name
## 提取库名称中的版本后缀
#
#  @param s Value named `s` supplied by the enclosing analysis.
#  @return Result of the `getVersion` operation.
def getVersion(s):
    index = 0
    for i, ch in enumerate(s):
        if ch.isdigit():
            index = i
            break
    return  s[index:]


## Scan library versions and record variadic API definitions and forwarding risks
## 扫描多个库版本并记录可变参数API定义及转发风险
#
#  @param libName Configured library name or source-version label.
#  @return Result of the `getKwargAPI` operation.
def getKwargAPI(libName):
    pathObj1 = Path("D")
    pathObj1.getPath(f"/home/zhang/Packages/{libName}")
    libPath = pathObj1.path
    visitor = FunctionDefVisitor()

    os.makedirs(f"KWARGS/APIDefWithVariadicPara/{libName}", exist_ok=True)
    os.makedirs(f"KWARGS/VariadicParaPitfalls/{libName}", exist_ok=True)

    cntDict = {}
    for lib in libPath:
        libNameAndVersion = lib.split('/')[-1]
        dic = {}
        defDict = {}
        pathObj2 = Path("DF")
        pathObj2.getPath(lib)
        codeFilePath = pathObj2.path
        for codeFile in codeFilePath:
            prefix = getPrefix(codeFile, libNameAndVersion)
            visitor.setPrefix(prefix)
            try:
                encdoing = getEncoding(codeFile)
                with open(codeFile, 'r', encoding = encdoing) as fr:
                    codeText = fr.read()
                root = ast.parse(codeText, filename='<unknown>', mode='exec')
            except:
                continue

            visitor.setRoot(root)
            try:
                visitor.visit(root)
            except:
                print(codeFile)

            if len(visitor.defWithVariadicParaLst) > 0:
                lst = copy.deepcopy(visitor.defWithVariadicParaLst)
                defDict[codeFile] = lst
                visitor.defWithVariadicParaLst.clear()

            if len(visitor.lst) > 0:
                lst = copy.deepcopy(visitor.lst)
                dic[codeFile] = lst
                visitor.lst.clear()

        # 保存当前版本的情况
        fileName = lib.split("/")[-1]
        if len(defDict) > 0:
            with open(f"KWARGS/APIDefWithVariadicPara/{libName}/{fileName}.txt", 'w') as fw:
                json.dump(defDict, fw, indent=4, ensure_ascii=False)

        if len(dic) > 0:
            with open(f"KWARGS/VariadicParaPitfalls/{libName}/{fileName}.txt", 'w') as fw:
                json.dump(dic, fw, indent=4, ensure_ascii=False)



        # 保存当前版本库的计数
        cntDict[fileName] = (visitor.cnt1, visitor.cnt2, visitor.cnt3)
        visitor.cleanCnt()

    sortedDict=dict(sorted(cntDict.items(), key=lambda it: cmp(getVersion(it[0]))))
    sortedDict = cntDict
    with open(f"KWARGS/VariadicParaPitfalls/{libName}/count", 'w') as fw:
        json.dump(sortedDict, fw, indent=4, ensure_ascii=False)

    print(libName)


libLst = [
"aiohttp", "click", "dask", "django", "faker", "fastapi", "flask", "gensim", "httpx", "jax", "keras",
"lightgbm", "loguru", "matplotlib", "networkx", "numpy", "pandas", "PIL", "plotly", "polars", "pydantic", "redis",
"requests", "rich", "scipy", "sklearn", "spacy", "sympy", "tensorflow", "torch", "tornado", "transformers", "xgboost"
]


if __name__ == '__main__':
    start = time.time()
    pool=Pool(20)
    pool.map(getKwargAPI, libLst)
    pool.close()
    pool.join()
    end = time.time()
    print(f"Total run time={(end-start)/3600:.2f} hour")
