## @package vppdetector.assess.context_cache
#  Reuse assessment-specific source contexts within a parent context.
#
#
#  Own constructor and dispatch contexts plus ContextVar package proofs. Package proofs are
#  returned as independent containers.
#  管理构造器和分派上下文及 ContextVar 包证明，返回独立容器形式的包证明。



from .._records import FrozenRecord


## Cache-owned immutable representation of a package proof.
## 缓存持有的不可变包证明表示。
class _PackageProof(FrozenRecord):
    _record_fields = ("source_hashes", "assumptions")
    __match_args__ = _record_fields

    ## Initialize a _PackageProof instance with its declared state.
    ## 使用声明的状态初始化 _PackageProof 实例。
    #
    #  @param source_hashes Value stored in the `source_hashes` field
    #  @param assumptions Value stored in the `assumptions` field
    def __init__(self, source_hashes, assumptions):
        object.__setattr__(self, "source_hashes", source_hashes)
        object.__setattr__(self, "assumptions", assumptions)


## Cache package initialization proofs for a particular ContextVar identity.
## 缓存针对特定 ContextVar 标识的包初始化证明。
class ContextVarPackageCache:
    ## Create an empty per-context package proof cache.
    ## 创建上下文专属的空包证明缓存。
    def __init__(self):
        self._completed = {}

    ## Get a private copy of the proof or the conservative unknown sentinel.
    ## 返回证明的独立副本或保守的未知哨兵。
    #
    #  Both outcomes are cached. If compute raises, the next lookup can retry.
    #  两种结果都会缓存。计算抛出异常时，下次查询可以重试。
    #
    #  @param packages Source package names
    #  @param identity Module and variable identifying the ContextVar
    #  @param compute Package initialization analysis
    #  @return Proof copy or True when analysis is inconclusive
    def initialization(
        self,
        packages,
        identity,
        compute,
    ):
        key = (tuple(sorted(packages)), identity)

        # A raised computation stays uncached. Completed proofs use immutable tuples in the cache.
        # 计算抛出异常时不写缓存，已完成的证明以不可变元组存储。
        if key not in self._completed:
            result = compute()
            self._completed[key] = (
                True
                if result is True
                else _PackageProof(
                    tuple(result["source_hashes"].items()), tuple(result["assumptions"])
                )
            )

        cached = self._completed[key]
        if cached is True:
            return True
        return {
            "state": "no_contextvar_write",
            "source_hashes": dict(cached.source_hashes),
            "assumptions": list(cached.assumptions),
        }


## Own context reuse for constructor and inferred dispatch assessments.
## 管理构造器及推断分派评估的上下文复用。
class AssessmentContexts:
    ## Create empty per-context assessment caches.
    ## 创建上下文专属的空评估缓存。
    def __init__(self):
        self._classes = {}
        self._dispatches = {}

    ## Reuse a resolved constructor context; unsuccessful resolution is not cached.
    ## 复用已解析的构造器上下文；解析失败不缓存。
    #
    #  @param identity Constructor class identity
    #  @param create Source-bound context and entry builder
    #  @return Resolved context and entry, or None if unavailable
    def constructor(
        self,
        identity,
        create,
    ):
        cached = self._classes.get(identity)
        if cached is None:
            cached = create()
            if cached is not None:
                self._classes[identity] = cached
        return cached

    ## Reuse a context for a source-inferred dispatch target.
    ## 复用源码推断分派目标的上下文。
    #
    #  @param identity Inferred target identity
    #  @param create Source-bound context builder
    #  @return Prepared dispatch context
    def dispatch(self, identity, create):
        cached = self._dispatches.get(identity)
        if cached is None:
            cached = create()
            self._dispatches[identity] = cached
        return cached
