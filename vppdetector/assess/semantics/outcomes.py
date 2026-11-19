## @package vppdetector.assess.semantics.outcomes
#  Distinguish a non-applicable rule from an unknown proof.
#
#
#  Share the sentinel that lets a semantic handler defer to the next applicable call rule.
#  提供语义处理器用来将调用交给后续适用规则的共享哨兵。



NOT_APPLICABLE = object()
