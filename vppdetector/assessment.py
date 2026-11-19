## @package vppdetector.assessment
#  Public parameter-assessment entry point.
#
#
#  Expose the parameter-assessment runner through the package's public assessment entry point.
#  通过包的公开评估入口导出参数评估执行器。



from .assess.runner import assess_change as assess_change

__all__ = ("assess_change",)
