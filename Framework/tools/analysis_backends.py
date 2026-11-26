"""符号执行 / 动态污点跟踪（DTaint）后端抽象接口。

**当前状态：未接入任何真实引擎。** 本模块只定义后端契约与注册/工厂机制，
便于后续在不改动 D 层编排的前提下插拔符号执行或污点跟踪后端；在后端注册
之前，工厂统一返回 :class:`_UnavailableBackend`，分析结果状态为 ``unavailable``，
不产出任何有罪/无罪结论。

与现有模块的分工：

* ``verify_taint`` —— 静态调用图 + 守卫作用域核验（不执行）；
* ``dynamic_check`` —— 编译运行 + Sanitizer 崩溃监控（动态执行）；
* 符号执行 / DTaint（本模块预留）—— 路径约束求解 / 污点传播追踪，
  用于补静态可达性判断与动态样本覆盖不到的路径。

## 如何插拔真实后端（后续阶段，不在默认链路启用）

实现对应抽象类 → 调用 :func:`register_backend` 注册 → 工厂取用：

.. code-block:: python

    class AngrSymbolic(SymbolicAnalyzer):
        name = "angr"

        def analyze(self, func_src, params, sinks, context):
            # 约束求解，返回 AnalysisResult；不可用 / 证据不足时返回 unknown，不判无罪
            return {"status": "unknown", "findings": [], "evidence": {}}

    register_backend("symbolic", "angr", AngrSymbolic)
    backend = get_symbolic_backend("angr")

未注册任何后端前，工厂一律返回 :class:`_UnavailableBackend`，结果状态 ``unavailable``。
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional

#: 分析结果状态：
#: * ``reachable``   —— 后端确认源到汇可达（有罪方向）；
#: * ``unreachable`` —— 后端确认不可达；
#: * ``unknown``    —— 后端跑完但证据不足；
#: * ``unavailable`` —— 后端未配置 / 未接入，未做分析。
ResultStatus = str

AnalysisResult = Dict[str, Any]


def _unavailable(kind: str, backend: str = "unavailable") -> AnalysisResult:
    return {
        "status": "unavailable",
        "backend": backend,
        "kind": kind,
        "findings": [],
        "evidence": {"reason": f"{kind} 后端未接入，未执行分析"},
    }


class SymbolicAnalyzer(ABC):
    """符号执行后端抽象：在约束求解下判断源到汇是否存在可达路径。"""

    name: str = "symbolic"

    @abstractmethod
    def analyze(
        self,
        func_src: str,
        params: List[str],
        sinks: List[str],
        context: Dict[str, Any],
    ) -> AnalysisResult:
        """对单个函数做符号执行分析。"""


class TaintTracker(ABC):
    """动态污点跟踪后端抽象：追踪污点从源到汇的传播。"""

    name: str = "taint"

    @abstractmethod
    def track(
        self,
        func_src: str,
        sources: List[str],
        sinks: List[str],
        context: Dict[str, Any],
    ) -> AnalysisResult:
        """对单个函数做污点传播追踪。"""


class _UnavailableBackend:
    """占位后端：未接入真实引擎时返回 unavailable，不冒充分析结果。"""

    name = "unavailable"

    def analyze(self, *_args: Any, **_kwargs: Any) -> AnalysisResult:
        return _unavailable("symbolic", self.name)

    def track(self, *_args: Any, **_kwargs: Any) -> AnalysisResult:
        return _unavailable("taint", self.name)


#: 后端注册表：``kind -> {name -> backend_cls}``；当前为空（无真实后端注册）。
_REGISTRY: Dict[str, Dict[str, type]] = {"symbolic": {}, "taint": {}}


def register_backend(kind: str, name: str, backend_cls: type) -> None:
    """注册一个后端实现（``kind`` 为 ``symbolic`` 或 ``taint``）。"""
    if kind not in _REGISTRY:
        raise ValueError(f"未知后端类型: {kind}")
    _REGISTRY[kind][name] = backend_cls


def _get(kind: str, name: Optional[str]) -> Any:
    pool = _REGISTRY.get(kind, {})
    if not pool:
        return _UnavailableBackend()
    if name is None:
        # 取首个已注册后端；当前注册表为空时落到占位后端。
        return next(iter(pool.values()))()
    cls = pool.get(name)
    return cls() if cls else _UnavailableBackend()


def get_symbolic_backend(name: Optional[str] = None) -> SymbolicAnalyzer:
    """取符号执行后端；未接入时返回占位后端（结果状态 unavailable）。"""
    return _get("symbolic", name)


def get_taint_backend(name: Optional[str] = None) -> TaintTracker:
    """取污点跟踪后端；未接入时返回占位后端（结果状态 unavailable）。"""
    return _get("taint", name)
