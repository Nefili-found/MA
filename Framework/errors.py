"""流水线错误分级（对应 20 文档 §5.2-12「错误传播不统一」）。

改造前的问题：部分错误追加到 ``state["errors"]``（但没人往里写）、
部分直接 ``raise RuntimeError``（崩掉整张图）、部分只写日志后降级——
上层调用者无法统一处理，也分不清「该重试 / 该跳过 / 该退出」。

本模块把失败分成三类，各自有明确的处置策略：

| 异常 | 触发场景 | 处置策略 | 谁处理 |
| --- | --- | --- | --- |
| ``ScanError`` | A/B/C 的 LLM 调用失败、输出格式修复超限 | **降级**：输出空报告骨架，流水线继续跑到 D，记 ``errors`` | ``agents.run_scan_agent`` |
| ``VerifyError`` | D 的工具验证循环失败 / 工具返回非法状态 | **隔离**：该条 finding 标 ``uncertain``，其余照常验证，记 ``errors`` | ``verify_agent.d._verify_findings`` |
| ``FatalError`` | 输入文件缺失、DB 无法初始化、三份报告缺失（编排缺陷） | **中止**：向上抛，``main.py`` 捕获并以退出码 ``2`` 退出 | ``main.main`` |

约定：不在这三类里的异常（``KeyError`` / ``TypeError`` / ``AttributeError`` …）
一律视为**编程缺陷**，照旧冒泡成 traceback —— 不要用 ``except Exception`` 把它们
悄悄降级，否则真 bug 会被吞掉。
"""
from __future__ import annotations


class PipelineError(Exception):
    """流水线内可分类错误的基类。"""

    stage = ""  # 出错的环节（scan / verify / fatal）

    def __init__(self, message: str = "", *, stage: str = "") -> None:
        super().__init__(message)
        self.message = message or self.__class__.__name__
        self.stage = stage or self.__class__.stage

    def __str__(self) -> str:  # pragma: no cover - 直通基类实现
        return self.message


class ScanError(PipelineError):
    """A/B/C 扫描失败：可降级为空报告，不中断整条流水线。

    典型来源：LLM 服务不可用 / 鉴权失败 / 限流、模型输出始终不是合法 JSON。
    """

    stage = "scan"


class VerifyError(PipelineError):
    """D 的某一步验证失败：只影响当前 finding（标 uncertain），不影响其它 finding。

    典型来源：工具循环无结果、工具返回非法 status、工具调用抛异常。
    """

    stage = "verify"


class FatalError(PipelineError):
    """不可恢复错误：继续跑没有意义，必须中止并以非零码退出。"""

    stage = "fatal"
    exit_code = 2
