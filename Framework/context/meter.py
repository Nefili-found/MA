"""Token 计量与上下文压力（移植自 A 篇第 09 章 ``meter.py``，并适配 LangChain 消息）。

================================================================================
【优化点 O-1】新增统一的 Token 计量器，替换 B 篇原来只会 ``len(text)//4`` 的
``observability.count_tokens``。
--------------------------------------------------------------------------------
优化来源（A 篇）：chapters/09-context-engineering/src/meter.py
    * 每 4 个字符 ≈ 1 个 token + 角色 / 内容块 / 工具调用结构开销；
    * ``measure()`` 只负责“测量”，``pressure()`` 只负责“算占比”，
      是否压缩 / 裁剪 / 外存交给调用方（职责分离，便于单测与复用）。
相对 A 篇的适配（B 篇）：
    * A 篇使用自定义 ``client.Message`` dataclass；B 篇使用 LangChain 的
      ``SystemMessage / HumanMessage / AIMessage / ToolMessage``。
      本模块通过鸭子类型（``.type`` / ``.content`` / ``.tool_calls``）读取，
      不强依赖具体类，便于在无 langchain 的单测里用普通对象替身。
    * 工具清单从“裸 dict schema”改为 LangChain ``BaseTool``（``@tool`` 装饰器
      产出的对象，含 ``name / description / args_schema``）。
================================================================================
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Iterable

# ---------------------------------------------------------------------------
# 启发式常量（与 A 篇官方保持一致）
# ---------------------------------------------------------------------------
CHARS_PER_TOKEN = 4
ROLE_OVERHEAD = 4
BLOCK_OVERHEAD = 4

# B 篇默认走 OpenAI 兼容接口（config 中 gpt-4o-mini 一类），默认窗口取 128k。
# 可由 config.yaml 的 context.context_window 覆盖；DeepSeek 等百万窗口模型可调大。
DEFAULT_CONTEXT_WINDOW = 128_000

# 压力阈值：占用 >= 80% 触发治理（对齐 A 篇官方 DEFAULT_THRESHOLD_RATIO=.8）
PRESSURE_THRESHOLD = 0.8


# ---------------------------------------------------------------------------
# 计量快照 / 压力读数（与 A 篇一致）
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class Measurement:
    """一次计量快照。"""

    message_tokens: int
    tools_tokens: int
    total_tokens: int
    per_message: tuple[tuple[str, int], ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class Pressure:
    """压力读数：总量、容量、占比、阈值与阈值 token 数。"""

    total_tokens: int
    context_window: int
    ratio: float
    threshold_tokens: int
    over_threshold: bool


# ---------------------------------------------------------------------------
# 纯函数：文本 / 消息 / 工具 的 token 估算
# ---------------------------------------------------------------------------
def estimate_tokens(text: str) -> int:
    """纯函数：一段文本的估算 = ceil(字符数 / 4)。"""
    return -(-len(text or "") // CHARS_PER_TOKEN)  # 向上取整的整除写法


def _message_role(message: Any) -> str:
    """读取 LangChain 消息角色。

    LangChain BaseMessage 暴露 ``.type``（system/human/ai/tool）；
    个别版本 / 自定义对象暴露 ``.role``。做一层兼容。
    """
    role = getattr(message, "type", None)
    if role:
        return str(role)
    return str(getattr(message, "role", "") or "")


def content_to_text(content: Any) -> str:
    """把 LangChain 的 content 统一成纯文本。

    多数模型返回 str，但部分提供商（如经代理转发的 gpt-5.x / 推理模型）返回
    content-block 列表 ``[{"type": "text", "text": "..."}]``；直接交给
    ``re.search`` / ``json.loads`` 会抛 "expected string or bytes-like object"。
    这里统一归一成字符串，调用方（agents / verify_agent / memory）都要走这个函数。
    """
    if content is None:
        return ""
    if isinstance(content, str):
        return content
    if isinstance(content, (list, tuple)):
        parts: list[str] = []
        for block in content:
            if isinstance(block, str):
                parts.append(block)
            elif isinstance(block, dict):
                if block.get("type") == "text":
                    parts.append(str(block.get("text", "")))
                else:
                    parts.append(json.dumps(block, ensure_ascii=False))
            else:
                parts.append(str(block))
        return "".join(parts)
    return str(content)


def _tool_call_parts(call: Any) -> tuple[str, str]:
    """从一个 tool_call（dict 或 LangChain ToolCall 对象）取 (name, args 字符串)。"""
    if isinstance(call, dict):
        name = str(call.get("name", "") or "")
        args = call.get("args", "")
    else:
        name = str(getattr(call, "name", "") or "")
        args = getattr(call, "args", "")
    if not isinstance(args, str):
        try:
            args = json.dumps(args, ensure_ascii=False)
        except (TypeError, ValueError):
            args = str(args)
    return name, args


def estimate_message(message: Any) -> int:
    """估算一条 LangChain 消息：正文、思考内容、工具调用 + 角色 / 内容块开销。"""
    role = _message_role(message)
    text = content_to_text(getattr(message, "content", None))

    # 空系统消息不计费（与 A 篇一致）
    if role == "system":
        return 0 if not text else estimate_tokens(text) + ROLE_OVERHEAD

    tokens = ROLE_OVERHEAD
    if text:
        tokens += estimate_tokens(text) + BLOCK_OVERHEAD

    # 思考内容（reasoning 模型可能返回）
    reasoning = getattr(message, "reasoning_content", None)
    if not reasoning:
        additional = getattr(message, "additional_kwargs", None)
        if isinstance(additional, dict):
            reasoning = additional.get("reasoning_content")
    if reasoning:
        tokens += estimate_tokens(str(reasoning)) + BLOCK_OVERHEAD

    # AIMessage 上的工具调用（名称 + 参数都要计入）
    for call in getattr(message, "tool_calls", None) or []:
        name, args = _tool_call_parts(call)
        tokens += estimate_tokens(name) + estimate_tokens(args) + BLOCK_OVERHEAD

    # ToolMessage 携带的工具名（回灌结果时的结构开销）
    if role == "tool" and getattr(message, "name", None):
        tokens += estimate_tokens(str(getattr(message, "name")))

    return tokens


def _tool_schema_text(tool: Any) -> str:
    """提取一个 LangChain 工具的名称 / 描述 / 参数 schema 文本。"""
    parts = [
        str(getattr(tool, "name", "") or ""),
        str(getattr(tool, "description", "") or ""),
    ]
    schema = getattr(tool, "args_schema", None)
    dumped = False
    if schema is not None:
        try:
            parts.append(json.dumps(schema.model_json_schema(), ensure_ascii=False))
            dumped = True
        except Exception:
            dumped = False
    if not dumped:
        try:
            parts.append(json.dumps(getattr(tool, "args", {}) or {}, ensure_ascii=False))
        except Exception:
            pass
    return "\n".join(p for p in parts if p)


def estimate_tools(tools: Iterable[Any] | None) -> int:
    """序列化工具 schema，按固定启发式估算结构开销。"""
    if not tools:
        return 0
    joined = "\n".join(_tool_schema_text(t) for t in tools)
    if not joined:
        return 0
    return estimate_tokens(joined) + ROLE_OVERHEAD


# ---------------------------------------------------------------------------
# 计量服务（对应 A 篇官方单例 ctx.tokenMeter）
# ---------------------------------------------------------------------------
class TokenMeter:
    """计量服务：只测量与算压力，不决定如何处理。"""

    def __init__(
        self,
        context_window: int = DEFAULT_CONTEXT_WINDOW,
        threshold_ratio: float = PRESSURE_THRESHOLD,
    ) -> None:
        if (
            not isinstance(context_window, int)
            or isinstance(context_window, bool)
            or context_window <= 0
        ):
            raise ValueError("context_window 必须是正整数")
        if (
            not isinstance(threshold_ratio, (int, float))
            or isinstance(threshold_ratio, bool)
            or not 0 < threshold_ratio <= 1
        ):
            raise ValueError("threshold_ratio 必须位于 (0, 1] 区间")
        self.context_window = context_window
        self.threshold_ratio = float(threshold_ratio)

    def measure(self, messages: list[Any], tools: Iterable[Any] | None = None) -> Measurement:
        """计量一段会话：消息面 + 工具 schema 的 envelope。"""
        tools_list = list(tools or [])
        per_message = tuple(
            (_message_role(m) or "?", estimate_message(m)) for m in messages
        )
        message_tokens = sum(tokens for _, tokens in per_message)
        tools_tokens = estimate_tools(tools_list)
        return Measurement(
            message_tokens=message_tokens,
            tools_tokens=tools_tokens,
            total_tokens=message_tokens + tools_tokens,
            per_message=per_message,
        )

    def pressure(self, measurement: Measurement) -> Pressure:
        """把计量换算成压力读数；是否裁剪 / 压缩 / 外存由调用方决定。"""
        ratio = measurement.total_tokens / self.context_window
        threshold_tokens = int(self.context_window * self.threshold_ratio)
        return Pressure(
            total_tokens=measurement.total_tokens,
            context_window=self.context_window,
            ratio=ratio,
            threshold_tokens=threshold_tokens,
            over_threshold=ratio >= self.threshold_ratio,
        )
