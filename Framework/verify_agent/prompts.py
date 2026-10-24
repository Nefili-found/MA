"""D 的提示词：外置到 ``prompts/verify.yaml``，内置默认值兜底。

【20 文档 §5.2-8】改造前 ``PROMPT_DEDUPE`` / ``PROMPT_ADJUDICATE`` / ``PROMPT_TOOL``
直接内联在 ``verify_agent/d.py`` 里，与 A/B/C 用 ``prompts/roles.yaml`` 外置的方式
不一致：改一句提示词就要动 Python 源码，没法单独版本管理，也没法做 A/B 实验。

现在的口径与 A/B/C 对齐：

* yaml 优先（路径来自 ``Settings.verify_prompts_path``，默认 ``prompts/verify.yaml``）；
* yaml 缺失 / 损坏 / 缺某个键时，**逐项**回落到本文件的 ``DEFAULTS``——
  缺一个提示词不应该让整条流水线失去该步骤的能力；
* 解析结果按路径缓存，``reset_cache()`` 供测试与热改后重载使用。
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional

from config import Settings, load_settings, resolve
from observability import log_event

# ---------------------------------------------------------------------------
# 内置默认提示词（yaml 缺失时的兜底；也是排障时的“标准答案”）
# ---------------------------------------------------------------------------
DEFAULTS: Dict[str, str] = {
    "dedupe": (
        "你是漏洞报告去重助手。给定若干漏洞条目的精简信息，"
        "请把语义上属于同一漏洞的条目分到同一组。"
        '只输出 JSON：{"groups": [[索引, ...], ...]}，不要输出其他内容。'
    ),
    "adjudicate": (
        "你是漏洞裁决助手。给定同一漏洞的多个视角判断（含 confidence），"
        "请裁决冲突并给出最终置信度与理由。"
        '只输出 JSON：{"final_confidence": 0.0, "reason": ""}，不要输出其他内容。'
    ),
    "tool": (
        "你是对抗式漏洞验证者。你的任务是**尝试推翻**给定的污点假设，而不是附和它。\n"
        "你有以下工具可用：\n"
        "* get_callers(function_name)：返回该函数在文件内的调用者（追踪污点参数来源）；\n"
        "* get_callees(function_name)：返回该函数调用的其他函数（追踪 sink / 指针使用 / 资源释放）；\n"
        "* get_function_body(function_name)：返回该函数的签名与实现（确认跨过程依赖）；\n"
        "* verify_taint(hypothesis, context)：工具侧的确定性核验（触发路径可达性 + 守卫/校验），\n"
        "  返回 verdict/evidence，可作为你的证据之一，但不要照抄它的结论。\n"
        "请先按需调用上下文工具（get_callers/get_callees/get_function_body）补充跨过程证据，"
        "再调用 verify_taint 取工具侧证据，最后给出你自己的裁决。\n"
        "注意：过大的源码或工具结果会以首尾预览 + 文件位置（stored at）给出，"
        "如需完整内容，请按需调用 get_function_body，或用 read 工具按 offset/limit 读取该文件。\n\n"
        "【最终输出】当证据足够时，停止调用工具，只输出一个 JSON 对象，不要任何解释或代码块：\n"
        '{"verdict": "accept|reject|challenge", "confidence": 0.0, "reason": ""}\n'
        "verdict 含义：accept=漏洞成立；reject=误报（触发路径不可达、或声称缺失的校验其实已存在）；"
        "challenge=证据不足以下结论。confidence 为 0~1。"
    ),
}


@dataclass(frozen=True)
class VerifyPrompts:
    """D 三个提示词的快照。"""

    dedupe: str
    adjudicate: str
    tool: str
    source: str = "default"  # yaml 路径或 "default"，便于排查“用的是哪份提示词”


_CACHE: Dict[str, VerifyPrompts] = {}


def reset_cache() -> None:
    """清空缓存（测试 / 热改 yaml 后重载）。"""
    _CACHE.clear()


def _read_yaml(path: Any) -> Dict[str, Any]:
    try:
        from config import _load_yaml  # 与 Settings 加载共用同一份解析逻辑

        data = _load_yaml(path)
        return data if isinstance(data, dict) else {}
    except Exception as exc:  # pragma: no cover - 极端情况：yaml 缺失/损坏
        log_event("verify_prompts.load_failed", level="warn", error=str(exc))
        return {}


def load_verify_prompts(settings: Optional[Settings] = None) -> VerifyPrompts:
    """加载 D 的提示词：yaml 优先，逐项回落到 ``DEFAULTS``。"""
    settings = settings or load_settings()
    raw_path = getattr(settings, "verify_prompts_path", "prompts/verify.yaml")
    path = resolve(raw_path)
    key = str(path)
    cached = _CACHE.get(key)
    if cached is not None:
        return cached

    data = _read_yaml(path)
    prompts: Dict[str, str] = {}
    for name, default in DEFAULTS.items():
        value = data.get(name)
        if isinstance(value, dict):  # 允许写成 {prompt: "..."} 形式
            value = value.get("prompt") or value.get("text")
        text = str(value).strip() if value is not None else ""
        prompts[name] = text or default

    source = key if path.exists() else "default"
    snapshot = VerifyPrompts(
        dedupe=prompts["dedupe"],
        adjudicate=prompts["adjudicate"],
        tool=prompts["tool"],
        source=source,
    )
    _CACHE[key] = snapshot
    log_event("verify_prompts.loaded", source=source, overridden=sum(
        1 for n in DEFAULTS if prompts[n] != DEFAULTS[n]
    ))
    return snapshot
