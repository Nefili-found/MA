"""LLM 客户端构造（唯一的提供商适配点）。

从 ``agents/__init__.py`` 拆出（20 文档 §5.1-3）。改造前 ``__init__.py`` 一个文件
混了 LLM 构造、提示词加载、JSON 解析、报告归一、降级逻辑、上下文治理六件事，
职责边界模糊。

当前实现只覆盖 OpenAI 兼容接口；``Settings.llm_provider`` 仍未被消费
（20 文档 §5.2-11 的 provider 分支不在本次范围内，留在此处单点扩展）。
"""
from __future__ import annotations

from typing import Any, Dict, Optional

from config import Settings, load_settings
from observability import log_event


def get_llm(settings: Optional[Settings] = None) -> Optional[Any]:
    """根据配置构造 LLM 客户端；未配置有效 API Key 时返回 None（触发降级）。"""
    settings = settings or load_settings()
    api_key = (settings.api_key or "").strip()
    if not api_key or api_key.upper().startswith("TODO"):
        log_event("llm.skipped", level="warn", reason="未配置有效 API Key")
        return None

    try:
        from langchain_openai import ChatOpenAI  # type: ignore
    except Exception as exc:  # pragma: no cover
        log_event("llm.import_failed", level="warn", error=str(exc))
        return None

    # TODO: 如需支持其他 LLM 提供商（Anthropic / 本地模型等），请在此按 provider 分支。
    kwargs: Dict[str, Any] = {
        "model": settings.model_name,
        "api_key": api_key,
        "temperature": settings.temperature,
    }
    if settings.base_url:
        kwargs["base_url"] = settings.base_url
    try:
        return ChatOpenAI(**kwargs)
    except Exception as exc:  # pragma: no cover
        log_event("llm.init_failed", level="warn", error=str(exc))
        return None
