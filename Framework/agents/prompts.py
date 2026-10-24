"""角色提示词加载 + schema 提示生成。

从 ``agents/__init__.py`` 拆出（20 文档 §5.1-3）。

两部分：

* **角色 Prompt**：外置在 ``prompts/roles.yaml``（路径见 ``Settings.roles_path``），
  加载后缓存；为空时回落到内置占位 Prompt（保证降级模式仍然能跑）。
* **schema 提示**：把某视角的 ``REPORT_TEMPLATE`` / ``FINDING_TEMPLATE`` 序列化成
  追加在 Prompt 末尾的结构说明 + 字段约定。字段约定只能靠文字表达（枚举、写法要求），
  ``json.dumps`` 表达不了；缺了它模型会自由发挥，下游 ``verify_taint`` 只能判「无法核」。
"""
from __future__ import annotations

import json
from typing import Any, Dict, Optional

from config import Settings, load_settings, resolve
from observability import log_event


def report_array_key(report_template: Dict[str, Any]) -> str:
    """从报告模板中推断“漏洞数组”字段名（第一个 list 值对应的键）。"""
    for key, value in report_template.items():
        if isinstance(value, list):
            return key
    raise ValueError("report_template 未包含数组字段（如 findings）")


# 字段级约束：json.dumps 只能表达结构，表达不了「枚举 / 写法约定」，
# 这里补一段文字规则。缺了它，模型会自由发挥 assumptions 的 kind、把路径写成
# 表达式，导致下游 verify_taint 只能判「无法核」。
_FIELD_RULES = (
    "\n字段约定（必须遵守）：\n"
    '* propagation_path：按 source→sink 顺序书写**本文件内的函数名**'
    '（如 ["main","handle","strcpy"]）；无法落到函数名时写表达式原文，'
    "下游会把该跳标记为“无法核”。\n"
    "* assumptions[].kind：只能是 null_check / bounds_check / sanitizer / other。\n"
    "* assumptions[].id：cond-1、cond-2 递增；assumptions[].text：一句话写成可核验的前置条件"
    "（写清“哪个变量/缓冲区、缺什么校验”）。无前置条件时给空数组 []，不要编造。\n"
    "* severity：critical / high / medium / low 之一；confidence：0~1 的小数。\n"
    "* id：<视角>-<序号>（A-1 / B-1 / C-1），同一视角内唯一。\n"
)


def build_schema_hint(
    report_template: Dict[str, Any], finding_template: Dict[str, Any]
) -> str:
    """依据某 agent 的报告模板生成追加到 Prompt 末尾的 schema 提示。"""
    array_key = report_array_key(report_template)
    return (
        "严格只输出一个 JSON 对象，不要输出 markdown 代码块或任何解释。JSON 顶层结构：\n"
        + json.dumps(report_template, ensure_ascii=False, indent=2)
        + f"\n其中 {array_key} 数组每一项结构：\n"
        + json.dumps(finding_template, ensure_ascii=False, indent=2)
        + _FIELD_RULES
    )


# 内置 fallback 占位 Prompt（当 prompts/roles.yaml 中 role_prompt 为空时使用）
_FALLBACK_ROLE_PROMPT = (
    ""
    "此处promote未加载成功\n"
    "# TODO: 这是占位 Prompt，请在 prompts/roles.yaml 中为 {agent} 填写真实角色 Prompt。"
)


_ROLES_CACHE: Optional[Dict[str, Any]] = None


def load_roles(settings: Optional[Settings] = None) -> Dict[str, Any]:
    """加载 ``prompts/roles.yaml``（进程内缓存；损坏时回落空表并记日志）。"""
    global _ROLES_CACHE
    if _ROLES_CACHE is not None:
        return _ROLES_CACHE
    settings = settings or load_settings()
    path = resolve(settings.roles_path)
    data: Dict[str, Any] = {}
    if path.exists():
        try:
            import yaml  # type: ignore

            with path.open("r", encoding="utf-8") as fh:
                loaded = yaml.safe_load(fh) or {}
            if isinstance(loaded, dict):
                data = loaded
        except Exception as exc:
            log_event("roles.load_failed", level="warn", error=str(exc))
    _ROLES_CACHE = data
    return _ROLES_CACHE


def role_prompt_for(agent: str, settings: Optional[Settings] = None) -> str:
    """取某 Agent 的角色 Prompt；为空则返回内置 fallback 占位 Prompt。"""
    roles = load_roles(settings)
    entry = roles.get(agent) or {}
    prompt = ""
    if isinstance(entry, dict):
        prompt = (entry.get("role_prompt") or "").strip()
    if not prompt:
        return _FALLBACK_ROLE_PROMPT.format(agent=agent)
    return prompt
