"""A/B/C/D Agent 共享工具函数。

集中放置：LLM 客户端构造、角色 Prompt 加载、报告 JSON 解析与修复、扫描节点实现。

设计要点：
* 未配置可用 LLM（无有效 API Key）时，扫描节点返回“空报告骨架”，
  保证整条流水线在没有密钥的情况下依然能完整跑通。
* A/B/C 角色 Prompt 默认留空 —— 空时使用内置 fallback 占位 Prompt。
"""
from __future__ import annotations

import json
import re
from typing import Any, Dict, Optional

from config import Settings, load_settings, resolve
from observability import log_event, track_time

# ---------------------------------------------------------------------------
# 报告结构骨架
# ---------------------------------------------------------------------------
# 各视角（A/B/C）的报告结构已下沉到各自文件：agents/a.py、agents/b.py、agents/c.py。
# 这里只提供“按传入模板工作”的通用机制：
#   * build_schema_hint() 依据某 agent 的模板生成追加到 Prompt 末尾的 schema 提示；
#   * _report_array_key() 从模板中推断漏洞数组的键名（如 "findings"）。
# TODO: 报告字段的最终定义在各 agent 文件中，自行修改即可。


def _report_array_key(report_template: Dict[str, Any]) -> str:
    """从报告模板中推断“漏洞数组”字段名（第一个 list 值对应的键）。"""
    for key, value in report_template.items():
        if isinstance(value, list):
            return key
    raise ValueError("report_template 未包含数组字段（如 findings）")


def build_schema_hint(
    report_template: Dict[str, Any], finding_template: Dict[str, Any]
) -> str:
    """依据某 agent 的报告模板生成追加到 Prompt 末尾的 schema 提示。"""
    array_key = _report_array_key(report_template)
    return (
        "严格只输出一个 JSON 对象，不要输出 markdown 代码块或任何解释。JSON 顶层结构：\n"
        + json.dumps(report_template, ensure_ascii=False, indent=2)
        + f"\n其中 {array_key} 数组每一项结构：\n"
        + json.dumps(finding_template, ensure_ascii=False, indent=2)
    )

# 内置 fallback 占位 Prompt（当 prompts/roles.yaml 中 role_prompt 为空时使用）
_FALLBACK_ROLE_PROMPT = (
    ""
    "此处promote未加载成功\n"
    "# TODO: 这是占位 Prompt，请在 prompts/roles.yaml 中为 {agent} 填写真实角色 Prompt。"
)


# ---------------------------------------------------------------------------
# LLM 构造
# ---------------------------------------------------------------------------
def get_llm(settings: Optional[Settings] = None) -> Optional[Any]:
    """根据配置构造 LLM 客户端；未配置有效 API Key 时返回 None（触发降级）。"""
    settings = settings or load_settings()
    api_key = (settings.api_key or "").strip()
    if not api_key or api_key.upper().startswith("TODO"):
        log_event("llm.skipped", reason="未配置有效 API Key")
        return None

    try:
        from langchain_openai import ChatOpenAI  # type: ignore
    except Exception as exc:  # pragma: no cover
        log_event("llm.import_failed", error=str(exc))
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
        log_event("llm.init_failed", error=str(exc))
        return None


# ---------------------------------------------------------------------------
# 角色 Prompt 加载
# ---------------------------------------------------------------------------
_ROLES_CACHE: Optional[Dict[str, Any]] = None


def load_roles(settings: Optional[Settings] = None) -> Dict[str, Any]:
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
            log_event("roles.load_failed", error=str(exc))
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


# ---------------------------------------------------------------------------
# JSON 解析 / 报告规范化
# ---------------------------------------------------------------------------
def parse_json_object(text: str) -> Dict[str, Any]:
    """从模型输出中提取第一个 JSON 对象，容忍 ```json 包裹与前后噪声。"""
    if not text:
        raise ValueError("模型输出为空")
    fenced = re.search(r"```(?:json)?\s*(.*?)```", text, re.DOTALL)
    if fenced:
        text = fenced.group(1)
    start = text.find("{")
    end = text.rfind("}")
    if start == -1 or end == -1 or end <= start:
        raise ValueError("未找到 JSON 对象")
    data = json.loads(text[start : end + 1])
    if not isinstance(data, dict):
        raise ValueError("顶层不是 JSON 对象")
    return data


def normalize_report(
    raw: Dict[str, Any],
    agent: str,
    file_path: str,
    report_template: Dict[str, Any],
    finding_template: Dict[str, Any],
) -> Dict[str, Any]:
    """按传入模板把模型输出规范化（补齐缺失字段，忽略未知字段）。"""
    array_key = _report_array_key(report_template)
    if not isinstance(raw, dict) or not isinstance(raw.get(array_key), list):
        raise ValueError(f"报告缺少 {array_key} 数组")

    report: Dict[str, Any] = json.loads(json.dumps(report_template))  # 深拷贝模板
    report[array_key] = []
    if "agent" in report:
        report["agent"] = agent
    if "file" in report:
        report["file"] = file_path

    for item in raw[array_key]:
        if not isinstance(item, dict):
            continue
        finding = json.loads(json.dumps(finding_template))  # 深拷贝模板
        for key in finding:
            if key in item:
                finding[key] = item[key]
        loc = item.get("location")
        if isinstance(loc, dict) and isinstance(finding.get("location"), dict):
            for key in finding["location"]:
                if key in loc:
                    finding["location"][key] = loc[key]
        report[array_key].append(finding)
    return report


def empty_report(
    report_template: Dict[str, Any], agent: str, file_path: str
) -> Dict[str, Any]:
    report = json.loads(json.dumps(report_template))
    if "agent" in report:
        report["agent"] = agent
    if "file" in report:
        report["file"] = file_path
    return report


# ---------------------------------------------------------------------------
# 扫描节点实现
# ---------------------------------------------------------------------------
def run_scan_agent(
    agent: str,
    report_template: Dict[str, Any],
    finding_template: Dict[str, Any],
    state: Dict[str, Any],
) -> Dict[str, Any]:
    """A/B/C 共用的扫描节点：返回 ``{"reports": {agent: report}}``。

    报告结构由调用方（各 agent 文件）通过 report_template / finding_template 传入。
    """
    settings = load_settings()
    file_path = state.get("file_path", "")
    code = state.get("code", "")
    array_key = _report_array_key(report_template)

    with track_time(f"scan.{agent}"):
        llm = get_llm(settings)
        if llm is None:
            log_event("scan.fallback", agent=agent, note="LLM 未配置，返回空报告骨架")
            report = empty_report(report_template, agent, file_path)
        else:
            report = _scan_with_llm(
                agent, code, file_path, settings, llm, report_template, finding_template
            )

    log_event("scan.done", agent=agent, findings=len(report.get(array_key, [])))
    return {"reports": {agent: report}}


def _scan_with_llm(
    agent, code, file_path, settings, llm, report_template, finding_template
) -> Dict[str, Any]:
    from langchain_core.messages import AIMessage, HumanMessage, SystemMessage

    system = role_prompt_for(agent, settings) + "\n\n" + build_schema_hint(
        report_template, finding_template
    )
    messages = [
        SystemMessage(content=system),
        HumanMessage(content=f"待扫描文件: {file_path}\n\n```c\n{code}\n```"),
    ]

    last_error: Optional[Exception] = None
    for attempt in range(1, settings.max_retries + 1):
        response = llm.invoke(messages)
        text = getattr(response, "content", str(response))
        try:
            raw = parse_json_object(text)
            return normalize_report(raw, agent, file_path, report_template, finding_template)
        except Exception as exc:  # 自动修复/重试
            last_error = exc
            log_event("scan.repair", agent=agent, attempt=attempt, error=str(exc))
            messages.append(AIMessage(content=text))
            messages.append(
                HumanMessage(
                    content="上面的输出不是合法 JSON。请只输出符合 schema 的合法 JSON，不要任何多余内容。"
                )
            )
    raise RuntimeError(
        f"Agent {agent} 报告格式修复失败（已重试 {settings.max_retries} 次）: {last_error}"
    )
