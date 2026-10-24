"""A/B/C/D Agent 共享工具函数。

集中放置：LLM 客户端构造、角色 Prompt 加载、报告 JSON 解析与修复、扫描节点实现。

设计要点：
* 未配置可用 LLM（无有效 API Key）时，扫描节点返回“空报告骨架”，
  保证整条流水线在没有密钥的情况下依然能完整跑通。
* A/B/C 角色 Prompt 默认留空 —— 空时使用内置 fallback 占位 Prompt。

================================================================================
【优化点 O-8】扫描节点接入 A 篇上下文治理（计量 + 大输入外存）。
--------------------------------------------------------------------------------
对应 B 篇原文件：agents/__init__.py（本文件优化前的版本）
原问题：
    * ``_scan_with_llm`` 把整份 C 源码直接拼进 HumanMessage，调用前不做任何
      计量；文件过大时只能被模型服务拒绝（context overflow），且没有可读提示。
    * 格式错误重试时不断追加纠正消息，也没有任何预算控制。
本文件的优化：
    * 扫描前用 TokenMeter 计量 system + 源码的压力；
    * 大源码在写入消息前经 ContextManager.spill_text 外存（A 篇 spill）：
      完整源码落盘，模型只见首尾 + 文件位置，并明确提示本次覆盖范围；
    * 每次 invoke（含格式修复重试）前调用 enforce_budget 统一治理；
    * 降级模式（无 LLM）行为不变，仍返回空报告骨架。
  说明：首轮是单轮扫描、无历史可压缩，超大源码无法靠压缩解决；spill 会使
  中段代码不进入本次扫描（覆盖率下降，根治需“分块扫描”，已在优化说明中列为
  后续项）。小文件（默认 <4096 字节）完全不受影响，依旧完整发送。
================================================================================
"""
from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

from config import Settings, load_settings, resolve
from context import ContextManager, content_to_text
from errors import ScanError
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
    array_key = _report_array_key(report_template)
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


# ---------------------------------------------------------------------------
# LLM 构造
# ---------------------------------------------------------------------------
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


# ---------------------------------------------------------------------------
# JSON 解析 / 报告规范化
# ---------------------------------------------------------------------------
def response_text(response: Any) -> str:
    """取模型回复正文，并归一为字符串。

    部分提供商（含本仓库使用的 OpenAI 兼容代理）对 gpt-5.x / 推理模型返回
    content-block 列表而非 str，直接解析会崩；统一在此归一。
    """
    content = getattr(response, "content", None)
    if content is None:
        return str(response)
    return content_to_text(content)


def _iter_json_objects(text: str) -> List[str]:
    """按平衡花括号切出文本中所有顶层 JSON 对象候选。

    【健壮性包 B-3】与旧实现 ``text[find("{"):rfind("}")]`` 的区别：
    * 字符串字面量与转义内的花括号（``"a{b"`` / ``"\\"}"``）不再干扰边界；
    * 一段文本里出现多个 JSON 块时逐个给出，不会把中间的散文一起切进去；
    * 被截断的未闭合对象直接丢弃，交给调用方报错，而不是猜一个边界。
    """
    objects: List[str] = []
    depth = 0
    start = -1
    in_string = False
    escaped = False
    for i, ch in enumerate(text):
        if in_string:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_string = False
            continue
        if ch == '"':
            in_string = True
            continue
        if ch == "{":
            if depth == 0:
                start = i
            depth += 1
        elif ch == "}":
            if depth == 0:
                continue  # 多余的右花括号：忽略
            depth -= 1
            if depth == 0 and start >= 0:
                objects.append(text[start : i + 1])
                start = -1
    return objects


def parse_json_object(text: str) -> Dict[str, Any]:
    """从模型输出中提取第一个可解析的 JSON **对象**。

    容忍：``` 围栏、前后散文、同一回复里多个 JSON 块、字符串里含花括号。
    全部候选都解析失败时，错误信息带偏移与片段预览（而不是只说“未找到 JSON”）。
    """
    if not text:
        raise ValueError("模型输出为空")
    candidates = _iter_json_objects(text)
    if not candidates:
        preview = text.strip()[:120].replace("\n", " ")
        raise ValueError(f"未找到完整的 JSON 对象（输出片段: {preview!r}）")

    failures: List[str] = []
    for idx, candidate in enumerate(candidates):
        offset = text.find(candidate)
        try:
            data = json.loads(candidate)
        except json.JSONDecodeError as exc:
            failures.append(
                f"候选 #{idx + 1}（偏移 {offset}）解析失败: {exc.msg}（char {exc.pos}）"
            )
            continue
        if isinstance(data, dict):
            return data
        failures.append(f"候选 #{idx + 1} 顶层不是对象（{type(data).__name__}）")
    raise ValueError("；".join(failures) or "未找到可解析的 JSON 对象")


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
def _build_context_manager(settings: Settings) -> ContextManager:
    """【优化 O-8】从配置构造扫描用的上下文治理器（spill 目录解析为绝对路径）。"""
    return ContextManager(
        context_window=int(getattr(settings, "context_window", 128_000)),
        threshold_ratio=float(getattr(settings, "context_threshold_ratio", 0.8)),
        retain_ratio=float(getattr(settings, "context_retain_ratio", 0.16)),
        spill_root=str(resolve(getattr(settings, "spill_root", "output/spill"))),
        max_inline_bytes=int(getattr(settings, "spill_max_inline_bytes", 4096)),
        prune_threshold_chars=int(getattr(settings, "prune_threshold_chars", 8192)),
        prune_head_chars=int(getattr(settings, "prune_head_chars", 4096)),
        prune_tail_chars=int(getattr(settings, "prune_tail_chars", 1024)),
        enable_spill=bool(getattr(settings, "context_enable_spill", True)),
        enable_compaction=bool(getattr(settings, "context_enable_compaction", True)),
    )


def run_scan_agent(
    agent: str,
    report_template: Dict[str, Any],
    finding_template: Dict[str, Any],
    state: Dict[str, Any],
) -> Dict[str, Any]:
    """A/B/C 共用的扫描节点：返回 ``{"reports": {agent: report}}``。

    报告结构由调用方（各 agent 文件）通过 report_template / finding_template 传入。

    【健壮性包 B-2】扫描失败不再崩图：``ScanError``（LLM 不可用 / 格式修复超限 /
    调用抛错）在此被捕获 → 降级为空报告骨架 + 记入 ``state["errors"]``，
    流水线照常进到 D。非 ``ScanError`` 的异常（编程缺陷）照旧冒泡。
    """
    settings = load_settings()
    file_path = state.get("file_path", "")
    code = state.get("code", "")
    session_id = state.get("session_id", "scan")
    array_key = _report_array_key(report_template)

    errors: List[str] = []
    with track_time(f"scan.{agent}"):
        llm = get_llm(settings)
        if llm is None:
            log_event(
                "scan.fallback",
                level="warn",
                agent=agent,
                note="LLM 未配置，返回空报告骨架",
            )
            report = empty_report(report_template, agent, file_path)
            errors.append(f"scan.{agent}: LLM 未配置，已降级为空报告")
        else:
            ctx = _build_context_manager(settings)  # 【优化 O-8】
            try:
                report = _scan_with_llm(
                    agent, code, file_path, settings, llm, report_template,
                    finding_template, ctx, session_id,
                )
            except ScanError as exc:
                # 【健壮性包 B-2】可降级失败：空报告 + errors，图继续跑到 D
                log_event("scan.degraded", level="warn", agent=agent, error=str(exc))
                report = empty_report(report_template, agent, file_path)
                errors.append(f"scan.{agent}: {exc}")

    log_event("scan.done", agent=agent, findings=len(report.get(array_key, [])))
    return {"reports": {agent: report}, "errors": errors}


def _scan_with_llm(
    agent, code, file_path, settings, llm, report_template, finding_template,
    ctx: "ContextManager", session_id: str,
) -> Dict[str, Any]:
    from langchain_core.messages import AIMessage, HumanMessage, SystemMessage

    system = role_prompt_for(agent, settings) + "\n\n" + build_schema_hint(
        report_template, finding_template
    )

    # 【优化 O-8】大源码外存（A 篇 spill）：完整源码落盘，模型只见首尾 + 位置。
    # 小文件（小于内联字节预算）原样返回，行为与优化前完全一致。
    code_view, code_locator = ctx.prepare_large_input(
        code or "",
        session_id=session_id,
        tool_name=f"scan-{agent}-source",
        call_id=f"{agent}-source",
    )
    code_block = f"待扫描文件: {file_path}\n\n```c\n{code_view}\n```"
    if code_locator:
        code_block += (
            "\n\n[注意] 该文件较大，完整源码已外存到："
            f"{code_locator}（可用 read 工具按 offset/limit 读取）。"
            "本次仅提供首尾片段，请据此识别风险，并在证据中注明未能覆盖的中段。"
        )
        log_event("scan.source_spilled", agent=agent, locator=code_locator)

    messages = [
        SystemMessage(content=system),
        HumanMessage(content=code_block),
    ]

    # 【优化 O-8】调用前计量与压力记录（首轮单请求，主要做可观测的预算检查）
    pressure = ctx.pressure(messages)
    log_event(
        "scan.pressure",
        agent=agent,
        tokens=pressure.total_tokens,
        ratio=f"{pressure.ratio:.3f}",
        over_threshold=pressure.over_threshold,
    )

    last_error: Optional[Exception] = None
    for attempt in range(1, settings.max_retries + 1):
        # 【优化 O-8】每次 invoke（含格式修复重试）前统一做预算治理
        messages, report = ctx.enforce_budget(
            messages, llm=llm, session_id=session_id, phase=f"scan.{agent}.attempt-{attempt}"
        )
        if report.acted:
            log_event(
                "scan.context_enforce",
                agent=agent,
                before=report.before_tokens,
                after=report.after_tokens,
                pruned=report.pruned_replacements,
                compact=report.compact_ok,
            )

        # 【健壮性包 B-2】LLM 调用失败（网络 / 鉴权 / 限流）也是可降级失败
        try:
            response = llm.invoke(messages)
        except Exception as exc:
            raise ScanError(f"LLM 调用失败: {type(exc).__name__}: {exc}") from exc
        text = response_text(response)
        try:
            raw = parse_json_object(text)
            return normalize_report(raw, agent, file_path, report_template, finding_template)
        except Exception as exc:  # 自动修复/重试
            last_error = exc
            log_event("scan.repair", level="warn", agent=agent, attempt=attempt, error=str(exc))
            messages.append(AIMessage(content=text))
            messages.append(
                HumanMessage(
                    content="上面的输出不是合法 JSON。请只输出符合 schema 的合法 JSON，不要任何多余内容。"
                )
            )
    raise ScanError(
        f"报告格式修复失败（已重试 {settings.max_retries} 次）: {last_error}"
    )
