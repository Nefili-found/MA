"""模型输出的解析与规范化（JSON 提取 / 报告对齐）。

从 ``agents/__init__.py`` 拆出（20 文档 §5.1-3）。两层：

* ``parse_json_object``：把自由文本里的 JSON 抠出来（平衡花括号扫描，容忍围栏、
  前后散文、多个 JSON 块、字符串内花括号）；
* ``normalize_report`` / ``empty_report``：把抠出来的对象对齐到某视角的报告模板，
  补齐缺失字段、丢弃未知字段——模板是唯一的字段真相。
"""
from __future__ import annotations

import json
from typing import Any, Dict, List

from context import content_to_text
from agents.prompts import report_array_key


def response_text(response: Any) -> str:
    """取模型回复正文，并归一为字符串。

    部分提供商（含本仓库使用的 OpenAI 兼容代理）对 gpt-5.x / 推理模型返回
    content-block 列表而非 str，直接解析会崩；统一在此归一。
    """
    content = getattr(response, "content", None)
    if content is None:
        return str(response)
    return content_to_text(content)


def iter_json_objects(text: str) -> List[str]:
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
    candidates = iter_json_objects(text)
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
    array_key = report_array_key(report_template)
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
    """降级模式骨架：结构完整、findings 为空（保证流水线能跑到 D）。"""
    report = json.loads(json.dumps(report_template))
    if "agent" in report:
        report["agent"] = agent
    if "file" in report:
        report["file"] = file_path
    return report
