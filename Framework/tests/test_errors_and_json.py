# -*- coding: utf-8 -*-
"""健壮性包 B 的离线自测：错误分级 / 结构化日志 / JSON 解析加固。

运行（在 Framework 根目录）：
    .venv/Scripts/python.exe tests/test_errors_and_json.py

覆盖：
    1. parse_json_object：字符串里的花括号不再干扰边界；
    2. parse_json_object：同一回复多个 JSON 块时逐个尝试、取第一个可解析的；
    3. parse_json_object：``` 围栏与前后散文照旧可用；
    4. parse_json_object：被截断的未闭合对象 → ValueError（带片段预览）；
    5. parse_json_object：顶层是数组 / 完全没有 JSON → ValueError；
    6. ScanError：LLM 调用抛错 → A 降级为空报告 + errors 非空 + 不崩图；
    7. ScanError：模型始终不吐合法 JSON → 重试耗尽后降级，而不是抛 RuntimeError；
    8. VerifyError：单条 finding 工具失败只隔离该条，其余照常验证，errors 有记录；
    9. FatalError：D 缺报告 → 抛 FatalError（exit_code = 2），不是 RuntimeError；
   10. 日志：json 格式可被 json.loads 解析、带 ts/level/event；text 格式保持旧形态；
   11. 日志：level 过滤生效（log_level=warn 时 info 事件被丢弃）。

全部通过会打印 ALL_TESTS_PASS 并以退出码 0 结束。
"""
from __future__ import annotations

import contextlib
import io
import json
import pathlib
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import agents as agents_pkg  # noqa: E402
import agents.a as agent_a  # noqa: E402
import verify_agent.d as d  # noqa: E402
import verify_agent.verify_loop as verify_loop  # noqa: E402
from agents import _iter_json_objects, parse_json_object  # noqa: E402
from config import load_settings  # noqa: E402
from errors import FatalError, PipelineError, ScanError, VerifyError  # noqa: E402
from memory import db as mem_db  # noqa: E402
from observability import configure_logging, log_event  # noqa: E402

# 与 test_verify_signals.py 同一份样例（行号 1-based）
CODE = """int sink(char *p) { return p ? *p : 0; }

int gate(char *raw) {
  if (raw == NULL) return -1;
  return sink(raw);
}

int direct(char *raw) {
  return sink(raw);
}
"""


def check(name: str, fn) -> None:
    fn()
    print(f"  ok  {name}")


# ---------------------------------------------------------------------------
# 1-5. JSON 解析加固
# ---------------------------------------------------------------------------
def t_braces_inside_string() -> None:
    text = '前缀 {"reason": "guard { not closed", "ok": true} 后缀'
    assert parse_json_object(text) == {"reason": "guard { not closed", "ok": True}


def t_multiple_objects() -> None:
    # 第一个候选是坏 JSON（``"a": }``），第二个才合法 → 取第二个
    text = '{"broken": } 一些散文 {"verdict": "accept", "confidence": 0.9}'
    assert _iter_json_objects(text) == ['{"broken": }', '{"verdict": "accept", "confidence": 0.9}']
    assert parse_json_object(text)["verdict"] == "accept"


def t_fenced_and_noise() -> None:
    text = '这是模型解释。\n```json\n{"final_confidence": 0.5, "reason": "x"}\n```\n结束。'
    assert parse_json_object(text) == {"final_confidence": 0.5, "reason": "x"}


def t_truncated_object() -> None:
    text = '{"verdict": "accept", "confidence": 0.'
    assert _iter_json_objects(text) == []
    try:
        parse_json_object(text)
    except ValueError as exc:
        assert "输出片段" in str(exc), exc
    else:  # pragma: no cover
        raise AssertionError("截断的 JSON 应该报错")


def t_no_object() -> None:
    for text in ('["a", "b"]', "抱歉，我无法完成。", ""):
        try:
            parse_json_object(text)
        except ValueError:
            continue
        raise AssertionError(f"应当报错: {text!r}")


# ---------------------------------------------------------------------------
# 6-7. ScanError → 降级
# ---------------------------------------------------------------------------
class _RaisingLLM:
    """invoke 直接抛错（模拟鉴权失败 / 限流 / 网络断）。"""

    def invoke(self, messages):  # noqa: ANN001
        raise RuntimeError("502 rate limited")


class _NotJsonLLM:
    """永远回非 JSON 文本，逼出「格式修复重试耗尽」这条路径。"""

    class _Resp:
        content = "我觉得这个函数有漏洞，但没有 JSON。"

    def invoke(self, messages):  # noqa: ANN001
        return self._Resp()


def _run_with_fake_llm(fake, state):  # noqa: ANN001
    settings = load_settings()
    settings.max_retries = 1
    old_llm, old_settings = agents_pkg.get_llm, agents_pkg.load_settings
    agents_pkg.get_llm = lambda _s=None: fake
    agents_pkg.load_settings = lambda *_a, **_k: settings
    try:
        return agent_a.run(state)
    finally:
        agents_pkg.get_llm, agents_pkg.load_settings = old_llm, old_settings


def _state() -> dict:
    return {
        "file_path": "t.c",
        "code": "int main(void) { return 0; }\n",
        "session_id": "sess-b2",
        "reports": {},
        "errors": [],
    }


def t_scan_error_degrades() -> None:
    out = _run_with_fake_llm(_RaisingLLM(), _state())
    report = out["reports"]["A"]
    assert report["findings"] == [], report
    assert out["errors"] and "LLM 调用失败" in out["errors"][0], out["errors"]


def t_scan_bad_json_degrades() -> None:
    out = _run_with_fake_llm(_NotJsonLLM(), _state())
    assert out["reports"]["A"]["findings"] == [], out["reports"]["A"]
    assert out["errors"] and "格式修复失败" in out["errors"][0], out["errors"]


# ---------------------------------------------------------------------------
# 8. VerifyError → 单条隔离
# ---------------------------------------------------------------------------
def t_verify_error_isolates() -> None:
    settings = load_settings()
    path = pathlib.Path(tempfile.mkdtemp()) / "b2.db"
    conn = mem_db.get_connection(path)
    ctx = d.build_context_manager(settings)
    findings = [
        {
            "id": "A-1",
            "propagation_path": ["gate", "sink"],
            "location": {"file": "t.c", "line_start": 5, "line_end": 5, "function": "gate"},
        },
        {
            "id": "B-1",
            "propagation_path": ["direct", "sink"],
            "location": {"file": "t.c", "line_start": 9, "line_end": 9, "function": "direct"},
        },
    ]
    state = {"file_path": "t.c", "code": CODE, "session_id": "sess-b2"}

    # 拆分后 _verify_findings 住在 verify_agent.verify_loop，补丁要打在它真正查找的模块上
    original = verify_loop.invoke_verify

    def fake_invoke(hypothesis, context, llm, settings, ctx, session_id, finding_idx):  # noqa: ANN001
        if finding_idx == 0:
            raise VerifyError("模拟工具循环失败")
        return (
            {"tool": "mock", "args": {}},
            {"status": "uncertain", "reason": "mock"},
            [],
            None,
        )

    verify_loop.invoke_verify = fake_invoke
    errors: list = []
    try:
        out = d._verify_findings(findings, state, "sess-b2", conn, None, settings, ctx, errors=errors)
    finally:
        verify_loop.invoke_verify = original
        conn.close()

    assert [f["id"] for f in out] == ["A-1", "B-1"], out
    assert out[0]["verification_status"] == "uncertain", out[0]
    assert out[0]["verify_error"] == "模拟工具循环失败", out[0]
    assert "verify_error" not in out[1], out[1]
    assert errors and errors[0].startswith("verify:A-1"), errors


# ---------------------------------------------------------------------------
# 9. FatalError
# ---------------------------------------------------------------------------
def t_missing_reports_is_fatal() -> None:
    assert issubclass(FatalError, PipelineError)
    assert FatalError.exit_code == 2
    try:
        d.run({"reports": {"A": {}}, "session_id": "s", "code": "", "file_path": "t.c"})
    except FatalError as exc:
        assert "缺失" in str(exc), exc
    else:  # pragma: no cover
        raise AssertionError("缺报告应当抛 FatalError")
    # 三个错误类型互不包含，避免 except 顺序踩坑
    assert not issubclass(ScanError, VerifyError)
    assert not issubclass(VerifyError, ScanError)


# ---------------------------------------------------------------------------
# 10-11. 日志
# ---------------------------------------------------------------------------
def _capture(fn) -> str:  # noqa: ANN001
    buf = io.StringIO()
    with contextlib.redirect_stderr(buf):
        fn()
    return buf.getvalue()


def t_log_json_format() -> None:
    configure_logging(log_format="json", log_level="info")
    out = _capture(lambda: log_event("scan.done", agent="A", findings=2))
    line = out.strip().splitlines()[-1]
    record = json.loads(line)
    assert record["event"] == "scan.done", record
    assert record["level"] == "info", record
    assert record["agent"] == "A" and record["findings"] == 2, record
    assert "ts" in record, record


def t_log_text_format() -> None:
    configure_logging(log_format="text", log_level="info")
    out = _capture(lambda: log_event("scan.done", agent="A", findings=2))
    assert out.strip().endswith("[event] scan.done agent=A findings=2"), out


def t_log_level_filter() -> None:
    configure_logging(log_format="text", log_level="warn")
    quiet = _capture(lambda: log_event("scan.done"))
    loud = _capture(lambda: log_event("scan.degraded", level="warn", agent="A"))
    assert quiet == "", quiet
    assert "scan.degraded" in loud, loud
    configure_logging(log_format="json", log_level="info")  # 还原默认


def main() -> int:
    print("=== 健壮性包 B：错误分级 / 日志 / JSON 解析 自测 ===")
    check("JSON：字符串内的花括号不干扰边界", t_braces_inside_string)
    check("JSON：多个对象逐个尝试", t_multiple_objects)
    check("JSON：``` 围栏与前后散文", t_fenced_and_noise)
    check("JSON：截断对象报错并给片段", t_truncated_object)
    check("JSON：无对象 / 空串报错", t_no_object)
    check("ScanError：LLM 调用失败降级为空报告", t_scan_error_degrades)
    check("ScanError：格式修复耗尽降级", t_scan_bad_json_degrades)
    check("VerifyError：单条隔离，其余照常", t_verify_error_isolates)
    check("FatalError：缺报告中止", t_missing_reports_is_fatal)
    check("日志：json 格式可解析", t_log_json_format)
    check("日志：text 格式保持旧形态", t_log_text_format)
    check("日志：level 过滤生效", t_log_level_filter)
    print("ALL_TESTS_PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
