"""合并接线回归：不调用模型、不编译、不读取相邻源码。"""
from copy import deepcopy

import pytest

from config import Settings, load_settings
from tools.execution_budget import DEADLINE, bounded_timeout
from verify_agent.execution import ExecutionSession
import verify_agent.signals as signals
import verify_agent.tool_loop as tool_loop


def _result(verdict="challenge"):
    return {"verdict": verdict, "status": "uncertain", "confidence": 0.3,
            "reason": "", "evidence": {"path_status": "reachable"}}


def test_plugin_config_defaults_and_overrides(tmp_path, monkeypatch):
    names = ("dynamic_enabled", "injection_enabled", "injection_runtime_enabled")
    for name in names:
        monkeypatch.delenv("VERIFY_" + name.upper(), raising=False)
        assert getattr(Settings(), "verify_" + name) is False
    config = tmp_path / "settings.yaml"
    config.write_text("verify:\n  dynamic_enabled: true\n  injection_enabled: true\n  injection_runtime_enabled: true\n", encoding="utf-8")
    settings = load_settings(str(config))
    assert all(getattr(settings, "verify_" + name) for name in names)
    monkeypatch.setenv("VERIFY_DYNAMIC_ENABLED", "false")
    assert load_settings(str(config)).verify_dynamic_enabled is False
    # 环境变量优先于配置文件；未配置时三路默认关闭（opt-in）
    monkeypatch.delenv("VERIFY_DYNAMIC_ENABLED", raising=False)
    assert load_settings(str(config)).verify_dynamic_enabled is True


@pytest.mark.parametrize("dynamic,static,runtime", [(False, False, False), (True, True, True),
                                                   (False, True, False), (False, False, True)])
def test_binding_exact_tools(monkeypatch, dynamic, static, runtime):
    tools = [object() for _ in range(7)]
    for name, value in zip(("verify_taint_tool", "dynamic_check_tool", "injection_check_tool",
                            "injection_runtime_tool"), tools):
        monkeypatch.setattr(tool_loop, name, value)
    monkeypatch.setattr(tool_loop, "CONTEXT_TOOLS", tools[4:])
    assert tool_loop.available_tools(dynamic, static, runtime) == (
        [tools[0]] + ([tools[1]] if dynamic else []) + ([tools[2]] if static else [])
        + ([tools[3]] if runtime else []) + tools[4:])


def test_disabled_plugins_never_start_processes(monkeypatch):
    import subprocess
    def fail(*args, **kwargs):
        pytest.fail("关闭时不得执行子进程")
    monkeypatch.setattr(subprocess, "run", fail)
    monkeypatch.setattr(subprocess, "Popen", fail)
    for name in ("dynamic_check", "injection_check", "injection_runtime"):
        result, _ = tool_loop.dispatch_tool(name, {}, {"cwe": "78"}, {"code": "system(cmd);"},
                                             settings=Settings())
        assert result["verdict"] == "uncertain"
        assert result["evidence"]["skipped"] is True


def test_injection_static_does_not_run_probe(monkeypatch):
    calls = []
    monkeypatch.setattr(signals, "verify_taint", lambda h, c: _result())
    monkeypatch.setattr(signals, "injection_check", lambda h, c, **kw: calls.append("static") or _result())
    monkeypatch.setattr(signals, "injection_runtime", lambda h, c, **kw: calls.append("runtime") or _result())
    signals.tool_signal({}, {}, injection_enabled=True)
    assert calls == ["static"]
    calls.clear()
    signals.tool_signal({}, {}, injection_runtime_enabled=True)
    assert calls == ["runtime"]


def test_execution_cache_isolated_and_exact(monkeypatch):
    calls = []
    def tool(h, c):
        calls.append(deepcopy(h))
        return _result()
    session = ExecutionSession("source", Settings())
    h, c = {"finding_id": "A-1", "assumptions": ["x"]}, {"code": "source"}
    first = session.call("verify_taint", tool, h, c)
    first["evidence"]["path_status"] = "corrupted"
    assert session.call("verify_taint", tool, h, c)["evidence"]["path_status"] == "reachable"
    assert len(calls) == 1 and session.records[-1]["cache_hit"]
    session.call("verify_taint", tool, {**h, "assumptions": ["y"]}, c)
    session.call("verify_taint", tool, h, {"code": "different"})
    ExecutionSession("source", Settings()).call("verify_taint", tool, h, c)
    assert len(calls) == 4


def test_execution_failures_and_incomplete_inputs_not_cached():
    calls = []
    def tool(h, c):
        calls.append(1)
        return _result("uncertain")
    session = ExecutionSession("source", Settings())
    for _ in range(2):
        session.call("dynamic_check", tool, {}, {"code": "source"}, )
    assert len(calls) == 2
    def challenge(h, c):
        calls.append(1)
        return _result()
    for _ in range(2):
        session.call("verify_taint", challenge, {}, {})
    assert len(calls) == 4


def test_plugin_source_boundary():
    def fail(*args, **kwargs):
        pytest.fail("不能执行其他源码")
    result = ExecutionSession("source", Settings()).call(
        "dynamic_check", fail, {}, {"code": "other source"}, enabled=True)
    assert result["verdict"] == "uncertain"


def test_signal_and_dispatch_share_results_without_changing_inputs(monkeypatch):
    calls = []
    def tool(h, c, **kwargs):
        calls.append((deepcopy(h), deepcopy(c), kwargs))
        return _result("accept")
    monkeypatch.setattr(signals, "verify_taint", tool)
    monkeypatch.setattr(tool_loop, "verify_taint", tool)
    h, c = {"finding_id": "A-1", "taint_sink": "copy"}, {"code": "source"}
    session = ExecutionSession("source", Settings())
    signals.tool_signal(h, c, execution=session)
    result, record = tool_loop.dispatch_tool("verify_taint", {"hypothesis": h, "context": c},
                                             h, c, settings=Settings(), execution=session)
    assert result["verdict"] == "accept" and record["tool"] == "verify_taint"
    assert calls == [(h, c, {})]
    assert session.records[-1]["cache_hit"] is True
    changed = {**h, "taint_sink": "other"}
    tool_loop.dispatch_tool("verify_taint", {"hypothesis": changed, "context": c}, h, c,
                            settings=Settings(), execution=session)
    assert calls[-1][0] == changed
    assert len(calls) == 2


def test_runtime_cache_requires_actual_harness_and_seed_identity():
    from tools.execution_budget import record_runtime_input
    calls = []
    def runtime(h, c):
        calls.append(h["seed"])
        record_runtime_input({"harness_sha256": "harness-" + str(h["seed"]), "seeds": [h["seed"]]})
        return _result("accept")
    session = ExecutionSession("source", Settings())
    for _ in range(2):
        session.call("injection_runtime", runtime, {"seed": 1}, {"code": "source"})
    assert calls == [1]
    assert session.records[-1]["cache_hit"]
    assert session.records[-1]["input_digest"] == session.records[-2]["input_digest"]
    session.call("injection_runtime", runtime, {"seed": 2}, {"code": "source"})
    assert calls == [1, 2]
    assert session.records[-1]["input_digest"] != session.records[-2]["input_digest"]
    def missing(h, c):
        calls.append("missing")
        return _result("accept")
    for _ in range(2):
        session.call("injection_runtime", missing, {}, {"code": "source"})
    assert calls[-2:] == ["missing", "missing"]


def test_verify_loop_passes_independent_switches_and_session(monkeypatch):
    import verify_agent.verify_loop as loop
    from agents.context_manager import build_context_manager
    seen = {}
    def signal(h, c, **kwargs):
        seen.update(kwargs)
        return _result()
    def invoke(*args, **kwargs):
        assert kwargs["execution"] is seen["execution"]
        return {"tool": "verify_taint"}, _result(), [], None
    monkeypatch.setattr(loop, "tool_signal", signal)
    monkeypatch.setattr(loop, "invoke_verify", invoke)
    monkeypatch.setattr(loop, "write_verification", lambda *args, **kwargs: None)
    settings = Settings(verify_dynamic_enabled=True, verify_injection_enabled=False,
                        verify_injection_runtime_enabled=True)
    result = loop.verify_findings([{"id": "A-1", "location": {"function": "f", "line_start": 1}}],
                                  {"file_path": "one.c", "code": "void f(void) {}"},
                                  "s", None, None, settings, build_context_manager(settings))
    assert len(result) == 1
    assert (seen["dynamic_enabled"], seen["injection_enabled"], seen["injection_runtime_enabled"]) == (True, False, True)


def test_process_timeout_removes_only_own_container(monkeypatch):
    import subprocess
    import tools.execution_budget as budget
    commands, cleanup = [], []
    class Process:
        pid = 12345
        returncode = None
        attempts = 0
        def __init__(self, command, **kwargs):
            commands.append(command)
        def __enter__(self):
            return self
        def __exit__(self, *args):
            pass
        def communicate(self, **kwargs):
            self.attempts += 1
            if self.attempts == 1:
                raise subprocess.TimeoutExpired(commands[0], 1)
            return "", ""
        def kill(self):
            self.returncode = -1
    monkeypatch.setattr(subprocess, "Popen", Process)
    monkeypatch.setattr(subprocess, "run", lambda command, **kw: cleanup.append(command))
    if budget.os.name != "nt":
        monkeypatch.setattr(budget.os, "killpg", lambda *args: None)
    with pytest.raises(subprocess.TimeoutExpired):
        budget.run_process(["docker", "run", "--rm", "--network=none", "image", "program"],
                           timeout=1, capture_output=True)
    name = commands[0][commands[0].index("--name") + 1]
    assert ["docker", "rm", "-f", name] in cleanup
    assert "--network=none" in commands[0] and "--cpus=1" in commands[0]


def test_shared_deadline(monkeypatch):
    import subprocess
    import tools.execution_budget as budget
    monkeypatch.setattr(budget.time, "monotonic", lambda: 10)
    token = DEADLINE.set(15)
    try:
        assert bounded_timeout(60) == 5
        monkeypatch.setattr(budget.time, "monotonic", lambda: 16)
        with pytest.raises(subprocess.TimeoutExpired):
            bounded_timeout(60)
    finally:
        DEADLINE.reset(token)


def test_path_safe_groups_keep_sinks_and_conditions_separate():
    from verify_agent.dedupe import path_safe_groups
    finding = {"cwe": "CWE-787", "location": {"function": "f", "line_start": 5},
               "taint_source": "src", "taint_sink": "dst", "propagation_path": ["f", "copy"],
               "assumptions": [{"id": "A-1", "text": "n > 10", "kind": "bounds_check"}]}
    duplicate = deepcopy(finding)
    duplicate["assumptions"][0]["id"] = "B-2"
    other_sink = {**finding, "taint_sink": "other"}
    other_condition = {**finding, "assumptions": [{"text": "n <= 10", "kind": "bounds_check"}]}
    assert path_safe_groups([finding, duplicate, other_sink, other_condition, {}]) == [[0, 1], [2], [3], [4]]


def test_singleton_skips_model():
    from verify_agent.dedupe import group_indices
    class Model:
        def invoke(self, *args):
            pytest.fail("单条候选不需请求模型")
    assert group_indices([{}], Model()) == [[0]]
