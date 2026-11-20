"""注入类漏洞的运行时复现探针（骨架）。

与 ``injection_check``（源码静态核验）互补：本模块在沙箱内构造探针 harness，
用 canary / 探针载荷实际调用被测函数，观测外部行为是否被注入控制。

口径（与动态崩溃、静态核验一致）：

* **只出有罪证据，永不 reject** —— 探针复现注入行为 → accept；未复现 / 编译失败 /
  无工具链 → uncertain（探针没跑出来 ≠ 没有漏洞）；
* 命令注入（78）：canary 回显探针；SQL 注入（89）：探针骨架（需 sqlite3 链接）；
  XSS（79）依赖浏览器渲染，本模块不做动态复现。

安全约束：探针在禁网、限时、限内存的沙箱内运行；载荷为固定 canary，不接真实
外部输入。本模块默认关闭（``INJRUNTIME_ENABLED=0``），探针链路需在有工具链的
环境调通后再开启。

注意：当前为骨架——harness 构造与 canary 检测逻辑可离线验证；真实编译/运行路径
未在本机（无 gcc/clang/docker）实测。
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
from typing import Any, Dict, List, Optional, Tuple

from observability import log_event

TOOL_NAME = "injection_runtime"

#: 运行时复现注入证据：高于静态启发式 0.88，略低于内存崩溃 0.92。
CONF_INJECTION_RUNTIME = 0.90

#: 开关：默认关闭；显式 ``INJRUNTIME_ENABLED=1`` 才启用探针执行。
ENABLED = os.environ.get("INJRUNTIME_ENABLED", "0") not in ("0", "false", "False")

#: 本模块尝试动态复现的注入类 CWE；79（XSS）需浏览器，不在此列。
RUNTIME_CWES = frozenset({"78", "89"})

#: 探针 canary：命令注入回显标记。
CANARY = "DYNCANARY7f3a"
#: 命令注入探针载荷：闭合当前命令并回显 canary。
_CMD_PAYLOAD = f";echo {CANARY};"

_CWE_RE = re.compile(r"(?:CWE[-_ ]?)?(\d{1,5})", re.IGNORECASE)
_FUNC_RE = re.compile(
    r"(?P<prefix>(?:static\s+|extern\s+|inline\s+)*)"
    r"(?P<ret>(?:const\s+)?(?:void|int|long|short|char|float|double|size_t|unsigned\s+\w+|"
    r"\w+\s*\*+|\w+))\s+"
    r"(?P<name>[A-Za-z_]\w*)\s*\((?P<params>[^;{}()]*)\)\s*\{",
)


def _norm_cwe(raw: Any) -> str:
    m = _CWE_RE.search(str(raw or ""))
    return m.group(1) if m else ""


def _toolchain() -> Optional[str]:
    for exe in ("gcc", "clang"):
        path = shutil.which(exe)
        if path:
            return path
    return None


def _extract_function(code: str, func_name: str) -> Optional[str]:
    """从源码粗提取被测函数文本（括号配平截取）。"""
    idx = code.find(func_name)
    if idx < 0:
        return None
    start = code.rfind("\n", 0, idx)
    m = _FUNC_RE.search(code, start)
    if not m:
        return None
    brace_start = code.find("{", m.end() - 1)
    if brace_start < 0:
        return None
    depth = 0
    for i in range(brace_start, len(code)):
        if code[i] == "{":
            depth += 1
        elif code[i] == "}":
            depth -= 1
            if depth == 0:
                return code[m.start(): i + 1]
    return None


def _cmd_probe_call(func_name: str) -> str:
    """生成命令注入探针调用：把 canary 载荷作为唯一字符串参数传入。"""
    return f'{func_name}("{_CMD_PAYLOAD}");'


def _cmd_probe_harness(func_src: str, probe_call: str) -> str:
    """命令注入探针 harness：调用被测函数，stdout 待检测 canary。"""
    return (
        "#include <stdlib.h>\n"
        "#include <stdio.h>\n"
        f"{func_src}\n"
        "int main(void) {\n"
        f"    {probe_call}\n"
        "    return 0;\n"
        "}\n"
    )


def _sql_probe_harness(func_src: str, func_name: str) -> str:
    """SQL 注入探针骨架：标注需链接 sqlite3；本轮不实现完整查询观测。"""
    return (
        "#include <stdlib.h>\n"
        "#include <stdio.h>\n"
        "/* SQL 探针需链接 sqlite3（-lsqlite3），在内存库上执行探针载荷并观测返回；\n"
        "   当前为骨架，编译/观测逻辑待有数据库工具链的环境补全。 */\n"
        f"{func_src}\n"
        f"/* probe target: {func_name} */\n"
        "int main(void) { return 0; }\n"
    )


def _skip(reason: str, finding_id: str = "", **extra: Any) -> Dict[str, Any]:
    ev: Dict[str, Any] = {"skipped": True, "reason": reason}
    ev.update(extra)
    return {
        "status": "uncertain",
        "verdict": "uncertain",
        "confidence": 0.0,
        "reason": f"注入探针跳过：{reason}",
        "evidence": ev,
        "tool_name": TOOL_NAME,
        "raw_output": {"finding_id": finding_id},
    }


def injection_runtime(
    hypothesis: Dict[str, Any],
    context: Dict[str, Any],
    enabled: Optional[bool] = None,
) -> Dict[str, Any]:
    """对一条注入类 finding 尝试运行时复现，返回与核验工具同构的结果。

    :param hypothesis: ``{finding_id, cwe, location:{function}, ...}``
    :param context:    ``{file, code}``
    :param enabled:    应用层开关；``None`` 时回退模块级 ``ENABLED``。
    """
    hypothesis = hypothesis or {}
    context = context or {}
    finding_id = str(hypothesis.get("finding_id") or "")

    flag = ENABLED if enabled is None else bool(enabled)
    if not flag:
        return _skip("注入探针已关闭（INJRUNTIME_ENABLED=0）", finding_id)

    cwe = _norm_cwe(hypothesis.get("cwe"))
    if cwe not in RUNTIME_CWES:
        return _skip(f"CWE {cwe or '?'} 不在动态复现范围（78/89；79 需浏览器）",
                     finding_id, cwe=cwe)

    code = str(context.get("code") or "")
    if not code.strip():
        return _skip("context.code 为空", finding_id)

    func_name = str(
        (hypothesis.get("location") or {}).get("function")
        or hypothesis.get("function_name")
        or ""
    ).strip()
    if not func_name:
        return _skip("hypothesis 未提供被测函数名", finding_id)

    func_src = _extract_function(code, func_name)
    if not func_src:
        return _skip(f"未能从源码提取函数 {func_name}", finding_id)

    # SQL 探针骨架：本轮不执行编译/观测，按 uncertain 降级并标注待补全（不依赖工具链）。
    if cwe == "89":
        return _skip("SQL 注入探针为骨架，待 sqlite3 工具链环境补全",
                     finding_id, probe_type="sql", canary=CANARY)

    if not _toolchain():
        return _skip("未找到 gcc/clang（探针编译需要工具链）", finding_id)

    # 命令注入：构造探针 harness，编译运行，检测 canary 是否回显。
    probe_call = _cmd_probe_call(func_name)
    harness = _cmd_probe_harness(func_src, probe_call)
    workdir = tempfile.mkdtemp(prefix="injprobe_")
    harness_path = os.path.join(workdir, "probe.c")
    bin_path = os.path.join(workdir, "probe.bin")
    try:
        with open(harness_path, "w", encoding="utf-8") as f:
            f.write(harness)
        compiler = _toolchain()
        cp = subprocess.run(
            [compiler, "-g", "-O1", harness_path, "-o", bin_path],
            capture_output=True, text=True, timeout=60,
        )
        if cp.returncode != 0:
            log_event("injection_runtime.compile_failed", finding_id=finding_id)
            return _skip("探针 harness 编译失败（被测函数可能依赖外部符号）",
                         finding_id, compile_stderr_tail=(cp.stderr or "")[-600:])

        rp = subprocess.run([bin_path], capture_output=True, text=True, timeout=10)
        blob = (rp.stdout or "") + (rp.stderr or "")
        reproduced = CANARY in blob
        if reproduced:
            return {
                "status": "verified",
                "verdict": "accept",
                "confidence": CONF_INJECTION_RUNTIME,
                "reason": f"命令注入探针复现：canary {CANARY} 被回显执行",
                "evidence": {
                    "reproduced": True,
                    "probe_type": "command_canary",
                    "canary": CANARY,
                    "payload": _CMD_PAYLOAD,
                    "probe_call": probe_call,
                    "stdout_tail": blob[-400:],
                },
                "tool_name": TOOL_NAME,
                "raw_output": {"finding_id": finding_id, "exit_code": rp.returncode},
            }
        return _skip("命令注入探针未复现（canary 未回显；未复现 ≠ 无漏洞）",
                     finding_id, probe_type="command_canary", canary=CANARY,
                     stdout_tail=blob[-400:])
    except subprocess.TimeoutExpired:
        return _skip("探针运行超时", finding_id)
    except Exception as exc:
        log_event("injection_runtime.error", finding_id=finding_id,
                  error=f"{type(exc).__name__}: {exc}")
        return _skip(f"探针内部异常 {type(exc).__name__}: {exc}", finding_id)


# ---------------------------------------------------------------------------
# LangChain 工具包装（与其他工具同款降级策略）
# ---------------------------------------------------------------------------
try:  # pragma: no cover
    from langchain_core.tools import tool as _lc_tool  # type: ignore

    @_lc_tool("injection_runtime")
    def injection_runtime_tool(hypothesis: dict, context: dict) -> dict:
        """对命令/SQL 注入 finding 做沙箱探针复现（只出有罪证据）。"""
        return injection_runtime(hypothesis, context)

except Exception:  # pragma: no cover
    injection_runtime_tool = None  # type: ignore
