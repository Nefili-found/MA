"""注入类漏洞的运行时复现探针。

与 ``injection_check``（源码静态核验）互补：本模块在沙箱内构造探针 harness，
用 canary / 探针载荷实际调用被测函数，观测外部行为是否被注入控制。

口径（与动态崩溃、静态核验一致）：

* **只出有罪证据，永不 reject** —— 探针复现注入行为 → accept；未复现 / 编译失败 /
  无工具链 → uncertain（探针没跑出来 ≠ 没有漏洞）；
* 命令注入（78）：canary 回显探针，载荷经 ``system``/``popen`` 类接口回显到 stdout；
* SQL 注入（89）：链接 sqlite3，在内存库上执行探针载荷，观测布尔绕过返回行数 /
  拼接痕迹；
* XSS（79）依赖浏览器渲染，本模块不做动态复现。

安全约束：探针在禁网、限时、限内存的沙箱内运行；载荷为固定 canary，不接真实
外部输入。本模块默认关闭（``INJRUNTIME_ENABLED=0``）。

工具链口径与 ``dynamic_check`` 一致：``DYNCHECK_CC`` 显式路径 → PATH 中 clang →
gcc。SQL 探针需要 ``-lsqlite3`` 与 sqlite3 开发头；本机便携工具链未携带该开发库，
链接失败时按 uncertain 降级，待 Linux/WSL 口径（装 libsqlite3-dev）实测调通。
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

#: 命令注入探针 canary：载荷闭合当前命令并回显该标记。
CANARY = "DYNCANARY7f3a"
#: 命令注入探针载荷：闭合当前命令并回显 canary。
_CMD_PAYLOAD = f";echo {CANARY};"

#: SQL 注入探针载荷：闭合字符串字面量，布尔绕过注释后续语句。
_SQL_PAYLOAD = "' OR '1'='1' -- "
#: SQL 探针基准行标记，内存库初始仅插入这一行。
_SQL_MARK = "SQLPROBE_BASE"
#: SQL 探针可执行的最少返回行数（基准 1 行；布尔绕过 >1 行视为复现）。
_SQL_ROW_THRESHOLD = 1

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
    """探测可用 C 工具链；返回编译器路径，都没有则 None。

    优先级：``DYNCHECK_CC`` 显式路径 → PATH 中的 clang → gcc，口径同 dynamic_check。
    """
    cc_env = os.environ.get("DYNCHECK_CC", "").strip()
    if cc_env and os.path.exists(cc_env):
        return cc_env
    for exe in ("clang", "gcc"):
        path = shutil.which(exe)
        if path:
            return path
    return None


def _local_env(compiler: Optional[str]) -> Dict[str, str]:
    """本地子进程环境：PATH 前置编译器 bin 目录，确保运行库可被加载。"""
    env = dict(os.environ)
    if compiler:
        bin_dir = os.path.dirname(compiler)
        if bin_dir:
            env["PATH"] = bin_dir + os.pathsep + env.get("PATH", "")
    return env


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


def _parse_params(func_src: str) -> List[str]:
    """从函数签名括号内提取形参声明列表（按逗号切分，保留原始声明文本）。"""
    m = _FUNC_RE.search(func_src)
    if not m:
        return []
    raw = m.group("params").strip()
    if not raw:
        return []
    return [p.strip() for p in raw.split(",") if p.strip()]


def _cmd_probe_call(func_name: str, params: List[str]) -> str:
    """命令注入探针调用：首个 char* 形参传 canary 载荷，其余 char* 传空串，其余类型传 0。"""
    args: List[str] = []
    payload_used = False
    for decl in params:
        if "char" in decl and "*" in decl:
            if not payload_used:
                args.append(f'"{_CMD_PAYLOAD}"')
                payload_used = True
            else:
                args.append('""')
        else:
            args.append("0")
    if not params:
        args.append(f'"{_CMD_PAYLOAD}"')
    return f"{func_name}({', '.join(args)});"


def _cmd_probe_harness(func_src: str, probe_call: str) -> str:
    """命令注入探针 harness：调用被测函数，stdout/stderr 待检测 canary 回显。"""
    return (
        "#include <stdlib.h>\n"
        "#include <stdio.h>\n"
        f"{func_src}\n"
        "int main(void) {\n"
        f"    {probe_call}\n"
        "    return 0;\n"
        "}\n"
    )


def _sql_mode(func_src: str) -> str:
    """判断 SQL 被测形态：首参 sqlite3* 或函数体调 sqlite3_exec → ``exec``；否则 ``build``。"""
    params = _parse_params(func_src)
    first_is_db = bool(params) and "sqlite3" in params[0]
    if first_is_db or "sqlite3_exec" in func_src:
        return "exec"
    return "build"


def _sql_probe_harness(func_src: str, func_name: str, mode: str) -> str:
    """SQL 注入探针 harness：在内存库上执行探针载荷，输出可观测信号。

    * ``exec``：被测函数接收 ``sqlite3*`` 并直接执行语句；harness 建表插基准行后调用，
      再统计 ``probe_t`` 行数（布尔绕过 >1 行视为复现）。
    * ``build``：被测函数返回拼接后的 SQL 串；harness 打印该串并尝试执行，观测载荷
      是否原样进入拼接结果。
    """
    if mode == "exec":
        body = (
            "    sqlite3_exec(db, \"CREATE TABLE probe_t(id INTEGER, note TEXT)\", NULL, NULL, NULL);\n"
            f"    sqlite3_exec(db, \"INSERT INTO probe_t VALUES(1, '{_SQL_MARK}')\", NULL, NULL, NULL);\n"
            f"    {func_name}(db, \"{_SQL_PAYLOAD}\");\n"
            "    printf(\"COUNT=%d\\n\", _sql_count(db));\n"
        )
        helpers = (
            "static int _sql_count(sqlite3 *db) {\n"
            "    sqlite3_stmt *st = NULL;\n"
            "    int n = 0;\n"
            "    if (sqlite3_prepare_v2(db, \"SELECT count(*) FROM probe_t\", -1, &st, NULL) == SQLITE_OK) {\n"
            "        if (sqlite3_step(st) == SQLITE_ROW) n = sqlite3_column_int(st, 0);\n"
            "        sqlite3_finalize(st);\n"
            "    }\n"
            "    return n;\n"
            "}\n"
        )
    else:
        body = (
            f"    const char *sql = {func_name}(\"{_SQL_PAYLOAD}\");\n"
            "    printf(\"SQL>%s\\n\", sql ? sql : \"(null)\");\n"
            "    char *err = NULL;\n"
            "    if (sqlite3_exec(db, sql ? sql : \"\", NULL, NULL, &err) != SQLITE_OK) {\n"
            "        fprintf(stderr, \"SQL_ERR: %s\\n\", err ? err : \"?\");\n"
            "        sqlite3_free(err);\n"
            "    }\n"
        )
        helpers = ""
    return (
        "#include <stdlib.h>\n"
        "#include <stdio.h>\n"
        "#include <sqlite3.h>\n"
        f"{func_src}\n"
        f"{helpers}"
        "int main(void) {\n"
        "    sqlite3 *db = NULL;\n"
        "    if (sqlite3_open(\":memory:\", &db) != SQLITE_OK) { fprintf(stderr, \"DB_OPEN_FAIL\\n\"); return 2; }\n"
        f"{body}"
        "    sqlite3_close(db);\n"
        "    return 0;\n"
        "}\n"
    )


def _cmd_reproduced(blob: str) -> bool:
    """命令注入有罪信号：canary 经命令回显出现在输出中。"""
    return CANARY in blob


def _sql_reproduced(blob: str, mode: str) -> bool:
    """SQL 注入有罪信号。

    * ``build``：拼接结果原样带出布尔绕过载荷片段；
    * ``exec``：探针表返回行数大于基准 1 行（布尔绕过）。
    """
    if mode == "build":
        return "' OR '1'='1" in blob
    m = re.search(r"COUNT=(\d+)", blob)
    return bool(m and int(m.group(1)) > _SQL_ROW_THRESHOLD)


def _compile_and_run(
    compiler: str,
    harness_src: str,
    extra_libs: List[str],
    run_timeout: int = 10,
) -> Dict[str, Any]:
    """编译并运行探针 harness，返回统一结果字典；临时目录用完兜底清理。

    返回键：``stage``（compile/run）、``blob``、``run_rc``、``compile_tail``。
    """
    workdir = tempfile.mkdtemp(prefix="injprobe_")
    harness_path = os.path.join(workdir, "probe.c")
    bin_path = os.path.join(workdir, "probe.bin")
    env = _local_env(compiler)
    try:
        with open(harness_path, "w", encoding="utf-8") as f:
            f.write(harness_src)
        cp = subprocess.run(
            [compiler, "-g", "-O1", harness_path, "-o", bin_path, *extra_libs],
            capture_output=True, text=True, timeout=60, env=env,
        )
        if cp.returncode != 0:
            return {"stage": "compile", "blob": "", "run_rc": None,
                    "compile_tail": (cp.stderr or "")[-600:]}
        rp = subprocess.run(
            [bin_path], capture_output=True, text=True, timeout=run_timeout, env=env,
        )
        blob = (rp.stdout or "") + (rp.stderr or "")
        return {"stage": "run", "blob": blob, "run_rc": rp.returncode, "compile_tail": ""}
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


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

    compiler = _toolchain()
    if not compiler:
        return _skip("未找到 gcc/clang（探针编译需要工具链）", finding_id)

    try:
        if cwe == "78":
            params = _parse_params(func_src)
            probe_call = _cmd_probe_call(func_name, params)
            harness = _cmd_probe_harness(func_src, probe_call)
            extra_libs: List[str] = []
            probe_type = "command_canary"

            def reproduced(blob: str) -> bool:
                return _cmd_reproduced(blob)

            mode: Optional[str] = None
        else:
            mode = _sql_mode(func_src)
            harness = _sql_probe_harness(func_src, func_name, mode)
            extra_libs = ["-lsqlite3"]
            probe_type = "sql_injection"

            def reproduced(blob: str) -> bool:
                return _sql_reproduced(blob, mode)

            probe_call = f'{func_name}("{_SQL_PAYLOAD}")'

        result = _compile_and_run(compiler, harness, extra_libs)
        if result["stage"] == "compile":
            log_event("injection_runtime.compile_failed", finding_id=finding_id)
            hint = "（SQL 探针可能缺 sqlite3 开发库，需在装 libsqlite3-dev 的 Linux/WSL 口径链接）" if cwe == "89" else ""
            return _skip(f"探针 harness 编译/链接失败{hint}", finding_id,
                         probe_type=probe_type, mode=mode,
                         compile_stderr_tail=result["compile_tail"])

        blob = result["blob"]
        if reproduced(blob):
            return {
                "status": "verified",
                "verdict": "accept",
                "confidence": CONF_INJECTION_RUNTIME,
                "reason": (
                    f"命令注入探针复现：canary {CANARY} 被回显执行"
                    if cwe == "78"
                    else f"SQL 注入探针复现：载荷进入语句并触发可观测信号（{mode}）"
                ),
                "evidence": {
                    "reproduced": True,
                    "probe_type": probe_type,
                    "canary": CANARY,
                    "payload": _CMD_PAYLOAD if cwe == "78" else _SQL_PAYLOAD,
                    "mode": mode,
                    "probe_call": probe_call,
                    "stdout_tail": blob[-400:],
                },
                "tool_name": TOOL_NAME,
                "raw_output": {"finding_id": finding_id, "exit_code": result["run_rc"]},
            }
        return _skip("探针未复现注入行为（未复现 ≠ 无漏洞）",
                     finding_id, probe_type=probe_type, mode=mode,
                     canary=CANARY, stdout_tail=blob[-400:])
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
