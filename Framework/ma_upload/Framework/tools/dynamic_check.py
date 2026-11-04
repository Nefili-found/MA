"""D 阶段动态验证工具：AutoSafeCoder 式 fuzzing「有罪证据」。

设计依据（与前期讨论一致，且与本仓库 verify_taint 的"证据哲学"对齐）：

* **只做第二阶段、只对内存类 CWE 启用** —— 静态 verify_taint 先跑；
  只有 hypothesis 的 CWE 属于运行时可复现的内存类缺陷（越界 / UAF / 双重释放 /
  溢出相关），才进入动态验证；
* **沙箱内编译 + 运行** —— 本机优先 gcc，其次 clang；均缺失时优雅降级
  （返回 uncertain，不抛错、不拖垮整图）；生产环境可挂 Docker；
* **只产出「有罪证据」，永远不产出「无罪判决」** ——
  跑出 ASan / 段错误 = accept（0.92，硬证据）；
  没跑出来 = uncertain（0.0），绝不 reject。没崩 ≠ 没漏洞，fuzz 覆盖率有限。

方法映射自 AutoSafeCoder（arXiv:2409.10737）Fuzzing Agent：
LLM 种子输入 → 类型感知变异 → 提取被测函数嵌入可运行 harness →
逐个喂入并监控 exit code / stderr → 崩溃种子连同错误上下文保留为证据。
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
from typing import Any, Dict, List, Optional, Tuple

from observability import log_event

TOOL_NAME = "dynamic_check"

# ---------------------------------------------------------------------------
# 置信度常量
# ---------------------------------------------------------------------------
#: 动态跑出 ASan/崩溃 = 硬证据，高于默认 tau(0.8)；与 verify_taint 的
#: CONF_PATH_BROKEN(0.90) 同档，构成 D 层的"可推翻/可定案"级证据。
CONF_DYNAMIC_CRASH = 0.92

#: 只对这类 CWE 做动态验证：运行时真崩的内存类缺陷。
#: 注入 / 命令执行 / 竞态 / 逻辑漏洞等无法靠喂输入复现的一律跳过。
MEMORY_CWES = frozenset({
    "119",  # Improper Restriction of Operations within the Memory Bounds
    "120",  # Classic Buffer Overflow
    "125",  # Out-of-bounds Read
    "126",  # Buffer Over-read
    "127",  # Buffer Under-read
    "787",  # Out-of-bounds Write
    "805",  # Buffer Access with Incorrect Length Value
    "122",  # Heap-based Buffer Overflow
    "121",  # Stack-based Buffer Overflow
    "190",  # Integer Overflow or Wraparound
    "191",  # Integer Underflow
    "415",  # Double Free
    "416",  # Use After Free
    "417",  # Incorrect Update of Resource Management (login ghost / misc)
    "134",  # Uncontrolled Format String
})

#: 单次运行超时秒数（AutoSafeCoder 取 6s；这里取 5s 更保守）
RUN_TIMEOUT = float(os.environ.get("DYNCHECK_TIMEOUT", "5"))
#: 变异输入轮数上限（AutoSafeCoder 跑 150 轮；单 finding 静态先行，这里取小值控成本）
MAX_ITERATIONS = int(os.environ.get("DYNCHECK_MAX_ITER", "24"))
#: 全局开关：显式关闭时直接跳过（默认开启，由工具链存在性自动兜底）
ENABLED = os.environ.get("DYNCHECK_ENABLED", "1") not in ("0", "false", "False")

# ---------------------------------------------------------------------------
# Docker 沙箱模式
# ---------------------------------------------------------------------------
#: 镜像名（构建见 Framework/docker/Dockerfile.dyncheck）
DOCKER_IMAGE = os.environ.get("DYNCHECK_IMAGE", "ma-dyncheck:latest")
#: auto = 有 docker 命令就走容器；on/off 强制
DOCKER_MODE = os.environ.get("DYNCHECK_DOCKER", "auto")


def _docker_available() -> bool:
    """探测 docker 是否可用（DOCKER_MODE=on 时只要求命令存在）。"""
    if DOCKER_MODE == "off":
        return False
    return shutil.which("docker") is not None


def _win_mount(path: str) -> str:
    """Windows 路径转 docker -v 挂载格式（C:\\a\\b → /c/a/b 风格正斜杠）。"""
    return os.path.abspath(path).replace("\\", "/")

_CWE_RE = re.compile(r"(?:CWE[-_ ]?)?(\d{1,5})", re.IGNORECASE)
# 函数定义签名：  rettype funcname ( params )  {
_FUNC_RE = re.compile(
    r"(?P<prefix>(?:static\s+|extern\s+|inline\s+)*)"
    r"(?P<ret>(?:const\s+)?(?:void|int|long|short|char|float|double|size_t|unsigned\s+\w+|"
    r"\w+\s*\*+|\w+))\s+"
    r"(?P<name>[A-Za-z_]\w*)\s*\((?P<params>[^;{}()]*)\)\s*\{",
)
# ASan / 崩溃标志
_CRASH_MARKS = (
    "ERROR: AddressSanitizer",
    "SEGV",
    "heap-buffer-overflow",
    "stack-buffer-overflow",
    "use-after-free",
    "heap-use-after-free",
    "stack-use-after-return",
    "double-free",
    "attempting free on address",
    "runtime error:",  # UBSan
)


# ---------------------------------------------------------------------------
# 小工具
# ---------------------------------------------------------------------------
def _norm_cwe(raw: Any) -> str:
    """从 hypothesis 的 cwe 字段抽出数字编号；抽不到返回 ''。"""
    m = _CWE_RE.search(str(raw or ""))
    return m.group(1) if m else ""


def _is_memory_cwe(hypothesis: Dict[str, Any]) -> bool:
    return _norm_cwe(hypothesis.get("cwe")) in MEMORY_CWES


def _toolchain() -> Optional[str]:
    """探测可用 C 工具链；返回编译器路径，都没有则 None。"""
    for exe in ("gcc", "clang"):
        path = shutil.which(exe)
        if path:
            return path
    return None


def _split_params(params: str) -> List[str]:
    return [p.strip() for p in params.split(",") if p.strip()]


def _param_kind(p: str) -> str:
    """参数分类：ptr / int / other。用于生成危险种子。"""
    pn = p.replace("const", "").strip()
    if "*" in pn:
        return "ptr"
    if re.search(r"\b(int|long|short|size_t|unsigned|uint|intptr_t|ssize_t)\b", pn):
        return "int"
    return "other"


def _gen_calls(func_name: str, params: List[str]) -> List[str]:
    """为被测函数生成类型感知变异的调用语句列表。

    AutoSafeCoder 的 type-aware mutation 移植：int 类给 0/-1/极大值；
    指针类给 malloc 出的异常尺寸缓冲区；other（struct/枚举）给 0/NULL。
    """
    kinds = [_param_kind(p) for p in params]
    calls: List[str] = []
    int_seeds = ["0", "-1", "1", "0x7fffffff", "0x10000", "-123456"]
    buf_seeds = ["0", "1", "4", "256", "4096"]  # 异常小/异常大缓冲区

    def build(buf_size: str, int_val: str) -> str:
        args: List[str] = []
        for k in kinds:
            if k == "ptr":
                args.append(f"(char*)malloc({buf_size})")
            elif k == "int":
                args.append(int_val)
            else:
                args.append("0")
        return f"{func_name}({', '.join(args)});"

    # 种子 1：经典危险组合（小缓冲区 + 负长度）
    for b in buf_seeds:
        for iv in ("-1", "0", "0x7fffffff"):
            calls.append(build(b, iv))
    # 去重保序
    seen = set()
    uniq: List[str] = []
    for c in calls:
        if c not in seen:
            seen.add(c)
            uniq.append(c)
    return uniq[:MAX_ITERATIONS]


def _extract_function(code: str, func_name: str) -> Optional[str]:
    """从源码里粗提取被测函数文本（括号配平截取）。"""
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


def _harness(func_src: str, func_name: str, calls: List[str]) -> str:
    """把被测函数包进带 main 的可运行 C。"""
    call_body = "\n    ".join(calls)
    return (
        "#include <stdlib.h>\n"
        "#include <string.h>\n"
        "#include <stdio.h>\n"
        f"{func_src}\n"
        "int main(void) {\n"
        f"    {call_body}\n"
        "    return 0;\n"
        "}\n"
    )


def _skip(reason: str, finding_id: str = "", **extra: Any) -> Dict[str, Any]:
    """统一降级返回：uncertain + 0.0 置信度（绝不 reject）。"""
    ev: Dict[str, Any] = {"skipped": True, "reason": reason}
    ev.update(extra)
    return {
        "status": "uncertain",
        "verdict": "uncertain",
        "confidence": 0.0,
        "reason": f"动态验证跳过：{reason}",
        "evidence": ev,
        "tool_name": TOOL_NAME,
        "raw_output": {"finding_id": finding_id},
    }


# ---------------------------------------------------------------------------
# 对外入口
# ---------------------------------------------------------------------------
def dynamic_check(hypothesis: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
    """对一条 finding 做动态验证，返回与 verify_taint 同构的结果。

    :param hypothesis: ``{finding_id, title, cwe, location:{function}, ...}``
    :param context:    ``{file, line_range, code}``

    判出口径：

    * CWE 非内存类 → 跳过（uncertain）；
    * 无 gcc/clang → 跳过（uncertain）；
    * 跑崩（ASan/段错误/UBSan）→ **accept / 0.92**，附崩溃证据；
    * 编译失败 / 全部跑通未崩 → **uncertain / 0.0**（不判无罪）。
    """
    hypothesis = hypothesis or {}
    context = context or {}
    finding_id = str(hypothesis.get("finding_id") or "")

    if not ENABLED:
        return _skip("DYNCHECK_ENABLED=0", finding_id)
    if not _is_memory_cwe(hypothesis):
        return _skip(
            f"CWE {_norm_cwe(hypothesis.get('cwe')) or '?'} 非内存类，动态验证不适用",
            finding_id,
        )
    use_docker = _docker_available()
    compiler = None if use_docker else _toolchain()
    if not use_docker and not compiler:
        return _skip("未找到 gcc/clang/docker（预期在 Linux/Docker 运行时挂载）",
                     finding_id)

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

    m = _FUNC_RE.search(func_src)
    if not m:
        return _skip(f"未能解析 {func_name} 的签名", finding_id)
    calls = _gen_calls(func_name, _split_params(m.group("params")))
    if not calls:
        return _skip(f"{func_name} 参数形态无法生成种子", finding_id)

    workdir = tempfile.mkdtemp(prefix="dyncheck_")
    harness_path = os.path.join(workdir, "harness.c")
    bin_path = os.path.join(workdir, "harness.bin")
    try:
        with open(harness_path, "w", encoding="utf-8") as f:
            f.write(_harness(func_src, func_name, calls))

        def _compile() -> Tuple[int, str]:
            """编译 harness（docker 模式在容器内完成）。返回 (returncode, stderr)。"""
            if use_docker:
                mount = _win_mount(workdir)
                cmd = ["docker", "run", "--rm", "--network=none",
                       "-v", f"{mount}:/work", "-w", "/work",
                       DOCKER_IMAGE, "gcc", "-g", "-O1",
                       "-fsanitize=address,undefined", "harness.c", "-o", "harness.bin"]
            else:
                cmd = [compiler, "-g", "-O1",
                       "-fsanitize=address,undefined", harness_path, "-o", bin_path]
            cp = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            return cp.returncode, (cp.stderr or "")

        def _run() -> Tuple[int, str]:
            """跑一次 harness（main 内含全部变异种子）。返回 (returncode, blob)。"""
            if use_docker:
                mount = _win_mount(workdir)
                cmd = ["docker", "run", "--rm", "--network=none",
                       "--memory=512m", "--pids-limit=64",
                       "-v", f"{mount}:/work", "-w", "/work",
                       DOCKER_IMAGE, "./harness.bin"]
            else:
                cmd = [bin_path]
            rp = subprocess.run(cmd, capture_output=True, text=True,
                                timeout=RUN_TIMEOUT + 10)
            return rp.returncode, (rp.stderr or "") + (rp.stdout or "")

        rc, stderr = _compile()
        if rc != 0:
            log_event("dynamic_check.compile_failed", finding_id=finding_id)
            return _skip("harness 编译失败（被测函数可能依赖外部符号）",
                         finding_id, compile_stderr_tail=stderr[-600:])

        # 跑一次：任一变异种子崩溃即定案（崩溃日志定位出错参数）
        rc, blob = _run()
        if rc != 0 or any(mark in blob for mark in _CRASH_MARKS):
            mark = next((mk for mk in _CRASH_MARKS if mk in blob), "crash")
            return {
                "status": "verified",
                "verdict": "accept",
                "confidence": CONF_DYNAMIC_CRASH,
                "reason": (
                    f"动态执行复现运行时错误（{mark}），"
                    f"共喂入 {len(calls)} 个变异种子"
                ),
                "evidence": {
                    "crash": True,
                    "crash_type": mark,
                    "trigger_calls": calls,
                    "seed_count": len(calls),
                    "sanitizer_log_tail": blob[-800:],
                    "backend": f"docker:{DOCKER_IMAGE}" if use_docker else str(compiler),
                },
                "tool_name": TOOL_NAME,
                "raw_output": {"finding_id": finding_id, "exit_code": rc},
            }

        # 全部跑通：fuzz 未覆盖到 ≠ 无漏洞
        return _skip(
            f"{len(calls)} 个种子均未触发运行时错误（未覆盖 ≠ 安全）",
            finding_id,
            iterations=len(calls),
        )
    except subprocess.TimeoutExpired:
        return _skip("运行超时（单个进程超过安全上限）", finding_id)
    except Exception as exc:  # 动态工具绝不拖垮整图
        log_event("dynamic_check.error", finding_id=finding_id,
                  error=f"{type(exc).__name__}: {exc}")
        return _skip(f"内部异常 {type(exc).__name__}: {exc}", finding_id)


# ---------------------------------------------------------------------------
# LangChain 工具包装（与 verify_taint_tool 同款降级策略）
# ---------------------------------------------------------------------------
try:  # pragma: no cover
    from langchain_core.tools import tool as _lc_tool  # type: ignore

    @_lc_tool("dynamic_check")
    def dynamic_check_tool(hypothesis: dict, context: dict) -> dict:
        """对内存类 CWE finding 做沙箱动态执行验证（只输出有罪证据）。"""
        return dynamic_check(hypothesis, context)

except Exception:  # pragma: no cover
    dynamic_check_tool = None  # type: ignore
