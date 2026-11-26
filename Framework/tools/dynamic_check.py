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
import random
import re
import shutil
import subprocess
import tempfile
import time
from typing import Any, Callable, Dict, List, Optional, Tuple

from observability import log_event

TOOL_NAME = "dynamic_check"

# ---------------------------------------------------------------------------
# 结果分级（对照 AutoSafeCoder FResult；判定口径不变：仅 crash 提权 accept）
# ---------------------------------------------------------------------------
#: 跑出运行时错误（ASan / 段错误 / UBSan）→ 有罪证据，accept 0.92
OUTCOME_CRASH = "crash"
#: 种子跑完未崩（fuzz 未覆盖到 ≠ 无漏洞）
OUTCOME_SAFE = "safe"
#: harness 编译失败（依赖外部符号 / 类型缺失等）
OUTCOME_COMPILE_FAILED = "compile_failed"
#: 存在种子执行超时（超时不计崩溃，单独记档）
OUTCOME_TIMEOUT = "timeout"
#: 参数形态无法生成有效种子（兜底 0 / NULL）
OUTCOME_WEAK_INPUT = "weak_input"
#: 本机 / 容器缺少编译运行工具链
OUTCOME_TOOLCHAIN_MISSING = "toolchain_missing"
#: 动态验证被开关关闭
OUTCOME_DISABLED = "disabled"
#: 非内存类 CWE，动态验证不适用
OUTCOME_NOT_APPLICABLE = "not_applicable"

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
#: 单条 finding 全部种子的运行总预算秒数（逐进程跑，防止极端情况超时堆积）
TOTAL_TIMEOUT = float(os.environ.get("DYNCHECK_TOTAL_TIMEOUT", "60"))
#: 覆盖率反馈开关：开启时编译带 --coverage，按覆盖增量排序并生成邻域变异第二轮；
#: 默认关闭，避免影响现有 ASan 路径。反馈闭环需在有工具链的环境调通。
COVERAGE_ENABLED = os.environ.get("DYNCHECK_COVERAGE", "0") not in ("0", "false", "False")
#: 变异输入轮数上限（AutoSafeCoder 跑 150 轮；单 finding 静态先行，这里取小值控成本）
MAX_ITERATIONS = int(os.environ.get("DYNCHECK_MAX_ITER", "24"))
#: 全局开关：显式关闭时直接跳过（默认开启，由工具链存在性自动兜底）
ENABLED = os.environ.get("DYNCHECK_ENABLED", "1") not in ("0", "false", "False")
#: 变异随机种子；固定默认值保证离线可复现，设为任意值可换一批变异样本
_SEED_RAW = os.environ.get("DYNCHECK_SEED", "0")
try:
    _SEED: int = int(_SEED_RAW)
except ValueError:
    _SEED = abs(hash(_SEED_RAW))
_RNG = random.Random(_SEED)
#: 第二轮覆盖引导：对排序靠前的前 K 个种子做邻域变异生成候选
NEIGHBOR_TOP_K = int(os.environ.get("DYNCHECK_NEIGHBOR_TOP_K", "2"))

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
    "Segmentation fault",  # Linux SIGSEGV shell 文案
    "segmentation violation",
    "access violation",  # Windows 访问违例
)


def _is_crash(rc: int, blob: str, sanitizer_on: bool) -> bool:
    """判定一次运行是否构成有罪崩溃证据。

    * blob 命中 sanitizer / 内存错误标记 → 崩；
    * sanitizer 在位（ASan/UBSan，或 Docker 镜像内齐全工具链）→ 非零退出码亦可采信；
    * 退化普通编译（本地工具链缺 sanitizer 运行库）→ 仅凭退出码不足为据，
      必须有明确崩溃标记，避免把普通异常退出误报为内存漏洞。
    """
    if any(mk in blob for mk in _CRASH_MARKS):
        return True
    return sanitizer_on and rc != 0


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
    """探测可用 C 工具链；返回编译器路径，都没有则 None。

    优先级：``DYNCHECK_CC`` 显式路径 → PATH 中的 clang → gcc。
    clang 优先：MinGW 版 gcc 通常不带 sanitizer 运行库，clang/LLVM-MinGW 才
    能链接 ASan/UBSan。
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
    """本地子进程环境：PATH 前置编译器 bin 目录，确保 ASan/UBSan 动态运行库可加载。"""
    env = dict(os.environ)
    if compiler:
        bin_dir = os.path.dirname(compiler)
        if bin_dir:
            env["PATH"] = bin_dir + os.pathsep + env.get("PATH", "")
    return env


#: sanitizer 标准编译 flags（ASan + UBSan）
_SANITIZER_FLAGS = ["-fsanitize=address,undefined"]
#: 编译器路径 -> 是否可链接 sanitizer 运行库（探针结果缓存，避免重复编译）
_SANITIZER_CACHE: Dict[str, bool] = {}


def _sanitizer_flags(compiler: Optional[str], use_docker: bool) -> List[str]:
    """返回本轮编译使用的 sanitizer flags。

    * Docker 模式默认带 ASan/UBSan（容器内工具链通常齐全）；
    * 本地模式先用最小探针试链 ``-fsanitize=address,undefined``：链接成功
      才带 sanitizer；部分 MinGW 构建未带 sanitizer 运行库（``-lasan`` 找不到），
      此时退化为普通编译，仅靠退出码 / SEGV 判定崩溃，不阻塞 harness 编译。

    探测结果按编译器路径缓存；探针编译失败按"不可用"处理。
    """
    if use_docker:
        return list(_SANITIZER_FLAGS)
    if not compiler:
        return []
    cached = _SANITIZER_CACHE.get(compiler)
    if cached is not None:
        return list(_SANITIZER_FLAGS) if cached else []
    probe_dir = tempfile.mkdtemp(prefix="dynprobe_")
    try:
        probe_c = os.path.join(probe_dir, "probe.c")
        probe_bin = os.path.join(probe_dir, "probe.bin")
        with open(probe_c, "w", encoding="utf-8") as fh:
            fh.write("int main(void){return 0;}\n")
        cp = subprocess.run(
            [compiler, "-g", "-O1", *_SANITIZER_FLAGS, probe_c, "-o", probe_bin],
            capture_output=True, text=True, timeout=30,
        )
        ok = cp.returncode == 0
        _SANITIZER_CACHE[compiler] = ok
        return list(_SANITIZER_FLAGS) if ok else []
    except Exception:
        _SANITIZER_CACHE[compiler] = False
        return []
    finally:
        shutil.rmtree(probe_dir, ignore_errors=True)


def _split_params(params: str) -> List[str]:
    return [p.strip() for p in params.split(",") if p.strip()]


#: 缓冲区 / 字符串类参数名关键词（用于把指针参数识别为可传串的 buffer）
_BUF_NAME_RE = re.compile(
    r"buf|buffer|str|string|name|msg|data|dst|src|dest|path|cmd|sql|payload|ptr",
    re.IGNORECASE,
)
#: 长度 / 尺寸类参数名关键词（与缓冲区配对做越界联动）
_LEN_NAME_RE = re.compile(r"(?:^|_)(?:len|length|size|count|num|cnt|n)$", re.IGNORECASE)
_IDENT_RE = re.compile(r"[A-Za-z_]\w*")

#: 字符串危险种子：空串 / 单字符 / 超长重复串 / 格式串 / 特殊转义串
_STR_SEEDS = [
    '""',
    '"A"',
    '"' + "A" * 64 + '"',
    '"%n%n%s"',
    '"\\n\\t\\"\\\\ "',
]
#: malloc 异常尺寸（异常小 / 异常大缓冲区）
_MALLOC_SIZES = ["0", "1", "4", "256", "4096"]
#: 长度 / 整数种子（含正负边界与极值）
_INT_SEEDS = ["-1", "0", "1", "-2147483648", "4096", "0x7fffffff"]


def _random_str_seed() -> str:
    """由可复现 RNG 生成一条随机字母数字串字面量（C 字符串安全字符集）。"""
    n = _RNG.randint(1, 32)
    return '"' + "".join(_RNG.choice(
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
        for _ in range(n)) + '"'


def _param_name(p: str) -> str:
    """从参数声明里取参数名（最后一个标识符，去掉 const / 指针符号）。"""
    toks = _IDENT_RE.findall(p.replace("const", " "))
    return toks[-1] if toks else ""


def _param_role(p: str) -> str:
    """参数角色：buffer / ptr / length / int / other。

    * ``buffer`` —— 指针且名字像缓冲区/串，可传串字面量或 malloc 缓冲；
    * ``ptr``    —— 其他指针，只给 malloc 缓冲；
    * ``length`` —— 整数且名字像长度/尺寸，与缓冲区做越界联动；
    * ``int``    —— 其他整数；
    * ``other``  —— 结构体 / 枚举等，给 0/NULL。
    """
    pn = p.replace("const", "").strip()
    name = _param_name(p)
    if "*" in pn:
        return "buffer" if _BUF_NAME_RE.search(name) else "ptr"
    if re.search(r"\b(int|long|short|size_t|unsigned|uint|intptr_t|ssize_t)\b", pn):
        return "length" if _LEN_NAME_RE.search(name) else "int"
    return "other"


def _gen_calls(func_name: str, params: List[str]) -> List[str]:
    """为被测函数生成类型感知变异的调用语句列表。

    种子策略（按风险优先级排序，超出 ``MAX_ITERATIONS`` 截断）：

    1. **越界联动**：buffer + length 同时存在时，小缓冲配大长度 / 负长度；
    2. **malloc 缓冲**：异常尺寸缓冲区配长度 / 整数种子；
    3. **串字面量**：空串 / 单字符 / 超长串 / 格式串直传 buffer；
    4. **兜底**：无指针参数时只喂整数 / 0。
    """
    roles = [_param_role(p) for p in params]
    has_buffer = any(r == "buffer" for r in roles)
    has_length = any(r == "length" for r in roles)
    calls: List[str] = []

    def args_for(malloc_size: str, str_literal: Optional[str], int_val: str) -> List[str]:
        args: List[str] = []
        for r in roles:
            if r == "buffer":
                args.append(str_literal if str_literal is not None
                            else f"(char*)malloc({malloc_size})")
            elif r == "ptr":
                args.append(f"(char*)malloc({malloc_size})")
            elif r in ("length", "int"):
                args.append(int_val)
            else:
                args.append("0")
        return args

    def build(malloc_size: str, str_literal: Optional[str], int_val: str) -> str:
        return f"{func_name}({', '.join(args_for(malloc_size, str_literal, int_val))});"

    # 1) 越界联动：小缓冲 + 大长度 / 负长度（最高风险，优先入列）
    if has_buffer and has_length:
        for size in ("1", "4"):
            for iv in ("4096", "0x7fffffff", "-1"):
                calls.append(build(size, None, iv))

    # 2) 串字面量直传 buffer（排在 malloc 矩阵前，避免被上限截断挤出）
    if has_buffer:
        str_seeds = list(_STR_SEEDS) + [_random_str_seed()]
        for seed in str_seeds:
            calls.append(build("0", seed, "0"))

    # 3) malloc 异常尺寸缓冲 + 长度 / 整数种子
    for size in _MALLOC_SIZES:
        for iv in _INT_SEEDS:
            calls.append(build(size, None, iv))

    # 4) 无指针参数：纯整数 / 0 兜底
    if not any(r in ("buffer", "ptr") for r in roles):
        for iv in _INT_SEEDS:
            calls.append(build("0", None, iv))

    # 去重保序，按上限截断控成本
    seen = set()
    uniq: List[str] = []
    for c in calls:
        if c not in seen:
            seen.add(c)
            uniq.append(c)
    return uniq[:MAX_ITERATIONS]


# ---------------------------------------------------------------------------
# LLM 种子提供方（C 档骨架）：有可用 LLM 时由模型定向生成调用种子；
# 无 Key / 导入失败 / 调用异常 / 返回不可解析时一律回退启发式种子，不阻塞主流程。
# ---------------------------------------------------------------------------
_LLM_SEED_PROMPT = """你是 C 语言模糊测试种子生成器。下面是一个待验证的 C 函数（CWE {cwe}）。
请给出最多 {n} 条调用该函数的 C 语句，优先构造可能触发缓冲区越界、空指针、
释放后使用或长度不一致的参数组合。只输出调用语句，每行一条；不要解释、
不要代码块围栏，指针参数用 (char*)malloc 或字符串字面量。

函数名：{func}
参数：{params}
源码：
{src}
"""


def _parse_llm_seeds(text: str, func_name: str) -> List[str]:
    """解析 LLM 输出为合法调用语句；注释 / 围栏 / 非本函数调用行丢弃。"""
    out: List[str] = []
    seen: set = set()
    prefix = f"{func_name}("
    for raw in text.splitlines():
        line = raw.strip().strip("`").strip()
        if not line or line.startswith("//") or line.startswith("#"):
            continue
        if line.startswith("```"):
            continue
        line = line.rstrip(";").strip()
        if line.endswith(")"):
            stmt = line + ";"
        else:
            stmt = line + ");"
        if not stmt.startswith(prefix) or stmt in seen:
            continue
        seen.add(stmt)
        out.append(stmt)
    return out


def _llm_seeds(
    llm: Any,
    func_name: str,
    params: List[str],
    func_src: str,
    cwe: str,
) -> List[str]:
    """调用 LLM 生成定向种子；任何失败 / 空结果返回空列表，交启发式兜底。"""
    if llm is None:
        return []
    try:
        prompt = _LLM_SEED_PROMPT.format(
            cwe=cwe or "?", func=func_name,
            params=", ".join(params) or "(无)", src=func_src,
            n=MAX_ITERATIONS,
        )
        resp = llm.invoke(prompt)
        content = getattr(resp, "content", None)
        if content is None:
            content = str(resp)
        return _parse_llm_seeds(str(content), func_name)
    except Exception as exc:
        log_event("dynamic_check.llm_seed_failed", level="warn",
                  function=func_name, error=f"{type(exc).__name__}: {exc}")
        return []


def _merge_seeds(*groups: List[str], cap: int = MAX_ITERATIONS) -> List[str]:
    """合并多组种子，去重保序，按上限截断控成本。"""
    seen: set = set()
    out: List[str] = []
    for group in groups:
        for c in group:
            if c and c not in seen:
                seen.add(c)
                out.append(c)
    return out[:cap]


def _default_llm() -> Optional[Any]:
    """懒加载框架 LLM 客户端；无 Key / 导入失败 / 构造失败返回 None。"""
    try:
        from agents.llm_client import get_llm
        return get_llm()
    except Exception:
        return None


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


def _all_functions(code: str) -> Dict[str, str]:
    """正则提取全文所有顶层函数定义：``{函数名: 完整源码}``。"""
    result: Dict[str, str] = {}
    for m in _FUNC_RE.finditer(code):
        name = m.group("name")
        brace_start = code.find("{", m.end() - 1)
        if brace_start < 0:
            continue
        depth = 0
        end: Optional[int] = None
        for i in range(brace_start, len(code)):
            if code[i] == "{":
                depth += 1
            elif code[i] == "}":
                depth -= 1
                if depth == 0:
                    end = i + 1
                    break
        if end is not None:
            result[name] = code[m.start():end]
    return result


#: struct / enum 定义块（括号配平截取，吞掉块尾可选分号）
_TYPE_BLOCK_RE = re.compile(r"\b(?:struct|enum)\b[^{;]*\{", re.S)
#: 单行 typedef 声明
_TYPEDEF_RE = re.compile(r"typedef\s+[^;{}]+;", re.S)


def _extract_type_definitions(code: str) -> List[str]:
    """提取源码中的 struct / enum / typedef 定义，供 harness 编译通过。"""
    defs: List[str] = []
    for m in _TYPE_BLOCK_RE.finditer(code):
        brace = code.find("{", m.start())
        if brace < 0:
            continue
        depth = 0
        end: Optional[int] = None
        for i in range(brace, len(code)):
            if code[i] == "{":
                depth += 1
            elif code[i] == "}":
                depth -= 1
                if depth == 0:
                    end = i + 1
                    break
        if end is None:
            continue
        if end < len(code) and code[end] == ";":
            end += 1
        defs.append(code[m.start():end].strip())
    for m in _TYPEDEF_RE.finditer(code):
        defs.append(m.group(0).strip())
    # 去重保序
    seen = set()
    uniq: List[str] = []
    for d in defs:
        if d not in seen:
            seen.add(d)
            uniq.append(d)
    return uniq


def _collect_dep_sources(
    code: str, func_name: str, func_src: str
) -> Tuple[List[str], List[str], str]:
    """收集被测函数闭包依赖的同文件函数。

    :return: ``(依赖函数名列表, 依赖函数源码列表, 解析数据源)``；
        数据源为 ``tree-sitter``（CallContext 沿 callees BFS）或 ``regex``（回退）。

    说明：只纳入**同文件**定义的函数；外部库 / 跨文件符号不在 harness 内
    补桩，编译失败仍按现有口径降级 uncertain（自动 stub 可能掩盖真问题）。
    """
    all_funcs = _all_functions(code)
    dep_names: List[str] = []
    source = "regex"

    # 优先走 tree-sitter 调用图；原生模块缺失 / 解析失败时落到正则回退。
    try:
        from tools.call_context import build_context

        ctx = build_context(code)
        if ctx.functions:
            source = "tree-sitter"
            seen = {func_name}
            queue = [func_name]
            while queue:
                cur = queue.pop(0)
                for c in ctx.callees(cur).get("callees", []):
                    callee = c.get("callee", "")
                    if c.get("defined_in_file") and callee and callee not in seen:
                        seen.add(callee)
                        dep_names.append(callee)
                        queue.append(callee)
    except Exception:
        source = "regex"
        dep_names = []

    if not dep_names:
        # 正则回退：被测函数体内出现的调用标识符，命中同文件函数表即纳入。
        for ident in _IDENT_RE.findall(func_src):
            if ident in all_funcs and ident != func_name and ident not in dep_names:
                dep_names.append(ident)

    dep_srcs = [all_funcs[n] for n in dep_names if n in all_funcs]
    return dep_names, dep_srcs, source


# ---------------------------------------------------------------------------
# 覆盖率反馈（框架；真实闭环需在有工具链的环境调通）
# ---------------------------------------------------------------------------
def _coverage_flags() -> List[str]:
    """覆盖率编译/链接选项；开关关闭时返回空列表。"""
    return ["--coverage"] if COVERAGE_ENABLED else []


#: gcov 文本行：``  计数: 行号: 源码``；计数为正整数=已覆盖，``-``=不可执行，
#: ``#####``=未覆盖。行级增量需工具链环境生成 .gcov 文本后才填得上。
_GCOV_LINE_RE = re.compile(r"^\s*(?P<count>\d+|-|#+\s*):\s*(?P<line>\d+):")


def _parse_gcov_lines(text: str) -> frozenset:
    """解析 gcov/llvm-cov 文本输出，返回**已覆盖行号集合**；无可执行行返回空集。"""
    covered: set = set()
    for line in text.splitlines():
        m = _GCOV_LINE_RE.match(line)
        if not m:
            continue
        cnt = m.group("count")
        if cnt.isdigit() and int(cnt) > 0:
            covered.add(int(m.group("line")))
    return frozenset(covered)


def _read_line_coverage(workdir: str) -> Optional[frozenset]:
    """读取 workdir 下 ``.gcov`` 文本产物汇总行级覆盖；无文本产物返回 None。

    说明：gcc 带 ``--coverage`` 运行后先产出 ``.gcda``，需再跑一次 ``gcov`` /
    ``llvm-cov`` 导出 ``.gcov`` 文本；该触发步骤依赖工具链，当前环境未验证，
    此处只负责读已有文本。
    """
    covered: set = set()
    found = False
    try:
        names = os.listdir(workdir)
    except OSError:
        return None
    for name in names:
        if not name.endswith(".gcov"):
            continue
        found = True
        try:
            with open(os.path.join(workdir, name), encoding="utf-8",
                      errors="replace") as fh:
                covered |= set(_parse_gcov_lines(fh.read()))
        except OSError:
            continue
    return frozenset(covered) if found else None


def _find_gcov_tool(compiler: Optional[str]) -> Tuple[Optional[str], Optional[str]]:
    """定位 gcov 兼容覆盖导出工具。

    :return: ``(工具路径, 调用形态)``；形态为 ``"llvm-cov"``（需 ``gcov`` 子命令）
        或 ``"gcov"``（裸命令）；都找不到返回 ``(None, None)``。
    """
    candidates = []
    if compiler:
        bdir = os.path.dirname(compiler)
        candidates += [
            (os.path.join(bdir, "llvm-cov.exe"), "llvm-cov"),
            (os.path.join(bdir, "llvm-cov"), "llvm-cov"),
            (os.path.join(bdir, "gcov.exe"), "gcov"),
            (os.path.join(bdir, "gcov"), "gcov"),
        ]
    for exe, runner in (("llvm-cov.exe", "llvm-cov"), ("llvm-cov", "llvm-cov"),
                        ("gcov.exe", "gcov"), ("gcov", "gcov")):
        candidates.append((shutil.which(exe) or "", runner))
    for cand, runner in candidates:
        if cand and os.path.exists(cand):
            return cand, runner
    return None, None


def _export_gcov(workdir: str, compiler: Optional[str], use_docker: bool) -> None:
    """本地模式用 gcov / llvm-cov 把 ``.gcda`` 导出为 ``.gcov`` 文本，供行级覆盖解析读取。

    失败静默：覆盖签名回退 ``.gcda`` 粗签名或 None，不阻塞主流程。
    docker 模式暂不在此导出（容器内由镜像侧处理）。
    """
    if use_docker:
        return
    tool, runner = _find_gcov_tool(compiler)
    if not tool:
        return
    # GCOV 产物名可能带可执行前缀（``<bin>-<src>.gcno/.gcda``），而 gcov 工具
    # 默认按 ``<src>.gcno/.gcda`` 查找；复制为标准名兜底。
    std_names = {".gcno": "harness.gcno", ".gcda": "harness.gcda"}
    try:
        names = os.listdir(workdir)
    except OSError:
        return
    for ext, std in std_names.items():
        if std in names:
            continue
        pre = next((n for n in names if n.endswith(ext)), None)
        if pre:
            try:
                shutil.copyfile(os.path.join(workdir, pre),
                                os.path.join(workdir, std))
            except OSError:
                pass
    try:
        cmd = [tool, "gcov", "harness.c"] if runner == "llvm-cov" else [tool, "harness.c"]
        subprocess.run(cmd, cwd=workdir,
                       capture_output=True, text=True, timeout=30)
    except Exception:
        return


def _coverage_signature(workdir: str) -> Optional[frozenset]:
    """汇总覆盖签名：优先行级覆盖行号集合；无 .gcov 文本时回退 .gcda 粗签名。

    无任何覆盖产物返回 None，种子排序退回原序。行级解析逻辑可离线用样例
    gcov 文本验证；真实 .gcov 产物的生成与增量排序需在有工具链的环境调通。
    """
    line_cov = _read_line_coverage(workdir)
    if line_cov is not None:
        return line_cov
    sig: set = set()
    try:
        names = os.listdir(workdir)
    except OSError:
        return None
    for name in names:
        if name.endswith(".gcda"):
            try:
                sig.add((name, os.path.getsize(os.path.join(workdir, name))))
            except OSError:
                sig.add((name, 0))
    return frozenset(sig) if sig else None


def _rank_by_coverage(
    calls: List[str], signatures: Dict[int, Optional[frozenset]]
) -> Tuple[List[str], List[Tuple[int, int]]]:
    """按覆盖增量给种子排序（新增覆盖多的排前）。

    :return: ``(排序后的 calls, [(新增覆盖量, 原索引), ...])``；
        无覆盖数据时原样返回，增益全记 0。
    """
    if not COVERAGE_ENABLED or not signatures:
        return list(calls), [(0, i) for i in range(len(calls))]
    covered: set = set()
    gains: List[Tuple[int, int]] = []
    for i, _ in enumerate(calls):
        sig = signatures.get(i)
        gain = len(sig - covered) if sig is not None else 0
        if sig is not None:
            covered |= sig
        gains.append((gain, i))
    order = [calls[i] for _, i in sorted(gains, key=lambda x: -x[0])]
    return order, gains


#: 邻域变异：串字面量截断正则
_STRING_LITERAL_RE = re.compile(r'"([^"]*)"')
_NUMERIC_RE = re.compile(r"0x[0-9a-fA-F]+|-?\d+")


def _neighbor_mutate(call: str) -> List[str]:
    """围绕一个种子做粗粒度邻域变异（文本级），返回 1~2 个新调用。

    说明：这是文本扰动，非结构化参数变异；作为覆盖率反馈第二轮的候选，
    真实方向应由覆盖引导。无工具链环境不会被执行。
    """
    variants: List[str] = []
    nums = _NUMERIC_RE.findall(call)
    if nums:
        target = nums[-1]
        for v in ("0", "2048"):
            variants.append(call.replace(target, v, 1))

    def _trim(m: re.Match) -> str:
        s = m.group(1)
        return '"' + s[: len(s) // 2] + '"' if len(s) > 8 else m.group(0)

    trimmed = _STRING_LITERAL_RE.sub(_trim, call)
    if trimmed != call:
        variants.append(trimmed)

    out: List[str] = []
    for v in variants:
        if v != call and v not in out:
            out.append(v)
    return out[:2]


def _minimize_call(
    call: str,
    replay: Optional[Callable[[str], bool]] = None,
) -> Tuple[str, Dict[str, Any]]:
    """崩溃输入参数级最小化。

    :param call: 触发崩溃的种子调用语句；
    :param replay: 重放回调，``replay(call) -> bool`` 表示缩减后仍复现崩溃；
        不可用（无工具链）时传 ``None``，原样返回不缩减。
    :return: ``(最小化后的 call, 缩减记录)``。

    缩减顺序：长度/整数向 0/1/-1/2 收缩 → malloc 尺寸收缩到 1 →
    串字面量二分截断到最短仍崩前缀。每一步只有 replay 仍返回 True 才保留；
    前缀不再复现崩溃即停止对该串继续二分（保守收缩，不破坏崩溃条件）。
    """
    record: Dict[str, Any] = {"minimized": False, "steps": []}
    if replay is None:
        return call, record

    current = call
    # 整数收缩候选（从大值向最简常用值依次尝试，保留首个仍崩的）
    num_candidates = ["0", "1", "-1", "2"]

    # 1) 数值参数：大值 → 0 / 1 / -1 / 2（逐个尝试，保留仍崩的最简值）
    for num in _NUMERIC_RE.findall(current):
        if num in num_candidates:
            continue
        for cand in num_candidates:
            trial = current.replace(num, cand, 1)
            if replay(trial):
                current = trial
                record["steps"].append(f"num {num}->{cand}")
                break

    # 2) malloc 尺寸收缩到 1
    def _malloc_shrink(m: re.Match) -> str:
        if m.group(1) in ("0", "1"):
            return m.group(0)
        trial = current.replace(m.group(0), "malloc(1)", 1)
        return "malloc(1)" if replay(trial) else m.group(0)

    current = re.sub(r"malloc\((\d+)\)", _malloc_shrink, current)

    # 3) 串字面量二分截断：逐串缩到最短仍复现崩溃的前缀
    def _str_bisect(m: re.Match) -> str:
        nonlocal current
        s = m.group(1)
        if len(s) <= 1:
            return m.group(0)
        cur = s
        while len(cur) > 1:
            half = cur[: len(cur) // 2]
            trial = current.replace(m.group(0), f'"{half}"', 1)
            if replay(trial):
                current = trial
                record["steps"].append(f"str {len(s)}->{len(half)}")
                cur = half
            else:
                # 前缀不再复现崩溃：保留当前 cur，停止该串二分
                break
        return f'"{cur}"'

    current = _STRING_LITERAL_RE.sub(_str_bisect, current)

    record["minimized"] = current != call
    return current, record


def _harness(
    type_defs: List[str],
    dep_srcs: List[str],
    func_src: str,
    calls: List[str],
) -> str:
    """把类型定义、依赖函数、被测函数包进可运行 C。

    每个变异种子包成独立的 ``seed_i`` 函数，``main`` 按 ``argv[1]`` 选择执行哪一个；
    编译只做一次，运行时逐种子起独立进程，崩溃即可定位到具体种子索引。
    """
    parts: List[str] = [
        "#include <stdlib.h>",
        "#include <string.h>",
        "#include <stdio.h>",
        "#ifdef __linux__",
        "#include <sys/resource.h>",
        "#include <signal.h>",
        "#endif",
        "",
        "static void _apply_limits(void) {",
        "#ifdef __linux__",
        "    struct rlimit rl;",
        "    rl.rlim_cur = rl.rlim_max = 512UL * 1024UL * 1024UL;  /* 地址空间 512MB */",
        "    setrlimit(RLIMIT_AS, &rl);",
        "    rl.rlim_cur = rl.rlim_max = 64UL * 1024UL * 1024UL;   /* 栈 64MB */",
        "    setrlimit(RLIMIT_STACK, &rl);",
        "    rl.rlim_cur = rl.rlim_max = 3UL;                       /* CPU 时间 3s */",
        "    setrlimit(RLIMIT_CPU, &rl);",
        "    rl.rlim_cur = rl.rlim_max = 1024UL * 1024UL;          /* 可写文件 1MB */",
        "    setrlimit(RLIMIT_FSIZE, &rl);",
        "    signal(SIGSEGV, SIG_DFL);",
        "    signal(SIGABRT, SIG_DFL);",
        "    signal(SIGBUS, SIG_DFL);",
        "#endif",
        "}",
        "",
    ]
    if type_defs:
        parts.extend(type_defs)
        parts.append("")
    if dep_srcs:
        parts.extend(dep_srcs)
        parts.append("")
    parts.append(func_src)
    parts.append("")
    for i, call in enumerate(calls):
        parts.append(f"static void seed_{i}(void) {{ {call} }}")
    parts.append("")
    parts.append("int main(int argc, char **argv) {")
    parts.append("    _apply_limits();")
    parts.append("    int idx = argc > 1 ? atoi(argv[1]) : 0;")
    parts.append("    switch (idx) {")
    for i in range(len(calls)):
        parts.append(f"        case {i}: seed_{i}(); break;")
    parts.append("        default: break;")
    parts.append("    }")
    parts.append("    return 0;")
    parts.append("}")
    return "\n".join(parts)


def _skip(reason: str, finding_id: str = "", *,
          outcome: str = OUTCOME_SAFE, **extra: Any) -> Dict[str, Any]:
    """统一降级返回：uncertain + 0.0 置信度（绝不 reject）。

    :param outcome: 结果分级（见 ``OUTCOME_*``），仅用于证据归档，不改变判定口径。
    """
    ev: Dict[str, Any] = {
        "skipped": True, "reason": reason, "outcome": outcome, "timeouts": 0,
    }
    ev.update(extra)
    return {
        "status": "uncertain",
        "verdict": "uncertain",
        "confidence": 0.0,
        "reason": f"动态验证跳过：{reason}",
        "evidence": ev,
        "outcome": outcome,
        "tool_name": TOOL_NAME,
        "raw_output": {"finding_id": finding_id},
    }


# ---------------------------------------------------------------------------
# 对外入口
# ---------------------------------------------------------------------------
def dynamic_check(
    hypothesis: Dict[str, Any],
    context: Dict[str, Any],
    enabled: Optional[bool] = None,
    llm: Optional[Any] = None,
) -> Dict[str, Any]:
    """对一条 finding 做动态验证，返回与 verify_taint 同构的结果。

    :param hypothesis: ``{finding_id, title, cwe, location:{function}, ...}``
    :param context:    ``{file, line_range, code}``
    :param enabled:    应用层开关；``None`` 时回退模块级 ``ENABLED``（环境变量
                       ``DYNCHECK_ENABLED``），显式 ``False`` 直接跳过，不触发编译/运行。
    :param llm:        可选 LLM 客户端；``None`` 时懒加载框架默认客户端，无可用
                       凭证则纯启发式种子。LLM 定向种子排在启发式之前，去重合并。

    判出口径：

    * CWE 非内存类 → 跳过（uncertain）；
    * 无 gcc/clang → 跳过（uncertain）；
    * 跑崩（ASan/段错误/UBSan）→ **accept / 0.92**，附崩溃证据；
    * 编译失败 / 全部跑通未崩 → **uncertain / 0.0**（不判无罪）。
    """
    hypothesis = hypothesis or {}
    context = context or {}
    finding_id = str(hypothesis.get("finding_id") or "")

    flag = ENABLED if enabled is None else bool(enabled)
    if not flag:
        return _skip("动态验证已关闭（verify.dynamic.enabled=false）", finding_id,
                     outcome=OUTCOME_DISABLED)
    if not _is_memory_cwe(hypothesis):
        return _skip(
            f"CWE {_norm_cwe(hypothesis.get('cwe')) or '?'} 非内存类，动态验证不适用",
            finding_id,
            outcome=OUTCOME_NOT_APPLICABLE,
        )
    use_docker = _docker_available()
    compiler = None if use_docker else _toolchain()
    if not use_docker and not compiler:
        return _skip("未找到 gcc/clang/docker（预期在 Linux/Docker 运行时挂载）",
                     finding_id, outcome=OUTCOME_TOOLCHAIN_MISSING)

    code = str(context.get("code") or "")
    if not code.strip():
        return _skip("context.code 为空", finding_id,
                     outcome=OUTCOME_WEAK_INPUT)

    func_name = str(
        (hypothesis.get("location") or {}).get("function")
        or hypothesis.get("function_name")
        or ""
    ).strip()
    if not func_name:
        return _skip("hypothesis 未提供被测函数名", finding_id,
                     outcome=OUTCOME_WEAK_INPUT)

    func_src = _extract_function(code, func_name)
    if not func_src:
        return _skip(f"未能从源码提取函数 {func_name}", finding_id,
                     outcome=OUTCOME_WEAK_INPUT)

    m = _FUNC_RE.search(func_src)
    if not m:
        return _skip(f"未能解析 {func_name} 的签名", finding_id,
                     outcome=OUTCOME_WEAK_INPUT)
    params = _split_params(m.group("params"))
    effective_llm = llm if llm is not None else _default_llm()
    llm_seeds = _llm_seeds(effective_llm, func_name, params, func_src,
                            _norm_cwe(hypothesis))
    heuristic = _gen_calls(func_name, params)
    calls = _merge_seeds(llm_seeds, heuristic)
    seed_source = "llm+heuristic" if llm_seeds else "heuristic"
    if not calls:
        return _skip(f"{func_name} 参数形态无法生成种子", finding_id,
                     outcome=OUTCOME_WEAK_INPUT)

    # harness 依赖补齐：同文件被调函数闭包 + 类型定义纳入编译单元；
    # 外部 / 跨文件符号不补桩，编译失败仍按 uncertain 降级。
    type_defs = _extract_type_definitions(code)
    dep_names, dep_srcs, dep_source = _collect_dep_sources(code, func_name, func_src)

    workdir = tempfile.mkdtemp(prefix="dyncheck_")
    harness_path = os.path.join(workdir, "harness.c")
    bin_path = os.path.join(workdir, "harness.bin")
    # 探测本地工具链是否带 sanitizer 运行库；缺失时退化普通编译（仅退出码/SEGV 判定）
    san_flags = _sanitizer_flags(compiler, use_docker)
    san_status = "address,undefined" if san_flags else "none:runtime missing"
    try:
        with open(harness_path, "w", encoding="utf-8") as f:
            f.write(_harness(type_defs, dep_srcs, func_src, calls))

        def _compile() -> Tuple[int, str]:
            """编译 harness（docker 模式在容器内完成）。返回 (returncode, stderr)。"""
            cov = _coverage_flags()
            if use_docker:
                mount = _win_mount(workdir)
                cmd = ["docker", "run", "--rm", "--network=none",
                       "-v", f"{mount}:/work", "-w", "/work",
                       DOCKER_IMAGE, "gcc", "-g", "-O1", *cov,
                       *san_flags, "harness.c", "-o", "harness.bin"]
            else:
                cmd = [compiler, "-g", "-O1", *cov,
                       *san_flags, harness_path, "-o", bin_path]
            cp = subprocess.run(cmd, capture_output=True, text=True, timeout=120,
                                env=None if use_docker else _local_env(compiler))
            return cp.returncode, (cp.stderr or "")

        def _run(idx: int) -> Tuple[int, str]:
            """跑指定索引的种子（独立进程）。返回 (returncode, blob)。"""
            seed_arg = str(idx)
            if use_docker:
                mount = _win_mount(workdir)
                cmd = ["docker", "run", "--rm", "--network=none",
                       "--memory=512m", "--pids-limit=64",
                       "-v", f"{mount}:/work", "-w", "/work",
                       DOCKER_IMAGE, "./harness.bin", seed_arg]
            else:
                cmd = [bin_path, seed_arg]
            rp = subprocess.run(cmd, capture_output=True, text=True,
                                timeout=RUN_TIMEOUT + 10,
                                env=None if use_docker else _local_env(compiler))
            return rp.returncode, (rp.stderr or "") + (rp.stdout or "")

        def _run_single_call(call: str) -> Tuple[bool, str]:
            """编译并运行单条调用；返回 ``(是否崩溃, 输出 blob)``。

            编译/运行异常一律按未崩溃处理（False, ""）。供崩溃最小化重放与
            覆盖率引导第二轮候选复用。
            """
            replay_dir = tempfile.mkdtemp(prefix="dynreplay_")
            try:
                rp = os.path.join(replay_dir, "r.c")
                rb = os.path.join(replay_dir, "r.bin")
                with open(rp, "w", encoding="utf-8") as f:
                    f.write(_harness([], dep_srcs, func_src, [call]))
                if use_docker:
                    mount = _win_mount(replay_dir)
                    c_compile = ["docker", "run", "--rm", "--network=none",
                                 "-v", f"{mount}:/work", "-w", "/work",
                                 DOCKER_IMAGE, "gcc", "-g", "-O1",
                                 *san_flags, "r.c", "-o", "r.bin"]
                    c_run = ["docker", "run", "--rm", "--network=none",
                             "--memory=256m", "--pids-limit=32",
                             "-v", f"{mount}:/work", "-w", "/work",
                             DOCKER_IMAGE, "./r.bin", "0"]
                else:
                    c_compile = [compiler, "-g", "-O1",
                                 *san_flags, rp, "-o", rb]
                    c_run = [rb, "0"]
                cp = subprocess.run(c_compile, capture_output=True, text=True, timeout=60,
                                    env=None if use_docker else _local_env(compiler))
                if cp.returncode != 0:
                    return False, ""
                rp_run = subprocess.run(c_run, capture_output=True, text=True,
                                        timeout=RUN_TIMEOUT + 10,
                                        env=None if use_docker else _local_env(compiler))
                blob = (rp_run.stderr or "") + (rp_run.stdout or "")
                return _is_crash(rp_run.returncode, blob, bool(san_flags)), blob
            except Exception:
                return False, ""
            finally:
                shutil.rmtree(replay_dir, ignore_errors=True)

        def _replay_single(call: str) -> bool:
            """重放单条调用是否仍崩溃；编译/运行失败一律按未复现处理（False）。"""
            return _run_single_call(call)[0]

        rc, stderr = _compile()
        if rc != 0:
            log_event("dynamic_check.compile_failed", finding_id=finding_id)
            return _skip("harness 编译失败（被测函数可能依赖外部符号）",
                         finding_id, outcome=OUTCOME_COMPILE_FAILED,
                         compile_stderr_tail=stderr[-600:],
                         dependency_functions=dep_names)

        # 逐种子起独立进程：任一崩溃即定案，并定位到具体种子索引；
        # 单种子超时不计崩溃，继续下一个；总预算耗尽则停止剩余种子。
        deadline = time.monotonic() + TOTAL_TIMEOUT
        crash_idx: Optional[int] = None
        crash_call = ""
        crash_mark = "crash"
        crash_blob = ""
        seeds_ran = 0
        timeouts = 0
        second_round: List[str] = []
        signatures: Dict[int, Optional[frozenset]] = {}
        for i, call in enumerate(calls):
            if time.monotonic() >= deadline:
                log_event("dynamic_check.budget_exhausted",
                          finding_id=finding_id, seeds_ran=seeds_ran,
                          seed_total=len(calls))
                break
            try:
                rc, blob = _run(i)
            except subprocess.TimeoutExpired:
                # 该种子超时：不作为崩溃证据，继续尝试后续种子
                timeouts += 1
                continue
            seeds_ran += 1
            signatures[i] = _coverage_signature(workdir)
            if _is_crash(rc, blob, bool(san_flags)):
                crash_mark = next((mk for mk in _CRASH_MARKS if mk in blob), "crash")
                crash_idx, crash_call, crash_blob = i, call, blob
                break

        # 第二轮：覆盖率引导邻域变异（仅开启覆盖反馈时；真实闭环待工具链环境验证）
        if crash_idx is None and COVERAGE_ENABLED:
            _export_gcov(workdir, compiler, use_docker)
            ordered, _gains = _rank_by_coverage(calls, signatures)
            seen2: set = set(calls)
            for seed in ordered[:NEIGHBOR_TOP_K]:
                for variant in _neighbor_mutate(seed):
                    if variant not in seen2:
                        seen2.add(variant)
                        second_round.append(variant)
            for j, s_call in enumerate(second_round):
                if time.monotonic() >= deadline:
                    break
                crashed, s_blob = _run_single_call(s_call)
                seeds_ran += 1
                if crashed:
                    crash_mark = next((mk for mk in _CRASH_MARKS if mk in s_blob),
                                      "crash")
                    crash_idx = len(calls) + j
                    crash_call, crash_blob = s_call, s_blob
                    break

        if crash_idx is not None:
            min_call, min_record = _minimize_call(crash_call, replay=_replay_single)
            return {
                "status": "verified",
                "verdict": "accept",
                "confidence": CONF_DYNAMIC_CRASH,
                "outcome": OUTCOME_CRASH,
                "reason": (
                    f"动态执行复现运行时错误（{crash_mark}，"
                    f"种子 #{crash_idx + 1}/{len(calls)}）"
                ),
                "evidence": {
                    "crash": True,
                    "outcome": OUTCOME_CRASH,
                    "crash_type": crash_mark,
                    "trigger_call": min_call,
                    "trigger_calls": [min_call],
                    "minimization": min_record,
                    "seed_index": crash_idx,
                    "seed_count": len(calls),
                    "second_round_seeds": len(second_round),
                    "seed_source": seed_source,
                    "seeds_ran": seeds_ran,
                    "timeouts": timeouts,
                    "coverage_enabled": COVERAGE_ENABLED,
                    "dependency_functions": dep_names,
                    "dependency_source": dep_source,
                    "type_definition_count": len(type_defs),
                    "sanitizer": san_status,
                    "sanitizer_log_tail": crash_blob[-800:],
                    "backend": f"docker:{DOCKER_IMAGE}" if use_docker else str(compiler),
                },
                "tool_name": TOOL_NAME,
                "raw_output": {"finding_id": finding_id, "exit_code": rc,
                               "seed_index": crash_idx},
            }

        # 全部跑通（或预算耗尽）：fuzz 未覆盖到 ≠ 无漏洞
        final_outcome = OUTCOME_TIMEOUT if timeouts > 0 else OUTCOME_SAFE
        extra = max(0, seeds_ran - len(calls))
        scope = (f"（首轮 {len(calls)} 种子 + {extra} 变异候选）"
                 if extra > 0 else f"/{len(calls)}")
        return _skip(
            f"{seeds_ran} 次运行{scope}未触发运行时错误（未覆盖 ≠ 安全）",
            finding_id,
            outcome=final_outcome,
            iterations=seeds_ran,
            seed_count=len(calls),
            second_round_seeds=len(second_round),
            seed_source=seed_source,
            seeds_ran=seeds_ran,
            timeouts=timeouts,
        )
    except subprocess.TimeoutExpired:
        # 单种子超时已在循环内消化；这里兜底编译阶段超时等未捕获的超时
        return _skip("编译或运行超时（超过安全上限）", finding_id,
                     outcome=OUTCOME_TIMEOUT)
    except Exception as exc:  # 动态工具绝不拖垮整图
        log_event("dynamic_check.error", finding_id=finding_id,
                  error=f"{type(exc).__name__}: {exc}")
        return _skip(f"内部异常 {type(exc).__name__}: {exc}", finding_id)
    finally:
        # 清理编译/运行临时目录（含 harness 源码、二进制、覆盖产物）
        shutil.rmtree(workdir, ignore_errors=True)


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
