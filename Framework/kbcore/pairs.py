"""数据集扫描：`patchdb_cvefixes_for_appatch_train/` → ``PairRecord``。

纯 IO + 正则，无 LLM、无外部依赖。对应设计文档
`change_process/design/知识库_双视图抽取与存储_代码方案_设计.md` §5.1。

实测口径（§1.1，306 对）：
* 每对目录同时含 ``*_vul.c`` 与 ``*_nonvul.c``；
* 只有 103 对额外带 ``.ast`` / ``.patterns`` / ``.diff`` 工件（仅作旁证）；
* 目录名形如 ``CWE-125_CVE-2018-16392_OpenSC_<sha>_decrypt_response``。
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable

# 数据集中实际出现的 CWE（§1.1）。出现新值说明换了数据源，必须显式放行。
KNOWN_CWES: frozenset[str] = frozenset(
    {"CWE-125", "CWE-190", "CWE-401", "CWE-457", "CWE-476", "CWE-787"}
)

_CWE_RE = re.compile(r"CWE-\d+")
_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}")
_HEX_RE = re.compile(r"[0-9a-f]{7,40}")

# 单对片段的体量上限：超过说明混进了整文件（§1.2 实测最大 355 行）
MAX_SNIPPET_CHARS = 200_000

_VUL_SUFFIX = "_vul.c"
_NONVUL_SUFFIX = "_nonvul.c"


@dataclass(frozen=True)
class PairRecord:
    """一个历史 vul / nonvul 对。"""

    pair_id: str
    cwe: str
    cve: str
    repo: str
    func: str
    vul_path: Path
    non_path: Path
    vul_src: str
    non_src: str
    commit: str = ""  # PatchDB 来源的部分样本没有 CVE，用 commit hash 记账
    artifacts: Dict[str, Path] = field(default_factory=dict)

    @property
    def has_ast_artifacts(self) -> bool:
        """该对是否带 Joern 风格的 AST / 模式对齐工件（103 对为 True）。"""
        return "diff" in self.artifacts

    @property
    def vul_lines(self) -> list[str]:
        return self.vul_src.splitlines()

    @property
    def non_lines(self) -> list[str]:
        return self.non_src.splitlines()


def parse_pair_id(dirname: str) -> dict:
    """从目录名解析 ``cwe`` / ``cve`` / ``commit`` / ``repo`` / ``func``。

    ``cwe`` 必须存在（CWE 硬过滤与统计的键，不能猜）。
    ``cve`` 允许为空：PatchDB 来源的部分样本只有 commit hash
    （如 ``CWE-125_PatchDB_31d4f3a2…_ext4_valid_extent``），此时用 ``commit`` 记账，
    泄漏检查以 ``cve`` 为主、``commit`` 兜底。
    """
    name = dirname.strip()
    if not name:
        raise ValueError("空目录名")

    cwe_m = _CWE_RE.search(name)
    if not cwe_m:
        raise ValueError(f"目录名缺少 CWE 编号：{dirname!r}")
    cwe = cwe_m.group(0)

    cve_m = _CVE_RE.search(name)
    cve = cve_m.group(0) if cve_m else ""

    parts = name.split("_")
    func = parts[-1] if parts else ""

    # repo / func：CVE 段（无 CVE 时从 CWE 段）之后的部分里，commit hash 段是纯十六进制。
    # 例：`linux_4ab2…214_kye_report_fixup` → repo=linux, commit=4ab2…, func=kye_report_fixup；
    #     `PatchDB_31d4f3a2…_ext4_valid_extent` → repo=PatchDB, func=ext4_valid_extent。
    tail_from = cve_m.end() if cve_m else cwe_m.end()
    tail = name[tail_from:].lstrip("_")
    tail_parts = [p for p in tail.split("_") if p]

    commit = ""
    hash_idx = None
    for i, part in enumerate(tail_parts):
        if _HEX_RE.fullmatch(part):
            hash_idx = i
            commit = part
    if hash_idx is not None:
        repo = "_".join(tail_parts[:hash_idx])
        func = "_".join(tail_parts[hash_idx + 1 :]) or func
    else:
        repo = "_".join(tail_parts[:-1]) if len(tail_parts) > 1 else name[: cwe_m.start()].rstrip("_")

    if not (cve or commit):
        raise ValueError(f"目录名既无 CVE 也无 commit hash，无法唯一标识：{dirname!r}")

    return {"cwe": cwe, "cve": cve, "commit": commit, "repo": repo, "func": func}


def _read(path: Path) -> str:
    return path.read_bytes().decode("utf-8", "replace")


def _pick(directory: Path, suffix: str) -> Path:
    """取唯一匹配 ``suffix`` 的 ``.c``（``_vul.c`` 不能匹配到 ``_nonvul.c``）。"""
    hits = [
        p
        for p in sorted(directory.glob("*.c"))
        if p.name.endswith(suffix) and not (suffix == _VUL_SUFFIX and p.name.endswith(_NONVUL_SUFFIX))
    ]
    if not hits:
        raise ValueError(f"{directory.name} 缺少 {suffix} 文件")
    return hits[0]


def _artifacts(directory: Path) -> Dict[str, Path]:
    found: Dict[str, Path] = {}
    for key, pattern in (
        ("vul_ast", "*_vul.c.ast"),
        ("non_ast", "*_nonvul.c.ast"),
        ("patterns", "*.patterns"),
        ("diff", "*.diff"),
    ):
        hits = sorted(directory.glob(pattern))
        if hits:
            found[key] = hits[0]
    return found


def load_pairs(
    root: Path,
    *,
    allow_unknown_cwe: bool = False,
    limit: int | None = None,
    cwes: Iterable[str] | None = None,
) -> list[PairRecord]:
    """扫描数据集根目录，返回按 ``pair_id`` 排序的 ``PairRecord`` 列表。

    :param allow_unknown_cwe: 换数据源（如 PRIMEVUL）时放开 CWE 白名单。
    :param limit: 只取前 N 对（K2 试跑与单测用）。
    :param cwes: 只保留这些 CWE（None = 全部）。
    """
    root = Path(root)
    if not root.is_dir():
        raise NotADirectoryError(f"数据集根目录不存在：{root}")

    keep = {c.strip().upper() for c in cwes} if cwes else None
    records: list[PairRecord] = []
    for entry in sorted(p for p in root.iterdir() if p.is_dir()):
        meta = parse_pair_id(entry.name)
        if not allow_unknown_cwe and meta["cwe"] not in KNOWN_CWES:
            raise ValueError(f"未登记的 CWE {meta['cwe']}（{entry.name}）；换数据源请显式放行")
        if keep is not None and meta["cwe"] not in keep:
            continue

        vul_path = _pick(entry, _VUL_SUFFIX)
        non_path = _pick(entry, _NONVUL_SUFFIX)
        vul_src, non_src = _read(vul_path), _read(non_path)

        for label, src in (("vul", vul_src), ("nonvul", non_src)):
            if not src.strip():
                raise ValueError(f"{entry.name} 的 {label} 文件为空")
            if len(src) > MAX_SNIPPET_CHARS:
                raise ValueError(
                    f"{entry.name} 的 {label} 片段过大（{len(src)} 字符），疑似整文件混入"
                )

        records.append(
            PairRecord(
                pair_id=entry.name,
                cwe=meta["cwe"],
                cve=meta["cve"],
                repo=meta["repo"],
                func=meta["func"],
                commit=meta.get("commit", ""),
                vul_path=vul_path,
                non_path=non_path,
                vul_src=vul_src,
                non_src=non_src,
                artifacts=_artifacts(entry),
            )
        )
        if limit is not None and len(records) >= limit:
            break

    return records


def cwe_histogram(pairs: Iterable[PairRecord]) -> Dict[str, int]:
    """CWE 计数（用于和 §1.1 的实测值对账）。"""
    hist: Dict[str, int] = {}
    for p in pairs:
        hist[p.cwe] = hist.get(p.cwe, 0) + 1
    return dict(sorted(hist.items()))


def select_spread(pairs: Iterable[PairRecord], per_cwe: int) -> list[PairRecord]:
    """每个 CWE 取前 ``per_cwe`` 对（按 pair_id 顺序）——小样本跨 CWE 试跑用。

    只按 ``limit`` 截断会全落在 CWE-125 上（目录名排序所致），看不见其它 CWE 的
    门禁/抽取行为，所以试跑应走这个选择器。
    """
    out: list[PairRecord] = []
    counts: Dict[str, int] = {}
    for pair in pairs:
        if counts.get(pair.cwe, 0) >= per_cwe:
            continue
        counts[pair.cwe] = counts.get(pair.cwe, 0) + 1
        out.append(pair)
    return out


__all__ = [
    "KNOWN_CWES",
    "MAX_SNIPPET_CHARS",
    "PairRecord",
    "parse_pair_id",
    "load_pairs",
    "cwe_histogram",
]
