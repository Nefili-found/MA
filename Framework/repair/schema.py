"""修复端全部数据契约的**单点定义**。

设计依据：``change_process/summery/修复端_结构重构_2026-10-24_设计.md`` §4。

约定
----
* 本模块是纯类型层：**零 IO、零网络、零 LLM**。其它模块只 import 这里，不各自定义
  字典形状——字段漂移要在这里报错，而不是在几百行外变成 ``KeyError``。
* 每个 dataclass 都有 ``to_dict()``，落盘用它的输出，所以"报告出来的字段"与
  "代码里用的字段"天然一致。
* 入口校验**复用检测端**：:meth:`RepairCase.validate` 直接调
  ``verify_agent.repair_projection.validate_repair_case``，不重写那六条规则。
  修复端只**额外**加 ``line_base`` 的判定（D5 / §9），因为那是修复端才有的概念。
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

# ---------------------------------------------------------------- 枚举（闭集）

#: 检测端给出的判定档位，与 ``verify_agent.repair_projection.REPAIR_VERDICTS`` 同源
VERDICTS = ("accept", "uncertain", "challenge", "reject")

#: 行号基准（D5）。``function`` 下 ``body_line_start`` 恒为 1，禁止进入 R3 路径
LINE_BASES = ("file", "function")

#: 入口判定档位
ENTRY_ACCEPTED = "accepted"
ENTRY_INVALID = "invalid_baseline"
ENTRY_SKIPPED = "entry_skipped"
ENTRY_KINDS = (ENTRY_ACCEPTED, ENTRY_INVALID, ENTRY_SKIPPED)

#: case 终局（``CaseOutcome.final`` 的取值）
FINAL_OUTCOMES = (
    "success",
    "no_match",
    "apply_rejected",
    "compile_fail",
    "poc_fail",
    "test_fail",
    "insufficient_facts",
    "invalid_baseline",
    "infra_error",
    # 阶段 A（R1 检索可验）的终局：没有修补动作，只能到“已检索”为止。
    # 单列而不复用 ``success``，避免 R1 的数字被误读成“修好了”。
    "retrieved",
)

CWE_RE = re.compile(r"^CWE-\d+$")


def is_canonical_cwe(value: Any) -> bool:
    return bool(CWE_RE.match(str(value or "")))


def cwe_key(value: Any) -> str:
    """CWE 归一化到规范串；抽不出就返回空串（= 永不过滤，交给校验拦下）。"""
    text = str(value or "").strip().upper()
    match = re.search(r"CWE[-_ ]?(\d+)", text)
    return f"CWE-{int(match.group(1))}" if match else ""


# ---------------------------------------------------------------- 入口：RepairCase


@dataclass
class Source:
    repo: str = ""
    commit: str = ""
    file: str = ""
    scan_file: str = ""


@dataclass
class Vuln:
    cwe: str = ""
    line: int = 0
    line_end: int = 0
    func: str = ""
    confidence: float = 0.0
    verdict: str = ""


@dataclass
class Code:
    func_src: str = ""
    body_line_start: int = 0
    body_line_end: int = 0
    #: ``file`` | ``function``；缺省时由 intake 推断并记 ``line_base_source``
    line_base: str = ""
    #: ``explicit``（输入里就有）| ``inferred``（intake 推断的）
    line_base_source: str = ""
    line_source: str = "llm"
    function_resolved_by: str = "llm"
    truncated: bool = False

    @property
    def lines(self) -> List[str]:
        return self.func_src.splitlines()

    @property
    def line_count(self) -> int:
        return len(self.lines)


@dataclass
class Evidence:
    """检测端 ``repair-input/1`` 的 ``evidence`` 原样透传（事实层的唯一输入）。"""

    path_status: str = ""
    path: List[Any] = field(default_factory=list)
    conditions: List[Any] = field(default_factory=list)
    blockers: List[Any] = field(default_factory=list)


@dataclass
class Intake:
    """修复端入口判定（本地新增，检测端不产出）。"""

    accepted: bool = False
    kind: str = ""
    reason: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {"accepted": self.accepted, "kind": self.kind, "reason": self.reason}


@dataclass
class RepairCase:
    """一个待修复 case 的全部输入。

    ``raw`` 保留检测端原始 dict：入口校验要交给检测端的 ``validate_repair_case``，
    从 dataclass 反推回 dict 容易漏字段，没必要冒这个险。
    """

    case_id: str = ""
    source: Source = field(default_factory=Source)
    vuln: Vuln = field(default_factory=Vuln)
    code: Code = field(default_factory=Code)
    evidence: Evidence = field(default_factory=Evidence)
    validation: Dict[str, Any] = field(default_factory=dict)
    intake: Intake = field(default_factory=Intake)
    raw: Dict[str, Any] = field(default_factory=dict, repr=False)
    #: 输入来自哪个数据集/批次，仅供记账（``repair-input/1`` / ``extractfix`` / ``zeroday``）
    origin: str = "repair-input/1"
    #: 评测集来源的附加记账（``eval_set`` / ``slice`` / ``vuln_line_abs`` / ``anchor_ok``）；
    #: 生产路径（``repair-input/1``）为空。刻意不进 ``to_dict()``：报告只需要 ``origin``。
    eval_meta: Dict[str, Any] = field(default_factory=dict, repr=False)
    # -- 构造 ---------------------------------------------------------------
    @classmethod
    def from_dict(cls, raw: Dict[str, Any], *, origin: str = "repair-input/1") -> "RepairCase":
        src = raw.get("source") or {}
        vuln = raw.get("vuln") or {}
        code = raw.get("code") or {}
        ev = raw.get("evidence") or {}
        return cls(
            case_id=str(raw.get("case_id") or ""),
            source=Source(
                repo=str(src.get("repo") or ""),
                commit=str(src.get("commit") or ""),
                file=str(src.get("file") or ""),
                scan_file=str(src.get("scan_file") or ""),
            ),
            vuln=Vuln(
                cwe=cwe_key(vuln.get("cwe")),
                line=_as_int(vuln.get("line")),
                line_end=_as_int(vuln.get("line_end")) or _as_int(vuln.get("line")),
                func=str(vuln.get("func") or ""),
                confidence=_as_float(vuln.get("confidence")),
                verdict=str(vuln.get("verdict") or ""),
            ),
            code=Code(
                func_src=str(code.get("func_src") or ""),
                body_line_start=_as_int(code.get("body_line_start")),
                body_line_end=_as_int(code.get("body_line_end")),
                line_base=str(code.get("line_base") or ""),
                line_base_source="explicit" if code.get("line_base") else "",
                line_source=str(code.get("line_source") or "llm"),
                function_resolved_by=str(code.get("function_resolved_by") or "llm"),
                truncated=bool(code.get("truncated") or False),
            ),
            evidence=Evidence(
                path_status=str(ev.get("path_status") or ""),
                path=list(ev.get("path") or []),
                conditions=list(ev.get("conditions") or []),
                blockers=list(ev.get("blockers") or []),
            ),
            validation=dict(raw.get("validation") or {}),
            raw=dict(raw),
            origin=origin,
        )
    # -- 校验 ---------------------------------------------------------------
    def detection_errors(self) -> List[str]:
        """检测端的六条校验（不重写，直接调用）。"""
        from verify_agent.repair_projection import validate_repair_case

        return list(validate_repair_case(self.raw)) if self.raw else ["raw 为空"]

    def line_base_errors(self) -> List[str]:
        """修复端**额外**的 ``line_base`` 判定（D5 / §9）。"""
        errors: List[str] = []
        base = self.code.line_base
        if base not in LINE_BASES:
            errors.append(f"code.line_base 非法：{base!r}（应为 {LINE_BASES}）")
            return errors

        start, end = self.code.body_line_start, self.code.body_line_end
        if base == "function" and start != 1:
            errors.append(f"line_base=function 但 body_line_start={start}（应恒为 1）")
        if base == "file" and start < 1:
            errors.append(f"line_base=file 但 body_line_start={start}（应 >= 1）")
        if base == "file" and not self.source.file:
            errors.append("line_base=file 但 source.file 为空（无法回到真实文件）")
        if not (start <= self.vuln.line <= end):
            errors.append(
                f"vuln.line {self.vuln.line} 不在 [{start}, {end}] 内（line_base={base}）"
            )
        return errors

    def validate(self) -> List[str]:
        """全部校验：检测端六条 + 修复端 line_base。空列表 = 可交给下游。"""
        return self.detection_errors() + self.line_base_errors()

    # -- 便捷 ---------------------------------------------------------------
    @property
    def vuln_line_local(self) -> int:
        """``vuln.line`` 在 ``func_src`` 内的下标（1-based）。"""
        return self.vuln.line - self.code.body_line_start + 1

    @property
    def anchor_text(self) -> str:
        local = self.vuln_line_local
        lines = self.code.lines
        if 1 <= local <= len(lines):
            return lines[local - 1].strip()
        return ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "case_id": self.case_id,
            "origin": self.origin,
            "source": {
                "repo": self.source.repo,
                "commit": self.source.commit,
                "file": self.source.file,
            },
            "vuln": {
                "cwe": self.vuln.cwe,
                "line": self.vuln.line,
                "line_end": self.vuln.line_end,
                "func": self.vuln.func,
                "confidence": self.vuln.confidence,
                "verdict": self.vuln.verdict,
            },
            "code": {
                "body_line_start": self.code.body_line_start,
                "body_line_end": self.code.body_line_end,
                "line_base": self.code.line_base,
                "line_base_source": self.code.line_base_source,
                "line_count": self.code.line_count,
                "line_source": self.code.line_source,
                "function_resolved_by": self.code.function_resolved_by,
            },
            "evidence": {
                "path_status": self.evidence.path_status,
                "n_path": len(self.evidence.path),
                "n_conditions": len(self.evidence.conditions),
                "n_blockers": len(self.evidence.blockers),
            },
            "validation": self.validation,
            "intake": self.intake.to_dict(),
            "anchor_text": self.anchor_text,
        }


# ---------------------------------------------------------------- 事实：FactSet


@dataclass
class RequiredGap:
    """``conditions[i].holds == True`` → 代码里确实缺这个前提。"""

    id: str
    kind: str = ""
    text: str = ""
    anchor_line: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {"id": self.id, "kind": self.kind, "text": self.text, "anchor_line": self.anchor_line}


@dataclass
class Protected:
    """``holds == False`` 且有 blocker → 已存在的守卫。

    注意语义边界：它只说明"这里**有一个**针对该符号的检查"，**不说明这个检查是对的**。
    ``if (row > nused)`` 会被判成 blocker，而它恰恰是那条 off-by-one 缺陷本身
    （实测：APPATCH extractfix 的 binutils dwarf.c 用例）。所以下游只能把它当
    "缺陷在守卫处或守卫与使用之间" 的线索，不能当成"此处无需改动"的免检牌。
    """

    id: str
    kind: str = ""
    line: int = 0
    code: str = ""
    symbol: str = ""
    #: 命中同一守卫的全部条件 id（多条假设常常落在同一个守卫上，按 (line, code) 合并后
    #: 用它把来源留住，避免 5 条假设被算成 5 个不同的守卫）
    condition_ids: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "kind": self.kind,
            "line": self.line,
            "code": self.code,
            "symbol": self.symbol,
            "condition_ids": list(self.condition_ids),
        }


@dataclass
class Reach:
    status: str = ""
    chain: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {"status": self.status, "chain": list(self.chain)}


@dataclass
class Dropped:
    """丢弃记账：``holds=null`` / ``path_status=unverifiable`` 一律进这里，不进统计。"""

    id: str
    reason: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {"id": self.id, "reason": self.reason}


@dataclass
class Sufficiency:
    ok: bool = False
    why: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {"ok": self.ok, "why": self.why}


@dataclass
class FactSet:
    required_gaps: List[RequiredGap] = field(default_factory=list)
    protected: List[Protected] = field(default_factory=list)
    reach: Reach = field(default_factory=Reach)
    dropped: List[Dropped] = field(default_factory=list)
    sufficiency: Sufficiency = field(default_factory=Sufficiency)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "required_gaps": [g.to_dict() for g in self.required_gaps],
            "protected": [p.to_dict() for p in self.protected],
            "reach": self.reach.to_dict(),
            "dropped": [d.to_dict() for d in self.dropped],
            "sufficiency": self.sufficiency.to_dict(),
        }

    @property
    def evidence_refs(self) -> List[str]:
        """本组事实涉及的全部 id（供 ``Query.evidence_refs`` 引用与审计）。"""
        refs = [g.id for g in self.required_gaps]
        for item in self.protected:
            refs.extend(item.condition_ids or [item.id])
        return list(dict.fromkeys(refs))


# ---------------------------------------------------------------- 检索键：Query


@dataclass
class QueryView:
    view_type: str = ""
    #: 唯一由 LLM 产出的字段
    root_cause: str = ""
    #: 来自 ``func_src`` 的 AST
    risky_calls: List[str] = field(default_factory=list)
    #: DF 视图：来自 required_gaps + reach.chain
    taint_flow: Optional[str] = None
    #: CF 视图：来自 required_gaps 的 kind + protected
    control_branch: Optional[str] = None
    #: 这段描述引用了哪几条事实（可审计字段）
    evidence_refs: List[str] = field(default_factory=list)
    #: 非空表示该视图的 root_cause 是降级产物，值为原因
    degraded_reason: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "view_type": self.view_type,
            "root_cause": self.root_cause,
            "risky_calls": list(self.risky_calls),
            "taint_flow": self.taint_flow,
            "control_branch": self.control_branch,
            "evidence_refs": list(self.evidence_refs),
            "degraded_reason": self.degraded_reason,
        }


@dataclass
class QueryPair:
    views: Dict[str, QueryView] = field(default_factory=dict)
    degraded: bool = False
    degraded_reason: str = ""
    #: 本次检索键的诊断来源：``evidence``（主臂，吃检测端事实）| ``none``（对照臂，只吃代码）
    source: str = "evidence"
    #: 每个视图的模型原文（复盘"是检索错还是生成错"要能回看，故随对象带走）
    raw: Dict[str, str] = field(default_factory=dict, repr=False)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "views": {k: v.to_dict() for k, v in self.views.items()},
            "degraded": self.degraded,
            "degraded_reason": self.degraded_reason,
            "source": self.source,
        }


# ---------------------------------------------------------------- 检索结果


@dataclass
class Exemplar:
    """知识库里的历史范例（``meta.jsonl`` 的一条）。"""

    pair_id: str = ""
    view_type: str = ""
    cwe: str = ""
    root_cause: str = ""
    fixing_strategy: str = ""
    risky_calls: List[str] = field(default_factory=list)
    vuln_code: str = ""
    fixed_code: str = ""
    index_row: int = -1

    @classmethod
    def from_meta(cls, meta: Dict[str, Any]) -> "Exemplar":
        return cls(
            pair_id=str(meta.get("pair_id") or ""),
            view_type=str(meta.get("view_type") or ""),
            cwe=str(meta.get("cwe") or ""),
            root_cause=str(meta.get("root_cause") or ""),
            fixing_strategy=str(meta.get("fixing_strategy") or ""),
            risky_calls=list(meta.get("risky_calls") or []),
            vuln_code=str(meta.get("vuln_code") or ""),
            fixed_code=str(meta.get("fixed_code") or ""),
            index_row=_as_int(meta.get("index_row")),
        )


@dataclass
class RetrievalHit:
    """一条检索命中。``rank`` 从 1 开始。

    ``bm25`` 是**池内 min-max 归一后**的值（真正参与打分），``bm25_raw`` 保留原始分，
    用于复盘"到底是归一化把排序改了，还是 BM25 本身选错了"。
    """

    pair_id: str = ""
    view_type: str = ""
    cwe: str = ""
    rank: int = 0
    cos: float = 0.0
    bm25: float = 0.0
    bm25_raw: float = 0.0
    score: float = 0.0
    index_row: int = -1

    def to_dict(self) -> Dict[str, Any]:
        return {
            "pair_id": self.pair_id,
            "view_type": self.view_type,
            "cwe": self.cwe,
            "rank": self.rank,
            "cos": round(self.cos, 6),
            "bm25": round(self.bm25, 6),
            "bm25_raw": round(self.bm25_raw, 6),
            "score": round(self.score, 6),
            "index_row": self.index_row,
        }


# ---------------------------------------------------------------- 轮次与结果


@dataclass
class PatchAttempt:
    """每轮一行 —— Table II 的唯一来源（B 阶段起用）。"""

    case_id: str = ""
    iter: int = 0
    views_used: List[str] = field(default_factory=list)
    diff_raw: str = ""
    diff_fixed: str = ""
    apply: str = "skip"
    compile: str = "skip"
    poc: str = "skip"
    test: str = "skip"
    log_head: str = ""
    tokens: Dict[str, int] = field(default_factory=dict)
    secs: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "case_id": self.case_id,
            "iter": self.iter,
            "views_used": list(self.views_used),
            "diff_raw": self.diff_raw,
            "diff_fixed": self.diff_fixed,
            "apply": self.apply,
            "compile": self.compile,
            "poc": self.poc,
            "test": self.test,
            "log_head": self.log_head,
            "tokens": dict(self.tokens),
            "secs": round(self.secs, 3),
        }


@dataclass
class CaseOutcome:
    """每个 case 一行。``final`` 必须在 :data:`FINAL_OUTCOMES` 内。"""

    case_id: str = ""
    origin: str = ""
    entry_kind: str = ""
    #: 入口判定的可读原因（``entry_kind`` 是机器档位，这个是给人看的）
    entry_reason: str = ""
    entry_verdict: str = ""
    line_base: str = ""
    facts_sufficiency: str = ""
    #: 充足性判定的理由原文（报告里直接引用，不重述）
    facts_sufficiency_why: str = ""
    facts_dropped: int = 0
    reverify_requested: bool = False
    reverify_rounds: int = 0
    reverify_improved: bool = False
    query_degraded: bool = False
    exemplar_pair_ids: List[str] = field(default_factory=list)
    final: str = ""
    iters: int = 0
    secs: float = 0.0

    def validate(self) -> List[str]:
        errors: List[str] = []
        if self.final and self.final not in FINAL_OUTCOMES:
            errors.append(f"final 非法：{self.final!r}")
        if self.entry_kind and self.entry_kind not in ENTRY_KINDS:
            errors.append(f"entry_kind 非法：{self.entry_kind!r}")
        if self.reverify_rounds > 1:
            errors.append("reverify_rounds > 1（单 case 最多 1 轮复核）")
        return errors

    def to_dict(self) -> Dict[str, Any]:
        return {
            "case_id": self.case_id,
            "origin": self.origin,
            "entry_kind": self.entry_kind,
            "entry_verdict": self.entry_verdict,
            "line_base": self.line_base,
            "facts_sufficiency": self.facts_sufficiency,
            "facts_sufficiency_why": self.facts_sufficiency_why,
            "facts_dropped": self.facts_dropped,
            "reverify": {
                "requested": self.reverify_requested,
                "rounds": self.reverify_rounds,
                "improved": self.reverify_improved,
            },
            "query_degraded": self.query_degraded,
            "exemplar_pair_ids": list(self.exemplar_pair_ids),
            "final": self.final,
            "iters": self.iters,
            "secs": round(self.secs, 3),
        }


# ---------------------------------------------------------------- 小工具


def _as_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _as_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


__all__ = [
    "VERDICTS",
    "LINE_BASES",
    "ENTRY_KINDS",
    "ENTRY_ACCEPTED",
    "ENTRY_INVALID",
    "ENTRY_SKIPPED",
    "FINAL_OUTCOMES",
    "is_canonical_cwe",
    "cwe_key",
    "Source",
    "Vuln",
    "Code",
    "Evidence",
    "Intake",
    "RepairCase",
    "RequiredGap",
    "Protected",
    "Reach",
    "Dropped",
    "Sufficiency",
    "FactSet",
    "QueryView",
    "QueryPair",
    "Exemplar",
    "RetrievalHit",
    "PatchAttempt",
    "CaseOutcome",
]
