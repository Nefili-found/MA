"""K0/K1 自检脚本：在 306 对上跑 pairs → anchor → views，输出可对账的统计。

用法：
    python -m kbcore.selftest_k01 [--root <数据集根>] [--limit N] [--show K]

不调用任何模型、不写任何索引，只打印数字与样例行——用来把设计文档 §1 的实测口径
和真实代码对上。
"""

from __future__ import annotations

import argparse
import sys
from collections import Counter
from pathlib import Path

from .anchor import CROSSCHECK_TOLERANCE, crosscheck_with_ast, locate
from .pairs import KNOWN_CWES, cwe_histogram, load_pairs
from .views import extract_evidence

DEFAULT_ROOT = Path("other fix framework/datasets/patchdb_cvefixes_for_appatch_train")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="K0/K1 自检（无 LLM）")
    ap.add_argument("--root", default=str(DEFAULT_ROOT))
    ap.add_argument("--limit", type=int, default=None)
    ap.add_argument("--show", type=int, default=0, help="打印前 K 对的证据样例")
    args = ap.parse_args(argv)

    root = Path(args.root)
    pairs = load_pairs(root, limit=args.limit)
    print(f"pairs            : {len(pairs)}")
    print(f"cwe histogram    : {cwe_histogram(pairs)}")

    kinds: Counter[str] = Counter()
    confs: Counter[str] = Counter()
    extra_ops = 0
    low_examples: list[str] = []
    cross_true = cross_false = cross_none = 0
    ev_ok = ev_none = 0
    df_items = cf_items = 0
    no_func: list[str] = []
    scopes: Counter[str] = Counter()

    for pair in pairs:
        anchor = locate(pair)
        kinds[anchor.kind] += 1
        confs[anchor.confidence] += 1
        extra_ops += anchor.extra_ops
        if anchor.confidence == "low" and len(low_examples) < 5:
            low_examples.append(f"{pair.pair_id[:58]} ratio={anchor.ratio:.3f}")

        cc = crosscheck_with_ast(pair, anchor)
        if cc is None:
            cross_none += 1
        elif cc:
            cross_true += 1
        else:
            cross_false += 1

        ev = extract_evidence(pair, anchor)
        if ev is None:
            ev_none += 1
            if len(no_func) < 5:
                no_func.append(f"{pair.pair_id[:58]} anchor=L{anchor.vul_start}-{anchor.vul_end}")
        else:
            ev_ok += 1
            df_items += len(ev.df.defs) + len(ev.df.calls)
            cf_items += len(ev.cf.guards) + len(ev.cf.loops) + len(ev.cf.early_returns)
            scopes[ev.scope] += 1

        if args.show and args.show > 0 and pairs.index(pair) < args.show:
            print("\n" + "=" * 78)
            print(pair.pair_id)
            print(f"cwe={pair.cwe} cve={pair.cve} func={pair.func}")
            print(f"anchor={anchor.as_dict()}")
            if ev is not None:
                print("--- DF ---")
                print(ev.df.render() or "(empty)")
                print("--- CF ---")
                print(ev.cf.render() or "(empty)")

    n = len(pairs)
    print(f"\nanchor kind      : {dict(kinds)}")
    print(f"anchor confidence: {dict(confs)}  extra_ops_total={extra_ops}")
    print(f"crosscheck       : hit={cross_true} miss={cross_false} n/a={cross_none}"
          f"  (±{CROSSCHECK_TOLERANCE} 行, 仅带 .diff 工件的对可用)")
    if cross_true + cross_false:
        rate = cross_true / (cross_true + cross_false)
        print(f"crosscheck rate  : {rate:.1%}  (阈值 ≥70%)")
    print(f"evidence         : ok={ev_ok} none={ev_none}  ({ev_ok / n:.1%} 覆盖)")
    print(f"evidence scope   : {dict(scopes)}  (file = 片段非法 C，证据退化为整片段)")
    if ev_ok:
        print(f"avg items/pair   : df={df_items / ev_ok:.1f} cf={cf_items / ev_ok:.1f}")

    if low_examples:
        print("\nlow-confidence examples:")
        for line in low_examples:
            print("  " + line)
    if no_func:
        print("\nno-evidence examples:")
        for line in no_func:
            print("  " + line)

    ok = (
        len(pairs) > 0
        and confs.get("low", 0) <= max(3, int(0.10 * n))  # low-confidence 占比 ≤ 10%
        and (cross_true + cross_false) > 0
        and (cross_true / max(1, cross_true + cross_false)) >= 0.70
        and ev_ok / n >= 0.90  # 证据覆盖率 ≥ 90%
    )
    print("\nK0/K1 verdict    :", "PASS" if ok else "CHECK")
    return 0 if ok else 1


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
