#!/usr/bin/env python3
"""extract_cases.py

Stream the raw PrimeVul JSONL splits, keep *complete* functions whose line count
is in [20, 150] inclusive (>150 is skipped, never truncated), take the first N,
and write them to test_cases.jsonl.

Design constraints (from the task):
  * Stream line-by-line -- a whole raw file is never loaded into memory.
  * Only statistics and errors are printed to stdout/stderr.
  * The label is taken verbatim from the dataset field (`target`); we never
    re-judge whether a reported finding is "true".
  * Position state for every evaluated function is checkpointed to state.json so
    each function is tracked as an independent unit and the run is resumable.

PrimeVul record fields (raw): idx, project, commit_id, project_url, commit_url,
commit_message, target, func, func_hash, file_name, file_hash, cwe, cve,
cve_desc, nvd_url.  `target` = 1 (vulnerable) / 0 (benign); `cwe` is a list.
"""
import argparse
import glob
import json
import os
import sys
import time

MIN_LINES = 20
MAX_LINES = 150
PER_FUNCTION_CAP = 5000  # bound state.json size on pathological input


def strip_comments_and_literals(code):
    """Blank out // and /* */ comments plus string/char literals.

    Used only to make the brace-balance "is this a complete function?" check
    robust -- braces inside comments or literals do not affect nesting.
    """
    out = []
    i, n = 0, len(code)
    state = "code"  # code | line_comment | block_comment | str | chr
    while i < n:
        c = code[i]
        nxt = code[i + 1] if i + 1 < n else ""
        if state == "code":
            if c == "/" and nxt == "/":
                state = "line_comment"
                out.append(" ")
                i += 1
            elif c == "/" and nxt == "*":
                state = "block_comment"
                out.append(" ")
                i += 1
            elif c == '"':
                state = "str"
                out.append(" ")
            elif c == "'":
                state = "chr"
                out.append(" ")
            else:
                out.append(c)
        elif state == "line_comment":
            if c == "\n":
                state = "code"
                out.append(c)
        elif state == "block_comment":
            if c == "*" and nxt == "/":
                state = "code"
                i += 1
        elif state == "str":
            if c == "\\":
                i += 1  # skip escaped char
            elif c == '"':
                state = "code"
        elif state == "chr":
            if c == "\\":
                i += 1
            elif c == "'":
                state = "code"
        i += 1
    return "".join(out)


def is_complete_function(func):
    """Heuristic completeness check: balanced braces + ends with a closing brace."""
    if not isinstance(func, str) or not func.strip():
        return False
    code = strip_comments_and_literals(func)
    depth = 0
    saw_open = False
    for c in code:
        if c == "{":
            depth += 1
            saw_open = True
        elif c == "}":
            depth -= 1
            if depth < 0:
                return False
    if not saw_open or depth != 0:
        return False
    return code.rstrip().endswith("}")


def count_lines(func):
    """Function line count, ignoring trailing newline(s)."""
    return len(func.rstrip("\n").split("\n"))


def pick_inputs(raw_dir):
    """All *.jsonl under raw_dir, preferring test -> valid -> train."""
    files = glob.glob(os.path.join(raw_dir, "*.jsonl"))

    def rank(path):
        b = os.path.basename(path).lower()
        if "test" in b:
            return (0, b)
        if "valid" in b:
            return (1, b)
        if "train" in b:
            return (2, b)
        return (3, b)

    return sorted(files, key=rank)


def _flush_state(state, state_path):
    state["updated_at"] = time.strftime("%Y-%m-%dT%H:%M:%S")
    tmp = state_path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(state, fh, ensure_ascii=False, indent=2)
    os.replace(tmp, state_path)


def extract(raw_dir, out_path, state_path, limit):
    inputs = pick_inputs(raw_dir)
    if not inputs:
        print("ERROR: no *.jsonl found under %s" % raw_dir, file=sys.stderr)
        return 1

    state = {
        "target": limit,
        "min_lines": MIN_LINES,
        "max_lines": MAX_LINES,
        "started_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "files": [
            {
                "path": os.path.basename(p),
                "size": os.path.getsize(p),
                "processed_bytes": 0,
                "processed_lines": 0,
            }
            for p in inputs
        ],
        "per_function": [],
        "per_function_truncated": False,
        "counters": {
            "evaluated": 0,
            "accepted": 0,
            "skipped_too_short": 0,
            "skipped_too_long": 0,
            "skipped_incomplete": 0,
            "skipped_nonstring": 0,
            "json_error": 0,
            "other_error": 0,
        },
        "done": False,
    }
    _flush_state(state, state_path)

    cases = []
    seq = 0
    stop = False
    for fi, path in enumerate(inputs):
        if stop:
            break
        offset = 0
        line_no = 0
        with open(path, "rb") as fh:
            for raw in fh:
                line_no += 1
                start_off = offset
                offset += len(raw)
                s = raw.decode("utf-8", errors="replace").strip()
                if not s:
                    continue

                state["counters"]["evaluated"] += 1
                seq += 1
                try:
                    d = json.loads(s)
                except Exception as e:  # noqa: BLE001
                    state["counters"]["json_error"] += 1
                    if state["counters"]["json_error"] <= 5:
                        print(
                            "WARN json parse error at %s:%d: %s"
                            % (os.path.basename(path), line_no, e),
                            file=sys.stderr,
                        )
                    continue

                func = d.get("func")
                line_count = None
                try:
                    if not isinstance(func, str) or not func.strip():
                        status = "skipped_nonstring"
                        state["counters"][status] += 1
                    else:
                        line_count = count_lines(func)
                        if line_count > MAX_LINES:
                            # > 150 lines -> skip outright, never truncate.
                            status = "skipped_too_long"
                            state["counters"][status] += 1
                        elif line_count < MIN_LINES:
                            status = "skipped_too_short"
                            state["counters"][status] += 1
                        elif not is_complete_function(func):
                            status = "skipped_incomplete"
                            state["counters"][status] += 1
                        else:
                            status = "accepted"
                            state["counters"]["accepted"] += 1
                            cases.append(
                                {
                                    "id": d.get("idx", seq),
                                    "func": func,
                                    "label": d.get("target"),
                                    "cwe": d.get("cwe"),
                                    "line_count": line_count,
                                    "source": d.get("project"),
                                }
                            )
                            if len(cases) >= limit:
                                stop = True
                except Exception as e:  # noqa: BLE001
                    status = "error"
                    state["counters"]["other_error"] += 1
                    print(
                        "WARN processing error at %s:%d: %s"
                        % (os.path.basename(path), line_no, e),
                        file=sys.stderr,
                    )

                if len(state["per_function"]) < PER_FUNCTION_CAP:
                    state["per_function"].append(
                        {
                            "seq": seq,
                            "id": d.get("idx"),
                            "file": os.path.basename(path),
                            "line_no": line_no,
                            "byte_offset": start_off,
                            "line_count": line_count,
                            "status": status,
                        }
                    )
                else:
                    state["per_function_truncated"] = True

                if seq % 200 == 0:
                    _flush_state(state, state_path)

                if stop:
                    break
        state["files"][fi]["processed_bytes"] = offset
        state["files"][fi]["processed_lines"] = line_no

    # Write the selected cases.
    with open(out_path, "w", encoding="utf-8") as fh:
        for case in cases:
            fh.write(json.dumps(case, ensure_ascii=False) + "\n")

    state["done"] = True
    state["written_cases"] = len(cases)
    _flush_state(state, state_path)

    print("=== extract_cases.py summary ===")
    print("raw_dir: %s" % raw_dir)
    print("inputs : %s" % ", ".join(os.path.basename(p) for p in inputs))
    for f in state["files"]:
        print(
            "  %-26s size=%d processed_lines=%d"
            % (f["path"], f["size"], f["processed_lines"])
        )
    c = state["counters"]
    print(
        "evaluated=%d accepted=%d skipped_too_short=%d skipped_too_long=%d "
        "skipped_incomplete=%d skipped_nonstring=%d json_error=%d other_error=%d"
        % (
            c["evaluated"],
            c["accepted"],
            c["skipped_too_short"],
            c["skipped_too_long"],
            c["skipped_incomplete"],
            c["skipped_nonstring"],
            c["json_error"],
            c["other_error"],
        )
    )
    print("wrote %d cases -> %s" % (len(cases), out_path))
    print("state -> %s" % state_path)
    return 0


def validate(path):
    """Confirm the file has exactly N parseable JSON lines with 20<=line_count<=150."""
    problems = []
    n = 0
    with open(path, "r", encoding="utf-8") as fh:
        for i, line in enumerate(fh, 1):
            s = line.strip()
            if not s:
                problems.append("line %d: empty line" % i)
                continue
            n += 1
            try:
                d = json.loads(s)
            except Exception as e:  # noqa: BLE001
                problems.append("line %d: JSON parse error: %s" % (i, e))
                continue
            missing = [k for k in ("id", "func", "label", "cwe", "line_count", "source") if k not in d]
            if missing:
                problems.append("line %d: missing keys %s" % (i, missing))
            func = d.get("func")
            if not isinstance(func, str):
                problems.append("line %d: func is not a string" % i)
                continue
            lc = count_lines(func)
            if d.get("line_count") != lc:
                problems.append(
                    "line %d: line_count field (%s) != actual (%d)"
                    % (i, d.get("line_count"), lc)
                )
            if not (MIN_LINES <= lc <= MAX_LINES):
                problems.append("line %d: line_count %d out of [%d,%d]" % (i, lc, MIN_LINES, MAX_LINES))
    return n, problems


def main():
    ap = argparse.ArgumentParser(description="Extract PrimeVul test cases.")
    ap.add_argument("--raw-dir", default=os.path.join(os.path.dirname(__file__), "primevul_raw"))
    ap.add_argument("--out", default=os.path.join(os.path.dirname(__file__), "test_cases.jsonl"))
    ap.add_argument("--state", default=os.path.join(os.path.dirname(__file__), "state.json"))
    ap.add_argument("--limit", type=int, default=5)
    ap.add_argument("--validate-only", action="store_true")
    args = ap.parse_args()

    if not args.validate_only:
        rc = extract(args.raw_dir, args.out, args.state, args.limit)
        if rc != 0:
            return rc

    n, problems = validate(args.out)
    print("=== validation ===")
    print("lines: %d" % n)
    if problems:
        print("FAILED (%d problem(s)):" % len(problems))
        for p in problems:
            print("  - %s" % p)
        return 2
    print("OK: exactly %d parseable JSON line(s); every func line_count in [%d,%d]" % (n, MIN_LINES, MAX_LINES))
    return 0 if n == args.limit else 3


if __name__ == "__main__":
    sys.exit(main())
