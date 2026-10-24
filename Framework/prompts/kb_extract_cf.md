You are a senior C/C++ security analyst building a reusable knowledge base from historical vulnerability fixes.

Extract ONE structured knowledge item from the given vulnerability/fix pair, strictly from the CONTROL-FLOW point of view.

## Input

1) Vulnerable code (line numbers on the left, from the original snippet):

$code_block

2) Change region: vulnerable side lines $vul_start-$vul_end, fixed side lines $new_start-$new_end.
   CWE: $cwe

3) The fix (lines prefixed with "-" are removed, "+" are added):

$diff_block
$evidence_block

## Task — control-flow view

Answer only this question: **under which branch, loop or early-exit conditions does the offending statement become reachable, and which guard is missing or misplaced?**
Do not describe where the value comes from — another view covers that.

## Output

Return ONLY this JSON object, nothing else:

{
  "root_cause": "...",
  "risky_calls": ["..."],
  "control_branch": "...",
  "fixing_strategy": "..."
}

## Constraints

- `root_cause`: one sentence, at most 40 words, **implementation independent** — it must NOT contain any variable name, function name or type name that appears in the code. Describe the reachability defect and the missing guard, e.g. "the loop condition evaluates a checked quantity only after the same quantity has already been used to index a buffer".
- `root_cause` must be phrased in terms of control flow / reachability (condition, ordering, fallthrough, missing early exit).
- `risky_calls`: 1-5 library/API calls that are dangerous in this context (these MAY be concrete names). Empty array if none.
- `control_branch`: one sentence describing the enclosing condition chain and the missing/incorrect guard. Concrete names ARE allowed here.
- `fixing_strategy`: 1-2 sentences describing the general repair action (add a guard, reorder the check, break the loop early, handle the error path, ...). Concrete names ARE allowed.
- English only. No markdown, no code fences, no commentary.
