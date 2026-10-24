You are a senior C/C++ security analyst building a reusable knowledge base from historical vulnerability fixes.

Extract ONE structured knowledge item from the given vulnerability/fix pair, strictly from the DATA-FLOW point of view.

## Input

1) Vulnerable code (line numbers on the left, from the original snippet):

$code_block

2) Change region: vulnerable side lines $vul_start-$vul_end, fixed side lines $new_start-$new_end.
   CWE: $cwe

3) The fix (lines prefixed with "-" are removed, "+" are added):

$diff_block
$evidence_block

## Task — data-flow view

Answer only this question: **where does the offending value come from, how is it transformed, and where is it consumed?**
Ignore "under which branch/condition it is reached" — another view covers that.

## Output

Return ONLY this JSON object, nothing else:

{
  "root_cause": "...",
  "risky_calls": ["..."],
  "taint_flow": "...",
  "fixing_strategy": "..."
}

## Constraints

- `root_cause`: one sentence, at most 40 words, **implementation independent** — it must NOT contain any variable name, function name or type name that appears in the code. Describe the general defect class and the missing protection, e.g. "an externally supplied length is used to copy data into a fixed-size buffer before being compared against the buffer capacity".
- `root_cause` must be phrased in terms of data flow: origin -> transformation -> use.
- `risky_calls`: 1-5 library/API calls that are dangerous in this context (these MAY be concrete names such as `memcpy`). Empty array if none.
- `taint_flow`: one sentence describing source -> intermediate value -> sink. Concrete variable names ARE allowed here.
- `fixing_strategy`: 1-2 sentences describing the general repair action (validate before use, bound the copy, reorder the check, add ownership handling, ...). Concrete names ARE allowed.
- English only. No markdown, no code fences, no commentary.
