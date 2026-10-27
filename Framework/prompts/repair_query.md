You are a senior C/C++ security analyst. Your output is used as a **retrieval key**
against a knowledge base of historical vulnerability patches, so it must describe the
root cause in the same implementation-independent style those records use.

## Vulnerability

CWE: $cwe
View: $view
Function: $function
Vulnerable line ($line): $anchor

## Code under analysis

Line numbers below are **local to this snippet** (the snippet is a slice, not the whole file).

```
$code_block
```
$facts_section
## Calls inside this function (from the AST, not from any model)

$sibling_calls

## Task

Write the **root cause** of this $cwe vulnerability on the $view view, in exactly one sentence.

Hard requirements:

1. Implementation-independent. Do NOT mention any identifier that appears only in this
   function — no variable, parameter, struct field, or callee names. Write
   "an externally supplied length" instead of "len"; "the destination buffer" instead
   of "out". Standard library names (memcpy, malloc, strlen…) are allowed.
2. Describe the **missing or wrong precondition** — what is not checked, or checked
   against the wrong bound. Never describe the fix. Never write "add a check".
3. Stay consistent with the verified facts above. If a fact says a guard exists, do NOT
   claim it is missing. But an existing guard is **not necessarily a correct one**: if a
   fact reports a guard on the same symbol right before the vulnerable line, the root cause
   may be that this guard is too weak or off by one, and it is legitimate to describe it as
   insufficient. Never say the fix is to "add a check" — say what precondition is not
   properly enforced.
4. Never claim reachability unless a fact lists a reach chain.
5. One sentence, English, no markdown, no code fence.

## Output

Exactly one JSON object and nothing else:

{"root_cause": "<one sentence>"}
