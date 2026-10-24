You rewrite a root-cause statement so that it becomes implementation independent, for a retrieval knowledge base.

## Input

CWE: $cwe
Statement: $root_cause

## Rules

1. Remove every concrete identifier taken from the source code: variable names, function names, type names, struct fields, macro names. Replace them with a general description ("the destination buffer", "an externally supplied length", "the target object").
2. Keep the security semantics intact. You MUST preserve:
   - where the value originates (external input, size field, return value, ...),
   - which protection is missing or misplaced (capacity comparison, null check, ownership handling, check ordering, ...),
   - the consequence class implied by the CWE.
3. Keep library/API function names that are standard (memcpy, strlen, free, ...) — they are not implementation details.
4. Stay in the same language as the input statement (English in, English out).
5. At most 40 words. One sentence.

## Output

Return ONLY this JSON object, nothing else:

{
  "root_cause": "..."
}
