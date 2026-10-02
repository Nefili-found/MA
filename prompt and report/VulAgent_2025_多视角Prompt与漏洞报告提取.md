# VulAgent（2025, IEEE / arXiv:2509.11523）多视角 Prompt 与漏洞报告提取

> 源文献：Ziliang Wang, Ge Li, Jia Li, Hao Zhu, Zhi Jin. *VulAgent: A Hypothesis Validation-Based Multi-Agent System for Software Vulnerability Detection*. arXiv:2509.11523v1 [cs.SE], 2025-09-15.
> 说明：本文所有 Prompt 均按论文 Figure 2 / 正文方框**原文摘录**（保留英文原貌），中文为结构性注解。论文未完整给出的部分已明确标注为"文中未给出/由模板推知"。

---

## 一、总体架构与四阶段流水线

VulAgent 把漏洞检测解耦为四个阶段，每个阶段由一类智能体承担：

| 阶段 | 智能体 | 视角定位 | 输出物 |
|---|---|---|---|
| Phase I：多视角检测与聚合 | MetaAgent → N 个专用 Analyzer → AggregatorAgent | 按 CWE 语义族切分的"分析视角" | 去重后的候选漏洞报告集合 |
| Phase II：假设构建 | TriggerPlanner | "攻击者可达性"视角 | 假设条件 A + 触发路径 P |
| Phase III：假设条件验证 | AssumptionPrunerAgent | "工程语境/不变量"视角 | 每条假设的 plausible / contradicted / unknown |
| Phase IV：路径防护校验 | FinalValidator | "防护是否支配路径"视角 | 最终漏洞报告（含 CWE 列表） |

预处理：对输入代码**逐行编号**（`int foo()` → `L1: int foo()`），行号贯穿检测、验证、报告全流程。

上下文来源：PrimeVul 用 Joern 抽取 CFG / 数据依赖 / 调用图；SVEN 自研静态工具回溯原始文件，构建最小上下文（项目名、文件内定义/调用函数、引用库）。

---

## 二、视角清单：11 个智能体（1 路由 + 10 专用）+ 4 个后处理智能体

### 2.1 MetaAgent（路由视角）
按函数**语义**而非关键字匹配，激活"最小但充分"的分析智能体集合。

### 2.2 基线集合 B（永远激活的 3 个兜底视角）

| 智能体 | 视角 | 职责 |
|---|---|---|
| StaticAnalyzerAgent | 语法/模式层 | 静态模式扫描，发现明显 red flags |
| BehaviorAnalyzerAgent | 控制流/数据流层 | 路径与错误处理缺陷推理 |
| MemoryLayoutAgent | 内存布局层 | 指针算术、缓冲区边界 |

形式化：`A_i = B ∪ (⋃_{r∈R} r(φ(c_i)))`，其中 `B = {AnalyzerAgent, BehaviorAnalyzerAgent, MemoryLayoutAgent}`。

> ⚠️ 论文内部命名不一致：公式与激活列表写 `AnalyzerAgent`，正文清单第 (1) 项与 Figure 2 方框标题写 `StaticAnalyzerAgent`，二者指同一角色。

### 2.3 专用分析智能体（按语义 cue 动态激活，共 10 个）

| # | 智能体 | 分析视角 | 关注对象 |
|---|---|---|---|
| 1 | StaticAnalyzerAgent | 静态模式 | 可疑语法模式 |
| 2 | BehaviorAnalyzerAgent | 运行时行为 | 控制/数据流模拟 |
| 3 | MemoryLayoutAgent | 内存布局 | 指针算术、缓冲区安全 |
| 4 | FormatStringAgent | 格式化字符串 | 不可控 format string |
| 5 | FilePermissionAgent | 文件与权限 | 不安全文件操作、权限变更 |
| 6 | AuthFlowAgent | 认证与授权 | 认证流、特权逻辑 |
| 7 | CryptoConfigAgent | 密码学配置 | 弱算法/错误配置/RNG 初始化 |
| 8 | ConcurrencyAnalyzerAgent | 并发 | 竞态、同步问题 |
| 9 | ErrorHandlingAgent | 错误处理 | 缺失错误处理、资源清理 |
| 10 | CodeInjectionAgent | 代码注入 | 动态代码执行、命令注入 |

路由示例：`format_string ↦ FormatStringAgent`。

### 2.4 后处理智能体
AggregatorAgent（聚合去重）、TriggerPlanner（假设构建）、AssumptionPrunerAgent（条件剪枝）、FinalValidator（最终裁定）。

---

## 三、各视角对应的 Prompt（原文）

### 3.1 MetaAgent — 视角分派 Prompt

```
Your goal is maximum recall, especially for semantic, and privilege-sensitive
vulnerabilities. You should select agents based on the semantics of the function,
not just keyword matches.

Input: {Code}

*BehaviorAnalyzerAgent: Detects behavioral flaws such as resource leaks, missing checks
*MemoryLayoutAgent: Detects pointer arithmetic, buffer handling, raw parsing,
                    or memory shape misuse
*CryptoConfigAgent:   Analyzes crypto usage, cipher config, RNG initialization
…

"Activated_agents": ["AnalyzerAgent", "BehaviorAnalyzerAgent",
                     "MemoryLayoutAgent", "FormatStringAgent", ...]
```

设计要点：
- 目标函数显式设为 **最大召回**（宁可多报，过滤交给下游）；
- 强调**按语义而非关键字**选择，避免关键词命中偏差；
- Always-on 的 3 个基线智能体构成安全网，即便 crypto/auth 未触发也有覆盖。

---

### 3.2 专用分析智能体 — 统一 Prompt 模板（四要素）

论文明确说明：**所有 base agents 共享同一套 prompt 模板**，模板包含四部分：

| 要素 | 内容 |
|---|---|
| (i) Role & Task | 该智能体针对的风险类型（memory layout / format string / file permission / auth flow / crypto config / concurrency / error handling / code injection），作用于**单个带行号的 C/C++ 函数** |
| (ii) CWE focus & trigger hints | 主 CWE ID + 典型触发模式（如适用） |
| (iii) Output contract | **严格 JSON schema** |
| (iv) Inputs | 编号后的函数体 `{function_code}` + 可选上下文 |

原文强调：*"These patterns are representative examples of how a CWE may manifest. They are not exhaustive. If the code exhibits behavior consistent with the CWE semantics: {CWE-787 / CWE-125, CWE-476..}"* —— 即 CWE 列表只是示例，判断依据是**语义一致性**而非模式穷举。

#### 论文中给出的唯一完整实例化示例：StaticAnalyzerAgent

```
Your responsibility is to analyze a single function code in isolation and identify
potential vulnerabilities using static pattern recognition and local reasoning.
These patterns are representative *examples* of how a CWE may manifest. They are
not exhaustive. If the code exhibits behavior consistent with the CWE semantics:
{CWE-787 / CWE-125, CWE-476..}

Input: {Code}
```

其输出报告样例：

```
CWE: CWE-476
Location: L14, L16…
Description: Potential NULL pointer dereference. The result of
             'entries.getUnchecked(index)' is used without a NULL check.
```

> 其余 9 个专用智能体（FormatString / FilePermission / AuthFlow / CryptoConfig / Concurrency / ErrorHandling / CodeInjection 等）论文**未逐条给出 prompt 原文**，只给出职责描述；按上述四要素模板套用即可复现。

#### 单个智能体输出的一般形式

每个被激活的智能体 `a` 输出一份文本报告 `t_i^a`，包含三部分：**finding（发现）+ trigger（触发）+ evidence（证据）**。
智能体被要求"保守运作以最大化召回"，因此原始输出含大量误报，仅作候选。

---

### 3.3 AggregatorAgent — 报告聚合 Prompt

```
Your goal is maximum recall, especially for semantic, and privilege-sensitive
vulnerabilities. You should select agents based on the semantics of the function,
not just keyword matches.

Input: {reports from all agents}

*Duplicate-merging rules
Merge all semantically identical issues into one report, integrating different
lines, descriptions, and perspectives into a unified entry

{ "vulnerability_reported": true,
  "confirmed_issues": [
    { "cwe": "CWE-787",
      "code_line": "12,15",
      "description": "Potential out-of-bounds write in buffer copy
                      (merged from multiple agents)." },
    { "cwe": "CWE-476", … } ] }
```

三条聚合规则（正文明确列出）：
1. **按 CWE + 行区间分组**：同 CWE 且行范围相同或重叠的条目归为一组，其余单独保留；
2. **组内合并**：保留一条最代表性的描述，证据片段与行引用取并集，并记录 `source_agents` 列表；
3. **保留必要项**：CWE 不同或区间不重叠的条目不得丢弃，作为独立条目继续传递。

形式化：`T_i = { t_i^a | a ∈ A_i }`，`ẽT_i = Agg(T_i)`。

> ⚠️ 提取观察：Figure 2 中 AggregatorAgent 方框的目标句与 MetaAgent 完全相同（"Your goal is maximum recall… select agents…"），疑为论文排版复制；Aggregator 的实际职责由下方 *Duplicate-merging rules* 与正文三条规则定义。

---

### 3.4 TriggerPlanner — 假设构建 Prompt

```
Input: {reports from AggregatorAgent}

Your only job is: **For each candidate issue, construct a feasible, attacker-controllable
path to the reported sink**, based on the upstream agent reports and the analyzed
function code. You are **not** responsible for judging whether the vulnerability is
valid or blocked. You are **not** allowed to discard paths based on protection logic
(e.g. bounds checks, guards, error handling, secure allocators). All filtering happens
later in the pipeline.

"confirmed_issues": [
  { "cwe": "CWE-476",
    "description": "...",
    "code_line": "L10,L22",
    "trigger_path": "A1: ... → L10: assignment → L22: struct write → ...",
    "assumptions": "A1: ..., A2: ..." },
  { "cwe": "767", … } … ]
```

Prompt 的四条硬约束（正文归纳）：
1. 定位上游报告给出的 **sink**（内存写、解引用、系统调用）；
2. 在函数内**反向回溯**数据如何流入该 sink；
3. 沿控制流/数据流边**追踪攻击者可控输入**（参数、缓冲区、文件读、反序列化结构）直到 sink；
4. 把中间步骤（赋值、变换、条件）记录为执行轨迹的一部分。

关键设计：**禁止用防护逻辑剪枝**，遇到的所有 guard 条件必须显式记录为假设 `A`，而不是用来丢弃路径。

形式化：`h_{i,k} = Ψ(ẽt_i^{(k)}, C_i) = ⟨cwe_{i,k}, A_{i,k}, P_{i,k}⟩`

路径模型：`P_{i,k} = v1 —e1→ v2 —e2→ … —e_{m-1}→ v_m`，其中 `v1 ∈ S_att`（攻击者可控源，如参数/文件网络读/反序列化输入），`v_m = s_{i,k}`（sink），边为控制或数据依赖边。

---

### 3.5 AssumptionPrunerAgent — 假设条件验证 Prompt

```
Input: {reports from TriggerPlanner}

You are **AssumptionPrunerAgent**, responsible for validating path hypotheses in
vulnerability reports and removing invalid entries based on flawed assumptions.

Your job is:
- For **each assumption**, determine:
  1. Whether it is **plausible**, **contradicted**, or **unknown**
  2. Whether invalidating this assumption would cause the **trigger_path to fail**
  3. When judging assumptions, consider whether project semantics, invariants, or
     common deployment contexts contradict them; discard assumptions that cannot
     realistically hold.

"confirmed_issues": [{
  "cwe": "...", "description": "...", "trigger_path": "...", "code_line": "...",
  "assumptions_checked": [{
      "assumption": "A1: platform_info.xla_device_metadata() is NULL",
      "status": "contradicted",
      "reason": "The xla_device_metadata() function is expected to return valid metadata.."
  }],
  [{ "assumption": "A2 ……] }]
```

判定逻辑形式化：`(ν_{i,k,j}, E_{i,k,j}) = f_va(a_{i,k,j}, c_i, C_i^ctx)`，其中 `ν ∈ {valid, contradicted, plausible}`，`E` 为支撑证据（引用行、推断的不变量、常量范围）。

只有 `Â_{i,k} = { a_{i,k,j} ∈ A_{i,k} | ν = valid 或 plausible }` 进入下一阶段；**路径推理被推迟到 Phase IV**。

判定依据（正文）：与结构不变量、API 语义、生命周期保证、同步规则相冲突 → `contradicted`；证据不足者保留为 `plausible` 但打标记。

#### 论文给出的图示化示例（Figure 3）

```
假设：A1: input is too long
Function A: void handle_request(char *input){
                if (strlen(input) > 256) return;   // boundary check
                process(input); }
Function B: void process(char *buf) { do_work(buf); }
Function C（被测函数，含 sink）: void do_work(char *data) { strcpy(global_buf, data); }

→ 调用图揭示 A、B 是 C 的调用者（收集为上下文）
→ Function A 中的长度检查与 A1 冲突
→ A1 判定为 contradicted，依赖 A1 的整条假设被拒绝
```

---

### 3.6 FinalValidator — 路径防护校验 Prompt

```
Input: {reports from AssumptionPrunerAgent, function_code, code_context}

You need to assess whether each CWE report's trigger path is valid — i.e., not
effectively blocked, guarded, or negated. Your goal is to:
- The analysis should not be limited to a single trigger path. Instead, it should
  identify prior safeguards, logical constraints, or subsequent error-handling
  behaviors across the entire code, context, and project knowledge to determine
  whether effective protection is already in place. This includes evaluating
  conditions, loop termination guarantees, and the equivalence or bounds between
  allocation sizes and access sizes.
- Prevent true vulnerabilities from being missed.

"confirmed_issues": [{
  "cwe": "CWE-617", "trigger_path": "...", "description": "...",
  "Path_validity": "Yes",
  "Reason_judgment": "..." },
  { "cwe": "CWE-190", …
    "Path_validity": "No", ... }],
"vulnerability_reported": true or false,   // ← Whether any "Yes" judgment exists
"cwe_list": ["CWE-617"]                    // ← All CWE types marked "Yes"
```

四条核心要求：
1. **二元判定 + guard-dominance 思想**：路径默认有效，除非存在置于 sink 之前、且覆盖所有可行路径的防护；
2. 综合参考控制流、数据流、调用关系、语义上下文（API 行为、生命周期、配置）寻找**具体证据**；
3. 出现明确的 sink 前防御、净化/覆写、前提不成立、保护性 API 语义、不可达、仅无害结果 → 拒绝路径；不确定则**保留并附简短理由**（不因不确定而抑制）；
4. 每条 CWE 条目返回严格 JSON 判定，外加全局 `vulnerability_reported` 与 `cwe_list`。

形式化：`r_{i,k} = f_pc(P_{i,k}, c_i, C_i^ctx; Â_{i,k})`，当且仅当触发路径被"位于 sink 之前 + 覆盖攻击者可控源到 sink 的所有可行路由"的防护所支配时判为 discarded。

---

## 四、漏洞报告的具体内容：四阶段报告结构对照

| 阶段 | 报告字段 | 语义 |
|---|---|---|
| **阶段一（单智能体）** | `CWE` / `Location`（行号）/ `Description` + `finding` / `trigger` / `evidence` | 单视角的原始候选，高召回 |
| **阶段一聚合后** | `vulnerability_reported`、`confirmed_issues[{cwe, code_line, description}]`、`source_agents` | 去重合并后的候选集 |
| **阶段二** | 增补 `trigger_path`（`A1: … → L10: assignment → L22: struct write → …`）、`assumptions`（`A1: … , A2: …`） | 结构化漏洞假设 |
| **阶段三** | 增补 `assumptions_checked[{assumption, status, reason}]`，`status ∈ {plausible, contradicted, unknown}` | 假设可行性剪枝 |
| **阶段四（最终）** | `confirmed_issues[{cwe, trigger_path, description, Path_validity, Reason_judgment}]`、`vulnerability_reported`、`cwe_list` | 最终交付报告 |

### 最终报告的判定语义
- `Path_validity = Yes` → 该 CWE 成立，计入 `cwe_list`；
- 只要存在任意 `Yes`，`vulnerability_reported = true`；
- 全部为 `No` → `vulnerability_reported = false`，判定为无漏洞。

---

## 五、案例研究中的具体报告内容（`search_make_new`，libevent evdns.c，commit ec65c42，CWE-125）

**真实标签：无漏洞（no-vulnerability）。**

### 5.1 基线（VulTrial，单/多智能体基线）报告的 5 条漏洞

| # | 报告类型 | 报告内容（原文要点） |
|---|---|---|
| 1 | Heap buffer overflow | `memcpy(newname + base_len + need_to_append_dot, postfix, postfix_len)` 可能溢出，理由是若 `postfix_len` 攻击者可控则缓冲区可能不足 |
| 2 | Integer overflow | 分配尺寸表达式 `base_len + need_to_append_dot + postfix_len + 1` 可能回绕，分配出比需求更小的缓冲区 |
| 3 | Null dereference | 若 `mm_malloc` 分配失败，`newname` 可能为 NULL 并被使用 |
| 4 | Loop-bound failure | `n` 为负可能导致非预期循环行为 |
| 5 | DoS via assertion | `EVUTIL_ASSERT(0)` 可被攻击者触发，导致程序终止 |

**复核结论：5 条全部为误报。**

### 5.2 VulAgent 的验证报告（逐条驳回理由）

- **分配尺寸**：已完整包含 `postfix_len`，缓冲区足以容纳写入 → 溢出假设不成立；
- **空指针**：`if (!newname) return NULL;` 显式判空，风险被中和；
- **内部指针可控性**：`state->head`、`dom->len` 来自内部可信分配，任何可行路径下都不可被攻击者控制 → 假设被引用结构不变量驳回；
- **断言**：`EVUTIL_ASSERT(0)` 在攻击者影响下不可达，判定为不可利用；
- **循环变量**：`n` 有界，内部链表遍历逻辑保证正确性。

**最终输出：所有路径均判定为不可利用，`vulnerability_reported = false`，与 ground truth 一致。**

### 5.3 案例揭示的核心结论
> LLM 检测器常把"理论缺陷"与"实际攻击面"混淆，导致高误报；关键在于能否依据工程项目的具体上下文排除不可触发的攻击路径。

---

## 六、Prompt 工程要点（可迁移设计）

1. **视角解耦**：按 CWE 语义族切分智能体，每个只关注单一关注点，降低推理深度与耦合；
2. **召回/精确职责分离**：上游（Meta / 专用 Analyzer / TriggerPlanner）一律"最大召回、禁止剪枝"，剪权集中在下游（AssumptionPruner / FinalValidator）；
3. **把上下文使用变成"假设驱动的定向检索"**：不是把上下文拼接进去，而是把每条假设变成一次定向查询；
4. **行号贯穿全流程**：预处理加行号，使敏感行可在检测→验证→报告间一致引用与传播；
5. **严格 JSON 输出契约**：配合非推理模型 + temperature=0 / top_p=1，控制 token 与延迟；
6. **不确定即保留**（FinalValidator）：不因证据不足而抑制，避免漏报，仅附简短理由。

---

## 七、复现相关配置（论文 3.2 节）

- 模型：Qwen3-235B-A22-instruct / GPT-4o / DeepSeek v3.1（商用 API）
- 采样：`temperature = 0`，`top_p = 1`；**不使用 few-shot 代码示例**
- 开销：平均每样本 **8.83 次调用、7,036.95 输出 token**；多线程并发度 8
- 数据集：PrimeVul（验证集 435 对，其中 304 对有上下文）、SVEN（803 对，9 种 CWE，C/C++ + Python）
- 开源物：全部生成的漏洞报告、Prompts、系统逻辑、SVEN 上下文构建静态工具、上下文增强数据集

---

## 附：论文未给出、需自行构造的部分

| 缺口 | 说明 |
|---|---|
| 9 个专用智能体的完整 Prompt 原文 | 仅 StaticAnalyzerAgent 有实例化示例，其余需按"四要素模板"（Role & Task / CWE focus & trigger hints / Output contract / Inputs）自行填充 |
| 各智能体的具体 CWE ID 映射表 | 仅举例 `CWE-787 / CWE-125 / CWE-476`、`format_string ↦ FormatStringAgent` |
| AssumptionPruner 的检索接口细节 | 仅说明用 Joern 取 CFG / 数据依赖 / 调用图，未给 API 层实现 |
| 各阶段 JSON schema 的完整字段定义 | 论文只给示例片段，字段名大小写在不同方框中不完全一致（如 `cwe` / `"767"` / `"CWE-617"`） |
