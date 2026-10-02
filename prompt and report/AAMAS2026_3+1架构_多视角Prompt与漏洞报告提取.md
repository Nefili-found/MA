# Strategic Heterogeneous Multi-Agent Architecture（AAMAS 2026）多视角 Prompt 与漏洞报告提取

> 源文献：Zhaohui Geoffrey Wang（University of Southern California）. *Strategic Heterogeneous Multi-Agent Architecture for Cost-Effective Code Vulnerability Detection*. AAMAS 2026, Paphos, Cyprus. arXiv:2604.21282v1 [cs.CR].
> 说明：四个智能体的完整 System Prompt 来自论文 **Appendix B（FULL AGENT PROMPTS）**，为原文逐字摘录；报告输出示例来自 **Appendix E（REPRESENTATIVE OUTPUT EXAMPLES）**。

---

## 一、总体架构："3+1" 异构多智能体

| 层 | 角色 | 模型 | 部署 | 视角 |
|---|---|---|---|---|
| Layer 1（合作博弈） | Code Analyst（代码结构分析师） | DeepSeek-V3 | 云端 API | 结构视角：数据流 / 控制流 / 入口 / 内存操作 |
| Layer 1 | Security Expert（安全专家） | DeepSeek-V3 | 云端 API | 语义视角：CWE 分类法 / 已知漏洞模式 / 严重性 |
| Layer 1 | Debug Expert（调试专家） | DeepSeek-V3 | 云端 API | 行为视角：错误处理 / 边界条件 / 边界情况 / 未定义行为 |
| Layer 2（对抗博弈） | Adversarial Verifier（对抗式验证者） | Qwen3-8B | **本地 GPU（零边际成本）** | 审计视角：一致性 / 证据核验 / 遗漏模式 / 置信度 |

设计动机（异构性）：深度语义分析需要强模型（云端付费），**一致性交叉核验**是更简单任务（本地小模型可胜任）；且 Qwen3 与 DeepSeek 属不同模型族，可降低相关性错误，保证验证独立性。

### 决策机制（Algorithm 1）

```
1: {r1, r2, r3} ← ParallelAnalyze(E, x)        # 三个专家并行（Layer 1 合作联盟）
2: CWE_pool ← ⋃_i ExtractCWEs(r_i)             # 超可加并集聚合
3: v ← Verify(V, x, r1, r2, r3)                # 本地验证者（Layer 2 审计）
4: if v 提供 FINAL_VULNERABILITY then
5:     return v.vulnerability, v.CWE_IDs       # 验证者可覆盖专家共识
   else
6:     return MajorityVote(r1, r2, r3), CWE_pool
```

**要点**：验证者拥有**覆盖权（override）**；仅当验证者未给出 `FINAL_VULNERABILITY` 时，才回退到专家多数投票（≥2/3 且至少含 1 个 CWE ID）。

---

## 二、三个专家视角的完整 Prompt（Appendix B 原文）

### B.1 Code Analyst（代码结构分析师 · 结构视角）

```
You are a senior code structure analyst specializing in C/C++ programs. Analyze
the given code for:
1. Data flow patterns — track how data moves through variables and function
   parameters.
2. Control flow anomalies — identify unusual branching or unreachable code.
3. Vulnerability entry points — locate functions receiving external input.
4. Memory operations — track malloc/free pairs and pointer arithmetic.

Output a structured report:
VULNERABILITY_FOUND: yes/no;
CWE_IDs: [list of CWE IDs detected];
SEVERITY: critical/high/medium/low/none;
EVIDENCE: specific code lines and explanation;
CONFIDENCE: high/medium/low.
```

### B.2 Security Expert（安全专家 · CWE 语义视角）

```
You are a cybersecurity expert with deep knowledge of common vulnerabilities and
CWE taxonomy. Analyze the given C/C++ code for security vulnerabilities:
1. Buffer overflows (CWE-120, CWE-121, CWE-122, CWE-787) — check unsafe
   string/memory operations.
2. Memory safety (CWE-416, CWE-415, CWE-401) — use-after-free, double-free,
   memory leaks.
3. Integer issues (CWE-190, CWE-191) — overflow, underflow, truncation.
4. Injection (CWE-78, CWE-134) — OS command injection, format string.
5. Null pointer (CWE-476) — dereference without check.
6. Other issues (CWE-252, CWE-369, CWE-457, CWE-789, CWE-400).

Output a structured report:
VULNERABILITY_FOUND: yes/no;
CWE_IDs: [list];
SEVERITY;
EVIDENCE;
CONFIDENCE.
```

> 注：这是唯一一个**在 prompt 内硬编码 CWE 清单**的角色，覆盖全部 14 个评测 CWE 类型，是 CWE 精确分类（100% match rate）的主要贡献者。

### B.3 Debug Expert（调试专家 · 行为/边界视角）

```
You are a debugging specialist focused on edge cases and error conditions in
C/C++ code. Analyze for:
1. Error handling gaps — missing return value checks, unchecked mallocs.
2. Boundary conditions — off-by-one errors, array index issues.
3. Edge cases — empty inputs, max values, null values.
4. Resource management — unclosed files, orphaned allocations.
5. Undefined behavior — uninitialized variables, signed overflow.

Output a structured report:
VULNERABILITY_FOUND: yes/no;
CWE_IDs: [list];
SEVERITY;
EVIDENCE;
CONFIDENCE.
```

### B.4 Adversarial Verifier（对抗式验证者 · 审计视角）

```
You are an adversarial code security reviewer. You receive three expert
vulnerability analysis reports for the same code snippet. Your job is to:
1. CHECK CONSISTENCY — Do the three reports agree on whether vulnerabilities
   exist? Flag contradictions.
2. VERIFY EVIDENCE — Are vulnerability claims supported by actual code
   references? Flag hallucinations.
3. FIND MISSED PATTERNS — Are there obvious vulnerabilities that all experts
   missed?
4. ASSESS CONFIDENCE — Based on agreement level, rate overall confidence.

Output your assessment:
DECISION: ACCEPT/CHALLENGE/REJECT;
FINAL_VULNERABILITY: yes/no;
FINAL_CWE_IDS: [consolidated list];
AGREEMENT_LEVEL: full/partial/none;
REASONING: brief explanation.
```

**Prompt 设计的关键点**：验证者被明确指示聚焦"找不一致"而非"重新分析"——这正是 Theorem 1 中 `p_fn ≈ 0`（不误杀真阳性）成立的 prompt 层保证。

---

## 三、漏洞报告的具体内容

### 3.1 专家报告结构（三个专家统一契约）

| 字段 | 取值 | 含义 |
|---|---|---|
| `VULNERABILITY_FOUND` | yes / no | 是否存在漏洞 |
| `CWE_IDs` | [CWE-NNN, …] | 检测到的 CWE 列表 |
| `SEVERITY` | critical / high / medium / low / none | 严重性 |
| `EVIDENCE` | 具体代码行 + 解释 | 证据 |
| `CONFIDENCE` | high / medium / low | 置信度 |

### 3.2 验证者报告结构

| 字段 | 取值 | 含义 |
|---|---|---|
| `DECISION` | ACCEPT / CHALLENGE / REJECT | 对专家报告的处置 |
| `FINAL_VULNERABILITY` | yes / no | **最终判定（可覆盖专家）** |
| `FINAL_CWE_IDS` | [合并后的 CWE 列表] | 最终 CWE |
| `AGREEMENT_LEVEL` | full / partial / none | 三份报告的一致程度 |
| `REASONING` | 简要说明 | 理由 |

### 3.3 系统级判定规则（Appendix C.1）

1. **CWE 抽取**：对所有智能体输出用正则抽取 CWE 标识符，归一化为 `CWE-NNN`；
2. **漏洞判定**：若验证者给出 `FINAL_VULNERABILITY`，**直接采用**；否则专家多数投票（≥2/3 为 positive 且至少含 1 个 CWE ID）；
3. **CWE 匹配（层次感知）**：
   - 精确匹配：预测 CWE-121，真值 CWE-121 → match
   - 层次匹配：预测 CWE-122，真值 CWE-121 → match（同属父类 CWE-120 Buffer Overflow）
   - 不匹配：预测 CWE-476，真值 CWE-121 → no match

**CWE 等价类表（Table 7）**

| 父类 | 等价 CWE |
|---|---|
| Buffer Overflow | CWE-119, CWE-120, CWE-121, CWE-122, CWE-787 |
| Integer Issues | CWE-190, CWE-191 |

其余 CWE 要求精确数值匹配。

---

## 四、代表性输出示例（Appendix E 原文要点）

### E.1 真阳性示例 —— CWE-78（OS 命令注入）
- **代码特征**：函数用未净化的用户输入拼接 shell 命令，并传给 `system()`；
- **三专家输出**：均正确识别 CWE-78，高置信度，引用"用户输入直接拼接到命令字符串"作为证据；
- **验证者输出**：确认三份报告**完全一致**，ACCEPT；
- **解读**：`system()` 是清晰的语法标记，因此该类 FPR 低（论文此处称 CWE-78 FPR 最低，为 10%）。

### E.2 真阴性示例 —— CWE-457（未初始化变量）
- **代码特征**：已修补函数，所有变量在使用前均正确初始化；
- **三专家输出**：两名专家仍报出潜在问题，第三名专家正确指出变量在所有代码路径上均已初始化；
- **验证者输出**：**CHALLENGE** 专家主张——找不到支撑漏洞的代码证据，最终判为 benign；
- **解读**：这是"对抗式验证者纠正多数派"的典型样本。

### E.3 假阳性示例 —— CWE-190（整数溢出）
- **代码特征**：已修补函数，加入了正确的溢出检查（`if (size > MAX_SIZE) return`）；
- **系统输出**：仍被标记为 vulnerable；
- **失败原因**：专家只针对算术运算本身标记"潜在危险"，验证者未覆盖（override），因为修补前后**代码结构高度相似**；
- **论文结论**：这揭示了 LLM 的根本困难——区分"存在危险模式"与"存在危险模式但已有正确防护"。

### E.4 假阴性分析
- **132 个漏洞样本全部被正确检出，零假阴性**；
- 论文自评：这很可能反映 Juliet Variant 01（baseline）用例的漏洞模式过于清晰，真实复杂代码上预计会出现假阴性。

---

## 五、三专家的分工证据：Shapley 值分析（Appendix F）

三个专家单独都达到 100% recall，因此对**召回**的边际贡献为 0；超可加价值体现在 **CWE 分类准确率**上（三视角并集达到 100% CWE match rate）：

| 专家 | 具体贡献 |
|---|---|
| Security Expert | 从分类法知识提供精确 CWE ID（如区分 CWE-121 与 CWE-122） |
| Code Analyst | 提供结构证据（数据流、缓冲区大小）来验证 CWE 主张 |
| Debug Expert | 识别边界条件，确认漏洞机理 |

纠正机制示例：当某专家误分类（如报 CWE-787 而真值为 CWE-121），其他专家的互补证据通过**并集聚合**纠正分类。

**验证者的 Shapley 值**（最关键结论）：
```
φ_V = v({1,2,3,V}) − v({1,2,3}) = 0.776 − 0.670 = +0.106（F1）
由于 C_V = 0（本地推理），φ_V / C_V → ∞
```
即：本地验证者具有**无穷大的边际回报**，增加它永远是个体理性的。

---

## 六、实验与配置（供复现）

### 6.1 系统配置（Table 8）

| 组件 | 规格 |
|---|---|
| 云端专家模型 | DeepSeek-V3（deepseek-chat），OpenAI 兼容 API |
| 云端 temperature | 0.1 |
| 云端 max tokens | 4,000 |
| 云端价格 | $0.27/MTok input，$1.10/MTok output |
| 本地验证者模型 | Qwen3-8B |
| 运行时 | HuggingFace Transformers，BFloat16 |
| GPU | NVIDIA RTX 3090（24GB VRAM） |
| 验证者 temperature | 0.1；max new tokens 2,048 |
| 验证者成本 | $0.00（本地推理） |
| 实验环境 | Python 3.11，asyncio 并发，Ubuntu 22.04 / Linux 6.18，2× RTX 3090 |

### 6.2 数据集（NIST Juliet Test Suite v1.3）
- 262 个真实函数级样本：**132 vulnerable + 130 benign（修补版本）**，类别均衡
- 14 种 CWE：内存安全（121/122/415/416）、整数（190）、空指针（476）、注入（78/134）、资源管理（401/789/400）、错误处理（252）、数值（369）、未初始化（457）
- 取自 Flow Variant 01（baseline），平均 38.5 行/样本

### 6.3 单样本成本（Table 9）

| 组件 | 平均 token | 平均成本 | 占比 |
|---|---|---|---|
| Code Analyst（DeepSeek） | ~1,074 | $0.00069 | 33.3% |
| Security Expert（DeepSeek） | ~1,074 | $0.00069 | 33.3% |
| Debug Expert（DeepSeek） | ~1,074 | $0.00069 | 33.3% |
| **云端小计** | 3,222 | $0.00208 | 100% |
| Verifier（Qwen3-8B 本地） | 3,459 | $0.00 | 0% |
| **总计** | 6,681 | $0.00208 | 100% |

### 6.4 主结果（Table 1，262 样本）

| 配置 | Prec. | Rec. | F1 | FPR | MCC |
|---|---|---|---|---|---|
| 3+1 并行 + 验证者 | .629 | 1.00 | **.772** | .600 | .501 |
| 3+1 并行 − 验证者 | .526 | 1.00 | .689 | .915 | .211 |
| 3+1 串行 + 验证者 | .644 | 1.00 | .783 | .562 | .531 |
| Single Expert | .555 | 1.00 | .714 | .815 | .320 |
| Cppcheck 2.13 | .504 | 1.00 | .670 | 1.00 | .000 |

**验证者的净效应（Table 3）**：Precision +10.3pp（52.6% → 62.9%，McNemar `p < 10⁻⁶`），FPR −31.5pp（91.5% → 60.0%），F1 +8.3pp；41 个样本被正确改判，**0 个样本由正确改判为错误**（单向精度过滤器）。

### 6.5 逐 CWE 的 FPR（Table 5，3+1 并行+验证者）

| CWE | 类别 | FPR | TN | FP |
|---|---|---|---|---|
| CWE-476 | NULL Deref | 11% | 8 | 1 |
| CWE-252 | Unchecked Return | 20% | 8 | 2 |
| CWE-401 | Memory Leak | 30% | 7 | 3 |
| CWE-457 | Uninit Variable | 30% | 7 | 3 |
| CWE-78 | Cmd Injection | 40% | 6 | 4 |
| CWE-415 | Double Free | 50% | 3 | 3 |
| CWE-122 | Heap Overflow | 60% | 4 | 6 |
| CWE-190 | Integer Overflow | 70% | 3 | 7 |
| CWE-369 | Divide by Zero | 70% | 3 | 7 |
| CWE-121 | Stack Overflow | 80% | 2 | 8 |
| CWE-134 | Format String | 90% | 1 | 9 |
| CWE-416 | Use After Free | 100% | 0 | 7 |
| CWE-789 | Mem Allocation | 100% | 0 | 8 |
| CWE-400 | Resource Exhaust | 100% | 0 | 10 |

**规律**：修补方式是"新增显式检查"（如 CWE-476 加 null guard、CWE-252 加返回值检查）的类别 FPR 低，因为修补版本结构差异明显；语义型漏洞（资源耗尽、UAF）FPR 高，因为修补只是细微控制流变化，修补前后结构相似。

---

## 七、⚠️ 提取时发现的论文内部数值不一致

| 位置 | 说法 | 与 Table 5 冲突 |
|---|---|---|
| E.1（真阳性示例） | "CWE-78 has our lowest FPR (10%)" | Table 5 中 CWE-78 FPR = **40%**，最低为 CWE-476（11%） |
| E.3（假阳性示例） | "CWE-190 has 90% FPR" | Table 5 中 CWE-190 FPR = **70%** |
| E.2（真阴性示例） | "CWE-457 has our second-lowest FPR (20%)" | Table 5 中 CWE-457 = **30%**，20% 对应的是 CWE-252 |

**解读**：Appendix E 的三处数值可能是早期实验版本的残留（或按不同阈值/不同配置统计）。引用该论文数据时**以 Table 5 为准**，正文叙事中的 FPR 数值需谨慎。

---

## 八、与 VulAgent（2025）的 Prompt 设计对照

| 维度 | 本论文（3+1，AAMAS 2026） | VulAgent（2025） |
|---|---|---|
| 视角数量 | 固定 3 专家 + 1 验证者 | 动态路由 10 个专用视角（3 个基线常开） |
| 视角切分依据 | 分析能力维度（结构 / 语义分类法 / 行为边界） | CWE 语义族（内存 / 格式化串 / 权限 / 认证 / 密码 / 并发 / 注入 …） |
| 报告格式 | 半结构化字段（VULNERABILITY_FOUND / CWE_IDs / SEVERITY / EVIDENCE / CONFIDENCE） | 严格 JSON（含 trigger_path / assumptions / Path_validity） |
| 抑制误报机制 | 单一对抗式验证者（一次性 ACCEPT/CHALLENGE/REJECT） | 两阶段链式剪枝（假设条件剪枝 → 路径防护校验） |
| 是否建模触发路径 | 否（无路径/假设概念） | 是（显式构造 trigger_path + assumptions） |
| 上下文使用 | 仅原始代码片段（+ Juliet 的 include/macro） | Joern 抽取 CFG / 数据依赖 / 调用图，假设驱动定向检索 |
| Prompt 是否含 CWE 清单 | 是（Security Expert 内硬编码 14 个 CWE） | 是（但明确声明"示例性、非穷尽"，按语义判断） |
| 成本设计 | 显式成本建模（云端付费 + 本地零成本），$0.002/样本 | 未建模成本，仅报告调用次数与 token 量 |

---

## 附：论文未给出的部分

| 缺口 | 说明 |
|---|---|
| 三个专家的完整 user prompt（仅给出 system prompt） | Appendix B 只列 system prompt，未给用户输入模板（代码片段如何拼接） |
| 验证者的完整输入拼接格式 | 只说明"接收原始代码 + 三份专家报告"，未给具体模板 |
| Appendix E 中四组示例的**原始 LLM 输出文本** | 只给出要点描述，完整输出在 supplementary material（未随正文提供） |
| 各专家的逐样本输出示例 | 未给 |
| Shapley 值的逐角色数值 | 只给验证者的 φ_V = +0.106，三个专家的具体 φ_i 称"见 appendix"但正文未列数值 |
