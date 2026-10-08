# Baseline 论文：ReasonVul（多视角推理漏洞检测框架）

> **论文**：*Three Heads Are Better Than One: A Multi-perspective Reasoning Framework for Enhanced Vulnerability Detection*
> **作者**：Xin Peng, Bo Lin, Jing Wang, Xiaoling Li, Jun Ma, Jie Yu, Xiaoguang Mao, Shangwen Wang（通讯）
> **来源**：Proc. ACM Softw. Eng. (FSE), Vol. 3, No. FSE, Article FSE190, July 2026
> **DOI**：https://doi.org/10.1145/3808197
> **本地文件**：`suitable else framework/00/3808197.md`
> **代码/数据**：https://zenodo.org/records/17106263

本文档记录该论文的**数据集**与**达到的实验效果**，并与其对比我们当前的实验框架骨架
（多 Agent A/B/C + D 汇总，见 `README.md`、`QUESTION.md`、`prompts/roles.yaml`）。

---

## 1. 论文核心思想（一句话）

ReasonVul 认为现有 LLM 漏洞检测受限于**单一推理范式**，于是设计
**演绎（Deductive）/ 归纳（Inductive）/ 溯因（Abductive）** 三个专家 Agent：
先**独立推理**产出结论，结论不一致时进入**多轮结构化辩论**（rebuttal / revision），
最终收敛为协同判定。（`3808197.md` §4.1）

两阶段流水线：

- **Multi-perspective Reasoning**：三 Agent 并行分析同一段源码，产出带理由的中间结论
- **Collaborative Debate**：冲突时多轮辩论，直至共识；超过最大轮数 `T_max` 未达成共识则**默认为“无漏洞”**（保守策略）

---

## 2. 数据集

| 数据集 | 层级 | 规模 | CWE 覆盖 | 用途 | 来源 |
| --- | --- | --- | --- | --- | --- |
| **PrimeVul** | 函数级 | 测试集 **435** 对 vulnerable/fixed | **140** 类 CWE，来自大规模开源项目 | **主评测集**（RQ1、RQ3） | `3808197.md` §5.2 |
| **JITVUL** | 仓库级 | **1758** 对样本（879 漏洞 + 879 良性） | **91** 类 CWE，来自 **879** 个 CVE | **泛化性评测**（RQ2） | `3808197.md` §5.2、§6.2 |
| **PairVul** | 函数级 | 主要用于动机实验 / 选型 | 主要 **5** 类 CWE，来自 Linux kernel | 动机研究、为各 Agent 选最优 LLM | `3808197.md` §3、§7.3 |

**数据集细节：**

- **PrimeVul**：高质量函数级 benchmark，结合自动标注 + 人工校验，严格去重（§5.2）。
- **JITVUL**：仓库级，通过 caller–callee 关系提供**跨过程上下文**。使用 **CFlow** 静态分析提取
  调用者/被调用者；存在多个时取 **top-5 最相似的 caller + top-5 最相似的 callee**，
  序列化为 `[Caller Context] + [Target Function] + [Callee Context]`（§6.2）。
- **PairVul**：仅用于选型，与 PrimeVul 的 token 级 **Jensen–Shannon 散度 = 0.43**，
  用于论证“选型不泄漏 PrimeVul 测试集”（§7.3）。

**基线方法（共 13 个）：**

- 学习型（8）：CausalVul、DeepDFA、VulChecker、FVD-DPM、Coca、VulSim、LineVul、MoEVD
- LLM 型（5）：SAVul、Vul-RAG、VulnSage、GPTLens、VulTrial

所有基线在**同一实验环境**下用**官方公开实现**重跑（§5.2.1）。

---

## 3. 评测指标

主指标为 **PairAcc（成对准确率）**：一对 `(vulnerable, fixed)` 只有当漏洞版预测为 `1`
**且**修复版预测为 `0` 时才算正确（§5.3）。其严格性同时惩罚高假阳/假阴。

$$\text{PairAcc} = \frac{|\{(v,f)\in P \mid \hat{y}_v = 1 \wedge \hat{y}_f = 0\}|}{|P|}$$

同时报告：**Accuracy、Precision、Recall、F1-score、FPR（假阳率）**。

---

## 4. 达到的实验效果

### 4.1 RQ1：PrimeVul 主结果（Table 2）

| 类型 | 方法 | PairAcc↑ | Accuracy↑ | Precision↑ | Recall↑ | F1↑ | FPR↓ |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 学习型 | CausalVul | 5.74 | 49.43 | 49.44 | 51.03 | 50.23 | 52.18 |
| 学习型 | DeepDFA | 4.36 | 49.54 | 49.51 | 46.21 | 47.80 | 47.12 |
| 学习型 | VulChecker | 3.67 | 48.28 | 47.81 | 37.70 | 42.16 | 41.15 |
| 学习型 | FVD-DPM | 5.52 | 52.30 | 53.28 | 44.83 | 48.69 | 39.31 |
| 学习型 | Coca | 4.14 | 50.92 | 50.91 | 51.95 | 51.42 | 50.11 |
| 学习型 | VulSim | 8.51 | 49.20 | 49.28 | 54.71 | 51.85 | 56.32 |
| 学习型 | LineVul | 4.36 | 52.07 | 52.31 | 46.90 | 49.45 | 42.76 |
| 学习型 | MoEVD | 8.97 | 53.67 | 54.12 | 48.27 | 51.03 | 40.92 |
| LLM | SAVul | 11.03 | 53.91 | 55.28 | 40.92 | 47.28 | 37.93 |
| LLM | Vul-RAG | 10.57 | 51.95 | 52.00 | 51.03 | 51.51 | 47.13 |
| LLM | VulnSage | 8.28 | 48.97 | 48.31 | 29.66 | 36.75 | 31.72 |
| LLM | GPTLens | 13.56 | 51.73 | 51.20 | 78.16 | 61.87 | 74.71 |
| LLM | VulTrial | 22.07 | 55.17 | 54.95 | 57.47 | 56.18 | 47.13 |
| **LLM** | **ReasonVul** | **40.00** | **69.77** | **66.48** | **79.77** | **72.52** | **40.23** |

**关键结论（§6.1）：**

- **PairAcc = 40.00%**，F1 = **72.52%**；较最强基线 **VulTrial 提升 81.24%（PairAcc）**、29.09%（F1）。
- 学习型 PairAcc 仅 3.67%–8.97%；LLM 型（单范式）8.28%–10.57%；GPTLens/VulTrial 靠多角色/对抗升至 13.56%/22.07%。
- GPTLens 召回高（78.16%）但 **FPR 高达 74.71%**（过度检测）；ReasonVul 在保持高召回的同时把 FPR 压到 **40.23%**。

### 4.2 Top-10 高频 CWE 准确率（Table 3）

| CWE | 类别 | 数量 | GPTLens | VulTrial | **ReasonVul** |
| --- | --- | ---: | ---: | ---: | ---: |
| CWE-787 | Out-of-bounds Write | 144 | 53.47 | 54.86 | **66.67** |
| CWE-125 | Out-of-bounds Read | 94 | 53.19 | 54.26 | **75.53** |
| CWE-703 | Improper Check/Handling | 94 | 56.38 | 51.06 | **72.04** |
| CWE-476 | NULL Pointer Deref | 78 | 48.72 | 53.85 | **75.64** |
| CWE-416 | Use After Free | 58 | 41.38 | 53.45 | **68.97** |
| CWE-200 | Sensitive Info Exposure | 32 | 53.12 | 62.50 | 59.38 |
| CWE-20 | Improper Input Validation | 28 | 53.57 | 50.00 | **78.57** |
| CWE-369 | Divide By Zero | 28 | 57.14 | 46.43 | **67.86** |
| CWE-119 | Improper Restriction of Ops | 28 | 53.57 | 57.14 | **71.43** |
| CWE-617 | Reachable Assertion | 24 | 62.50 | 54.17 | **70.83** |
| — | **平均** | — | 53.30 | 53.77 | **70.69** |

推理协同在**按缺陷类型分组**后依然稳定领先（平均 70.69% vs 53.30%/53.77%）。

### 4.3 RQ2：JITVUL 泛化结果（Table 4）

| 类型 | 方法 | PairAcc↑ | Accuracy↑ | Precision↑ | Recall↑ | F1↑ | FPR↓ |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 学习型 | CausalVul | 3.07 | 51.54 | 51.50 | 52.90 | 52.19 | 49.83 |
| 学习型 | DeepDFA | 3.98 | 51.99 | 52.25 | 46.19 | 49.03 | 42.21 |
| 学习型 | VulChecker | 3.19 | 51.59 | 51.83 | 45.05 | 48.20 | 41.87 |
| 学习型 | FVD-DPM | 4.32 | 52.16 | 52.11 | 53.36 | 52.73 | 49.03 |
| 学习型 | Coca | 2.05 | 50.85 | 50.49 | 87.71 | 64.09 | 86.01 |
| 学习型 | VulSim | 6.94 | 53.47 | 53.17 | 58.25 | 55.59 | 51.31 |
| 学习型 | LineVul | 5.12 | 51.65 | 51.75 | 48.69 | 50.18 | 45.39 |
| 学习型 | MoEVD | 5.80 | 52.28 | 51.85 | 63.82 | 57.22 | 59.27 |
| LLM | SAVul | 8.99 | 49.77 | 49.84 | 68.83 | 57.81 | 69.28 |
| LLM | Vul-RAG | 12.97 | 54.32 | 53.51 | 65.87 | 59.05 | 57.22 |
| LLM | VulnSage | 9.22 | 50.17 | 50.27 | 32.08 | 39.17 | 31.74 |
| LLM | GPTLens | 10.69 | 52.90 | 51.68 | 89.42 | 65.50 | 82.13 |
| LLM | VulTrial | 20.93 | 56.83 | 56.93 | 56.09 | 56.50 | 42.43 |
| **LLM** | **ReasonVul** | **28.67** | **63.54** | **61.85** | **70.65** | **65.96** | 43.57 |

**关键结论（§6.2）：**

- 仓库级难度上升导致整体下滑，但 ReasonVul 仍**全指标第一**：PairAcc **28.67%**、F1 **65.96%**。
- 较学习型最强 VulSim：PairAcc **+21.73%**、F1 **+10.37%**；较 LLM 型最强 VulTrial：PairAcc **+7.74%**、F1 **+9.46%**。
- 对 GPTLens 的 F1 优势仅 0.46%，但 **FPR 降低 38.56%**（82.13% → 43.57%），说明其优势在跨过程推理而非激进预测。

### 4.4 RQ3：消融实验（PrimeVul）

**单个推理 Agent 的影响（Table 5）：**

| 配置 | PairAcc | Accuracy | Precision | Recall | F1 |
| --- | ---: | ---: | ---: | ---: | ---: |
| w/o Deductive Agent | 35.00 | 64.45 | 68.09 | 65.31 | 66.67 |
| w/o Inductive Agent | 31.95 | 65.17 | 64.10 | 68.97 | 66.45 |
| w/o Abductive Agent | 24.60 | 57.47 | 56.70 | 63.22 | 59.78 |
| Deductive Agent Only | 25.28 | 58.16 | 57.17 | 65.06 | 60.86 |
| Inductive Agent Only | 20.92 | 55.06 | 67.36 | 67.36 | 59.97 |
| Abductive Agent Only | 27.81 | 62.18 | 62.21 | 62.07 | 62.14 |
| **Full** | **40.00** | **69.77** | **66.48** | **79.77** | **72.52** |

- 三 Agent 全开最优；**去掉任一 Agent 都下降**。
- 去掉溯因（Abductive）掉得最多：PairAcc −15.40%、F1 −12.74%，说明其捕捉**复杂上下文相关漏洞**的能力独特。
- 单 Agent 配置普遍远弱于全模型：PairAcc 下降 12.91%–19.08%。

**辩论轮数的影响（Fig. 4，PrimeVul 验证集）：**

| T_max（轮数） | PairAcc | Accuracy | F1 |
| --- | ---: | ---: | ---: |
| 0（仅多数投票） | 21.67 | 54.69 | 57.23 |
| 1 | 26.46 | 59.38 | 61.54 |
| **2（最优）** | **30.42** | **62.50** | **63.41** |
| >2 | 开始下降（上下文过长） | — | — |

- 辩论显著优于多数投票；**`T_max = 2` 最优**。
- 未达共识时**默认“无漏洞”**的保守策略，比多数投票在测试集上 **PairAcc 绝对提升 4.14%**。

### 4.5 协同效应分析（§7.2）

- 辩论前：演绎 283、溯因 293、归纳 270 个漏洞，**交集仅 133**（互补性强、盲区明显）。
- 辩论后：ReasonVul 共识别 **347** 个漏洞，其中 **214** 个来自辩论解决的初始分歧。
- 相比单 Agent 分别多检出 **+64（vs 演绎）、+54（vs 溯因）、+77（vs 归纳）**。
- 局限：演绎/归纳 Agent 单独发现而 ReasonVul 最终漏判的各有 25、12 个（辩论可能过度偏向某条推理线）。
- 摘要口径：分析 **542** 个冲突案例，**389** 个被正确解决（约 **72%**），而多数投票仅约 **9%**。

---

## 5. 实验配置（§5.4）

| 项 | 设置 |
| --- | --- |
| 开源模型 | Llama-4-Scout-17B-16E-Instruct、Phi-4、Devstral-Small-2505（本地部署，4× RTX 4090） |
| 商用模型 | gpt-4o-2024-05-13、qwen-max、gemini-2.5-flash、deepseek-v3-0324 |
| 生成配置 | temperature = 0；top_p = 1.0；top_k = 50；repetition_penalty = 1.0 |
| 辩论轮数 | `T_max = 2` |
| 判定缺省 | 未达共识 → 默认“无漏洞”（保守） |

---

## 6. 与我们的实验框架对比

我们的框架（`README.md`）：A/B/C 三个扫描 Agent 从**三个视角**并行扫描同一 C 源码，
各自产出统一 JSON 报告；D 汇总 Agent 待三份齐全后做 **LLM 语义去重 → 冲突裁决 → 工具验证 → 落库**，
输出精简 JSON 供修复 Agent 使用。

| 维度 | ReasonVul（论文） | 我们的框架（本仓库） |
| --- | --- | --- |
| **Agent 划分依据** | 三个**推理范式**：演绎 / 归纳 / 溯因 | 三个**分析视角**：A 静态分析 / B 行为控制流 / C 内存布局（`prompts/roles.yaml`） |
| **并行分析** | 三 Agent 独立分析同一源码 | A/B/C 并行 fan-out 同一源码（`graph.py`） |
| **冲突解决** | **多轮结构化辩论**（rebuttal/revision，`T_max=2`，未共识默认无漏洞） | D **语义去重 + 裁决**（LLM 优先，回退启发式），无迭代辩论（`verify_agent/d.py`） |
| **外部知识** | 漏洞知识库 + 安全规则库（演绎/归纳依赖） | SQLite `ledger`/`view` **会话内**记忆，无向量库、不跨会话（`memory/`） |
| **结果验证** | 无独立工具验证环节 | `verify_taint` **工具验证**（默认 `uncertain`，占位，`tools/verify_taint.py`） |
| **输入粒度** | 函数级（PrimeVul）/ 仓库级含 caller-callee（JITVUL） | 单个 C 源码文件（仅读该文件，`main.py`） |
| **输出** | 单一漏洞判定 | 精简 JSON `findings`（含 taint_chain / verification_status / fix_suggestion），供修复 Agent |
| **评测指标** | **PairAcc** 为主 + Acc/Prec/Recall/F1/FPR，13 个基线 | 骨架**未定义指标**；验收仅要求“能跑通”（`README.md`） |
| **实现状态** | 完整实现 + 公开数据（Zenodo） | 可运行骨架，关键逻辑留白（`QUESTION.md`） |

**可借鉴点（把论文当 baseline）：**

1. **指标对标**：论文用 **PairAcc**（漏洞/修复成对正确）为核心。我们若要量化，需构造
   vulnerable/fixed 成对样本并采用同口径指标，才能与上表直接比较。
2. **辩论 vs 裁决**：论文证明**多轮辩论**（非多数投票）能显著提升；我们目前只有“去重+裁决”，
   可考虑在 D 引入有限轮辩论，并沿用“未共识默认无漏洞”的保守策略。
3. **视角 ≡ 范式**：我们的 A/B/C 与论文的演绎/归纳/溯因高度呼应（A 静态规则≈演绎，
   B 行为假设≈溯因，C 内存布局≈模式/归纳），但其消融表明**溯因（行为/上下文）视角贡献最大**，
   可作为我们 B 视角权重的参考。
4. **跨过程上下文**：论文 JITVUL 通过 caller/callee 上下文提升仓库级表现，我们当前仅读单文件，
   若目标含跨文件漏洞需补齐调用上下文。

---

## 7. 引用来源

- 数据集与规模：`3808197.md` §5.2（PrimeVul 435 对 / JITVUL 1758 对）、§3、§7.3（PairVul）
- 指标定义与 PairAcc 公式：`3808197.md` §5.3
- Table 2（PrimeVul 主结果）、Table 3（Top-10 CWE）、Table 4（JITVUL）、Table 5（消融）、Fig. 4（辩论轮数）：`3808197.md` §6
- 协同效应数字：`3808197.md` §7.2、摘要
- 实验配置：`3808197.md` §5.4
- 我们框架：`README.md`、`QUESTION.md`、`prompts/roles.yaml`
