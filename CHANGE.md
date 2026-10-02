# CHANGE.md

> 对 `Framework/` 的**改动记录**，**按日期倒序**排列（最新在上）。
> 本文件位于 `experiment framework/`（上一级，位于 `Framework/` 之外）。
> 说明：本机无 git 仓库，日期取文件系统时间（本地）。

---

## 2026-10-02

**当日概览**

| 项 | 内容 |
| --- | --- |
| 代码逻辑 | 未改动（仅阅读核对） |
| 变更文件 | `Framework/QUESTION.md`（补丁 + 全文重写） |
| 新增/归档 | `CHANGE.md`（本文件，归档至上一级 `experiment framework/`） |
| 核对范围 | `Framework/` 全部源文件与配置 |

**当日任务链**

1. 阅读 `Framework/` 代码结构 → 更新 `QUESTION.md` → 记录改动到本文件。
2. 按代码里的新结构**全文重写** `QUESTION.md`。
3. 将 `CHANGE.md` 从 `Framework/` 移至上一级 `experiment framework/`。

---

### R1 · `QUESTION.md` 补丁（3 处）

| # | 章节 | 改动前 | 改动后 | 依据 |
| --- | --- | --- | --- | --- |
| 1 | 第 1 节 A/B/C 角色 Prompt | 「均为空字符串」+ 三条 `# TODO` 待补充 | 改为「**已填写**」，列出实际内容、fallback 机制、`【输出格式】` 取舍 | `prompts/roles.yaml` 已含 A/B/C 英文 Prompt |
| 2 | 第 4 节 报告内容字段 | 仅「内容留白」 | 追加「结构对齐提示」：Prompt 的 `【输出格式】` 与 `FINDING_TEMPLATE` 字段不一致 | 对比 `our prompt.txt` 与 `agents/a.py` 的 `FINDING_TEMPLATE` |
| 3 | 第 8 节 目录结构补充 | 仅说明 `config/__init__.py` 为补充包 | 追加说明：D 独立为 `verify_agent/` 包，而非 `agents/d.py` | 目录树 + `graph.py` 的 `from verify_agent import d` |

#### 2.1 第 1 节 —— A/B/C 角色 Prompt

**改动前**

```
- **状态**：`A.role_prompt` / `B.role_prompt` / `C.role_prompt` 均为空字符串。
- **行为**：为空时使用内置 fallback 占位 Prompt（`agents/__init__.py`
  中的 `_FALLBACK_ROLE_PROMPT`），保证项目可完整跑通。
- **待补充**：
  - A 的角色 Prompt：# TODO: 请填写 A 的角色 Prompt
  - B 的角色 Prompt：# TODO: 请填写 B 的角色 Prompt
  - C 的角色 Prompt：# TODO: 请填写 C 的角色 Prompt
```

**改动后**

```
- **状态**：**已填写**。A/B/C 均已写入完整英文角色 Prompt
  （【Role】/【Input】/【Tasks】/【Constraints】四段），来源为
  `prompt and report/our prompt.txt`（A / B / C 按序写入）。
- **行为**：fallback 机制仍保留（role_prompt 为空时用内置占位 Prompt）。
- **已决定的取舍**：`our prompt.txt` 中每角色附带的 `【输出格式】` 段
  （agent_type / vulnerability_report / assume）未写入 `roles.yaml`，
  输出结构改由框架运行时追加（FINDING_TEMPLATE schema）。
```

**原因**：`prompts/roles.yaml` 的 A/B/C 三个 `role_prompt` 已不再是空串，原描述与实际代码不符。

#### 2.2 第 4 节 —— 报告内容字段

在原有「待补充」条目后**追加**：

```
- **结构对齐提示**：角色 Prompt 来源 `our prompt.txt` 的 `【输出格式】` 骨架
  （agent_type / vulnerability_report / assume）与代码 `FINDING_TEMPLATE`
  （findings / cwe / severity / confidence / ...）字段并不一致，
  需明确以哪套为准（详见第 1 节）。
```

**原因**：README / QUESTION 把 A/B/C 报告结构描述为 `agent/file/findings[]`，
而角色 Prompt 的原始来源文件用的是另一套字段，二者需显式对齐。

#### 2.3 第 8 节 —— 目录结构补充

在原有 `config/__init__.py` 说明后**追加**：

```
- D 未放在 `agents/d.py`，而是独立为 `verify_agent/` 包
  （verify_agent/__init__.py + verify_agent/d.py，D 的提示词内联其中）；
  graph.py 通过 `from verify_agent import d` 引用它。
```

**原因**：原始代码生成提示词要求的是 `agents/d.py`；实际骨架拆成了独立包 `verify_agent/`。

---

### R2 · `QUESTION.md` 全文重写

- **请求**：按代码里的新结构重写整份 `QUESTION.md`。
- **做法**：以 `Framework/` 实际目录树为骨架重新组织，改为**按模块 / 文件**逐项列出留白与疑问；
  新增「0. 目录结构总览」（带状态标记的目录树）。章节顺序：
  `编排层(main/graph/state) → 扫描层(agents + prompts) → 汇总层(verify_agent/d) →
  记忆库(memory) → 验证工具(tools) → 配置层(config) → 可观测性 → 错误处理 → 其他`。
- **diff 要点（旧 → 新）**：
  - 旧：按“主题”编号 1~9（角色 Prompt / 验证工具 / API Key / 报告字段 / D 去重 / 记忆库 / 错误处理 / 目录补充 / 其他）。
  - 新：按“代码位置”编号 0~9，每节对应到具体文件与符号，并全面对齐实际代码
    （含 `verify_agent/` 包、`config/__init__.py`、`FINDING_TEMPLATE` 字段、
    `_FALLBACK_ROLE_PROMPT`、`retrieval.py` 的 `top_k=3` 等）。
  - 新增状态标记约定（已完成 / 待补充 / 待确认）与目录树总览。
- **未改代码**；原要点全部保留，仅重组并补齐定位。

---

### R3 · `CHANGE.md` 归档到上一级

- `CHANGE.md` 从 `Framework/` 移到上一级 `experiment framework/`。
- 同步更新 `Framework/QUESTION.md` 第 0 节目录树：移除 `CHANGE.md` 条目，加注其新位置。

---

### R4 · 建立 Git 版本记录

- 在仓库根 `experiment framework/` 执行 `git init -b main`。
- 新增 `.gitignore`：排除 `.venv/`、`.idea/`、`.env`、`memory.db`、`output/*.json`、`Framework - 副本/` 等；放行 `.env.example` 与 `output/.gitkeep`。
- 新增 `WORKFLOW.md`：提交信息规范 / 里程碑 tag / 与 `CHANGE.md` 日期联动。
- 首个提交：`bfa055e` `chore: 初始化仓库（Framework 骨架 + 文档）`（42 文件）。
- 本地身份：`user.name=fkh37`（`--local`），沿用全局 `user.email`；`core.autocrlf=true`、`core.quotepath=false`。

---

### 附 A · 代码与文档核对差异（依据）

| 核对点 | 实际代码 | 原文档描述 | 结论 |
| --- | --- | --- | --- |
| A/B/C 角色 Prompt | 已填写完整英文 Prompt | 「均为空字符串」 | **不一致 → 已更新** |
| fallback 占位 Prompt | 仍保留（`agents/__init__.py`） | 保留 | 一致 |
| 报告内容字段 | `FINDING_TEMPLATE` 内容字段留白 | 「内容留白」 | 一致 |
| 输出结构来源 | 框架运行时追加 `FINDING_TEMPLATE` schema | 未说明与 `【输出格式】` 的差异 | **补充说明** |
| 具体验证工具 | `verify_taint` 仍返回 `uncertain` | 「默认返回 uncertain，留白」 | 一致 |
| API Key 配置 | `config/.env` 的 `OPENAI_API_KEY` 仍为空 | 「待补充」 | 一致 |
| 记忆库 | SQLite，`ledger` + `"view"` 两表 | 同 | 一致 |
| D 的位置 | `verify_agent/d.py`（独立包） | 第 4 节已按此写，第 8 节未提 | **第 8 节补充** |

### 附 B · 仍成立的留白项（未改动）

- `tools/verify_taint.py`：默认占位，`status="uncertain"`、`reason="具体验证工具未配置"`。
- `config/.env`：`OPENAI_API_KEY` / `MODEL_NAME` 等仍为 TODO 待填。
- 各 Agent 报告的**内容字段**（cwe / severity / confidence / taint_* / evidence / suggestion 等）取值规范未定。
- `verify_agent/d.py` 的 `FINAL_REPORT_TEMPLATE` 仍带 `# TODO: 输出报告结构待修改`。
- D 的去重 / 裁决阈值、记忆库清理策略、错误重试策略等疑问项未变。

### 附 C · 其它观察（建议，未改动代码）

- `prompts/roles.yaml` 顶部注释仍写「role_prompt 默认为空字符串」，与已填写状态不符，建议同步。
- `agents/__init__.py` 的 `_FALLBACK_ROLE_PROMPT` 含疑似笔误「此处promote未加载成功」（应为 prompt）。
- `Framework - 副本/` 为旧布局（`agents/d.py` + 含 `【输出格式】` 的 roles.yaml），与 `Framework/` 已分叉，勿混用。

### 附 D · 涉及并核对的代码文件（未改动）

- `main.py`、`graph.py`、`state.py`、`observability.py`、`requirements.txt`
- `agents/__init__.py`、`agents/a.py`、`agents/b.py`、`agents/c.py`
- `verify_agent/__init__.py`、`verify_agent/d.py`
- `memory/db.py`、`memory/ledger.py`、`memory/view.py`、`memory/retrieval.py`
- `tools/verify_taint.py`
- `config/__init__.py`、`config/config.example.yaml`、`config/.env.example`
- `prompts/roles.yaml`、`examples/input/sample.c`、`output/.gitkeep`

---

<!-- 追加模板：
## YYYY-MM-DD

**当日概览**
| 项 | 内容 |
| --- | --- |
| 代码逻辑 |  |
| 变更文件 |  |

### R1 · <标题>
...
-->
