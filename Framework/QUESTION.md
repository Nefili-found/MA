# QUESTION.md

集中记录 `Framework/` 中的**留白、疑问、需要后续补充的内容**。
本文件**按当前代码结构（目录 → 文件）逐项组织**，与源码一一对应，可据此逐文件补齐。

标注约定：

- **已完成**：可运行，通常只需替换内容或按需扩展。
- **待补充**：留白 / 占位实现，需要你补齐。
- **待确认**：需要你拍板的疑问。

---

## 0. 目录结构总览

```
Framework/
├── main.py                     # 入口：读单个 C 文件 → 跑图 → 落盘
├── graph.py                    # LangGraph 编排：A/B/C 并行 fan-out → D join
├── state.py                    # 图状态 ScanState（含并发写 reducer）
├── agents/                     # A/B/C 扫描 Agent
│   ├── __init__.py             #   共享机制：LLM 构造 / Prompt 加载 / JSON 解析 / 扫描节点
│   ├── a.py                    #   A（Static Analyze）
│   ├── b.py                    #   B（Behavior Analyze）
│   └── c.py                    #   C（Memory Layout）
├── verify_agent/               # D 汇总 / 验证 Agent（独立包）
│   ├── __init__.py
│   └── d.py                    #   去重 / 裁决 / 工具验证 / 落库 / 输出
├── memory/                     # SQLite 记忆库
│   ├── __init__.py
│   ├── db.py                   #   连接 + 建表（ledger / "view"）
│   ├── ledger.py               #   原始报告读写
│   ├── view.py                 #   工具调用 + D 推断读写
│   └── retrieval.py            #   会话内相似漏洞检索
├── tools/                      # 验证工具
│   ├── __init__.py
│   └── verify_taint.py         #   污点验证接口（占位）
├── prompts/
│   └── roles.yaml              #   A/B/C 角色 Prompt（已填写）
├── config/                     # 配置
│   ├── __init__.py             #   Settings + load_settings()（补充包）
│   ├── config.example.yaml     #   非敏感配置示例
│   └── .env.example            #   环境变量示例
├── observability.py            #   log_event / track_time / count_tokens
├── output/
│   └── .gitkeep                #   最终报告输出目录
├── examples/input/sample.c     #    占位示例输入
├── requirements.txt
├── README.md
└── QUESTION.md                 # 本文件
```

> 改动记录（`CHANGE.md`）位于上一级 `experiment framework/`。

---

## 1. 编排层：`main.py` / `graph.py` / `state.py`

- **`graph.py`**：`START → {A, B, C} → D → END`。A/B/C 并行 fan-out，D 为 join。
- **`state.py`**：`ScanState`；`reports` 用 `merge_reports` reducer 合并，
  `errors` 用 `operator.add` 追加（避免并行写同一 channel 报错）。
- **`main.py`**：仅读 `--file` 指定的单个 C 文件；`session_id = uuid4().hex`；
  以 `config={"recursion_limit": 50}` 调图，结束后打印输出路径 / 记忆库 / session_id。
- **状态**：**已完成**，可运行。
- **待确认**：
  - 是否需要**顺序调度**（A→B→C 链式）？当前为并行 fan-out，`graph.py` 内已留注释说明改法。
  - 是否需要**并发度 / 单节点超时**控制？当前只设了 `recursion_limit=50`。
  - `recursion_limit=50` 是否合适，是否需要暴露到配置？

---

## 2. 扫描层：`agents/` 与 `prompts/roles.yaml`

### 2.1 `prompts/roles.yaml` —— A/B/C 角色 Prompt

- **状态**：**已填写**。`A.role_prompt` / `B.role_prompt` / `C.role_prompt`
  均为完整的英文角色 Prompt（`【Role】/【Input】/【Tasks】/【Constraints】` 四段），
  来源为 `prompt and report/our prompt.txt`（A / B / C 按序写入）。
- **fallback 机制仍保留**：某 `role_prompt` 为空串时，使用
  `agents/__init__.py` 的 `_FALLBACK_ROLE_PROMPT` 占位，保证可跑通。
- **已决定的取舍**：`our prompt.txt` 中每个角色原本还附有一段
  `【输出格式】` JSON 骨架（`agent_type` / `vulnerability_report` / `assume`）；
  当前 `roles.yaml` **只写入 Role/Input/Tasks/Constraints，未写入 `【输出格式】` 段**，
  输出结构改由框架在运行时追加（`agents/*.py` 的 `FINDING_TEMPLATE` schema）。
  若要以 Prompt 内嵌的 `【输出格式】` 为准，需把该段补回 `roles.yaml`。
- **待确认**：
  - A/B/C 是否需要在 Prompt 中强制“只输出 JSON”？（当前由框架追加 schema 约束。）
  - 三者的视角差异如何界定（分类维度 / 覆盖范围）？

### 2.2 `agents/a.py` / `agents/b.py` / `agents/c.py` —— 报告模板

- **位置**：各文件内的 `REPORT_TEMPLATE` 与 `FINDING_TEMPLATE`。
- **状态**：全部**内容字段留白**：
  `id / title / location{file,line_start,line_end,function} / cwe / severity /
  confidence / taint_source / taint_sink / propagation_path / evidence / suggestion`。
  三个文件当前结构相同，仅 `AGENT_NAME` 与视角不同（A Static / B Behavior / C Memory Layout）。
- **待补充**：由角色 Prompt 生成具体内容；框架只负责结构与规范化。
- **结构对齐提示**：`our prompt.txt` 的 `【输出格式】` 骨架
  （`agent_type` / `vulnerability_report` / `assume`）与 `FINDING_TEMPLATE`
  字段并不一致，需明确以哪套为准（见 2.1）。
- **待确认**：
  - `severity` / `confidence` 的取值规范（枚举？区间？）。
  - `id` 的生成规则（是否需要跨 Agent 可对齐以辅助去重）。

### 2.3 `agents/__init__.py` —— 共享机制

- `get_llm()`：**仅支持 OpenAI 兼容接口**（`langchain_openai.ChatOpenAI`）；
  无有效 Key 时返回 `None` 触发降级。文件内 `# TODO`：其他 provider（Anthropic / 本地模型）分支待补。
- `_FALLBACK_ROLE_PROMPT`（第 50 行附近）：占位 Prompt，文案含疑似笔误“此处promote未加载成功”。
- `parse_json_object()` / `normalize_report()`：解析与规范化模型输出（容忍 ```json 包裹）。
- `run_scan_agent()`：LLM 未配置时返回**空报告骨架**；配置时走
  `_scan_with_llm()`，格式错误自动追加纠正消息并重试 `settings.max_retries` 次。
- **待确认**：`MAX_RETRIES` 耗尽后是否允许降级为空报告继续（见第 8 节）。

---

## 3. 汇总 / 验证层：`verify_agent/d.py`

职责：校验 A/B/C 报告齐全 → LLM 语义去重 → 冲突裁决 → 工具验证 → 落库 → 输出精简报告。

### 3.1 输出报告结构

- **位置**：`FINAL_REPORT_TEMPLATE`（文件内已标 `# TODO: 输出报告结构待修改`）。
- **结构**：`{file, findings:[{location{file,line_start,line_end,function},
  taint_chain[], verification_status, confidence, fix_suggestion}]}`。
- **待确认**：`taint_chain` 语义（完整传播路径 vs. 关键节点）；`fix_suggestion` 来源。

### 3.2 去重 / 裁决（`_deduplicate` / `_adjudicate`）

- **去重**：优先 LLM 语义分组（`_llm_group`，提示词 `PROMPT_DEDUPE` 内联）；
  失败回退启发式 `_heuristic_group`（cwe + function + 行号//5 + 归一化标题分桶）。
- **裁决**：优先 LLM（`_llm_adjudicate`，`PROMPT_ADJUDICATE` 内联）；
  失败回退启发式 `_heuristic_adjudicate`（取各视角最高 `confidence`）。
- **待确认**：
  - 去重的相似度阈值是否需要固定（当前 LLM 自由分组 / 启发式按桶）。
  - 冲突裁决时“保守 / 激进”策略的取舍。

### 3.3 工具验证（`_verify_findings` / `_invoke_verify` / `_tool_loop`）

- 有 LLM 且工具包装可用 → `llm.bind_tools([verify_taint_tool])` 走工具循环；
  否则直接调用 `verify_taint()`。
- 最终 `confidence`：工具给出则用工具值，否则回退 D 的 `final_confidence`。
- **待确认**：工具调用轮数上限（当前 `max(1, max_retries) + 2`）是否合适。

### 3.4 落库 / 输出

- 原始报告写入 `ledger`；工具调用与 D 推断写入 `"view"`；
  最终报告 `json.dump` 到 `output/final_report.json`（纯 JSON）。

---

## 4. 记忆库：`memory/`

- **`db.py`**：建两张表 `ledger` 与 `"view"`（`VIEW` 为 SQLite 关键字，故加引号），
  含 `idx_ledger_session` / `idx_view_session` 索引；`row_factory=Row`、`PRAGMA foreign_keys=ON`。
- **`ledger.py`**：`write_report()`（记 agent + report_json + `code_hash`=sha256）、`read_reports()`。
- **`view.py`**：`write_verification()`（记 hypothesis / tool_call / tool_result / inference /
  status / confidence / reason）、`read_views()`。
- **`retrieval.py`**：`find_similar_findings()`，**仅同会话内**、`top_k=3`；
  有 LLM 走语义（`_llm_similar`），否则 `difflib` 近似（`_heuristic_similar`）；
  **无向量库、不跨会话持久**。
- **待确认**：
  - 是否需要清理策略（同一 `session_id` 的记录何时删除）。
  - `view.status` 是否需要扩展枚举（当前 verified / rejected / uncertain）。

---

## 5. 验证工具：`tools/verify_taint.py`

- **接口**：`verify_taint(hypothesis, context) -> dict`，
  返回 `{status, confidence, reason, tool_name, raw_output}`。
- **状态**：**占位**。默认返回 `status="uncertain"`、`reason="具体验证工具未配置"`。
- **待补充**：接入真实实现（静态分析器 / 符号执行 / 数据流引擎 / 自定义规则等），
  保持返回结构不变；D 已通过 `verify_taint_tool`（LangChain 包装，缺失时为 `None`）调用它。
- **待确认**：
  - 验证工具的输入需求：完整源码还是仅相关片段？
  - 工具输出语义如何映射为 verified / rejected / uncertain？

---

## 6. 配置层：`config/`

- **`config/.env`（从 `.env.example` 复制）待补充**：
  - `OPENAI_API_KEY=`（`# TODO: 请在此处配置 API Key 或环境变量`）
  - `MODEL_NAME=`（模型名）
  - `LLM_PROVIDER=`（非 OpenAI 兼容接口需扩展 `agents/__init__.py::get_llm`）
  - `OPENAI_BASE_URL=` / `LLM_TEMPERATURE=` / `MEMORY_DB_PATH=` / `INPUT_FILE=` /
    `OUTPUT_PATH=` / `MAX_RETRIES=` / `LOG_ENABLED=`
- **`config/config.example.yaml`**：llm{provider,model,base_url,temperature}、
  memory{db_path}、input{file}、output{path}、retries{max}、logging{enabled}、prompts{roles_path}。
- **`config/__init__.py`（补充包，非原目录结构）**：提供 `Settings` 与 `load_settings()`；
  优先级 **代码默认值 < YAML < 环境变量 / `.env`**。**如不需要可合并回 `main.py`。**
- **密钥规则**：只从环境变量 / `.env` 读取，代码中不硬编码。

---

## 7. 可观测性：`observability.py`

- `log_event()`（写 stderr，避免污染最终 JSON）、`track_time()`（上下文计时）、
  `count_tokens()`（≈4 字符/token 粗估）。
- **待补充**：如需 OpenTelemetry / LangSmith / 结构化日志，在此扩展；
  需要记录哪些事件与指标由你定义。

---

## 8. 错误处理策略（跨模块）

- Agent 输出格式错误：自动修复并重试（次数 = 配置 `retries.max`）。
- 工具失败 / 无结果 / 非法状态：**停止并报错**（抛 `RuntimeError`）。
- 无法验证：标记 `uncertain` 并记录原因。
- **待确认**：重试耗尽后，是否允许“降级为空报告”继续，而非中断整条流程？

---

## 9. 其他未明确项 / 环境与版本

- LangGraph 版本：骨架按 **1.x** 的 `StateGraph` API 编写；若用 0.x，请确认
  `START / END` 等导入兼容。
- `requirements.txt` 的 LangGraph / LangChain 采用 `>=x,<y` 范围而非精确固定；
  如需可改为精确版本。
- 是否需要并发度 / 超时控制（当前未引入复杂的超时与重试策略）。
- 示例数据：当前仅 `examples/input/sample.c` 占位，待替换为你的真实 C 源码与预期结果。
