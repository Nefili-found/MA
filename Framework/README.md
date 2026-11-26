# 多 Agent 代码漏洞扫描系统（框架骨架）

A/B/C 三个扫描 Agent 从三个视角并行扫描同一个 C / C++ 源码文件，各自生成统一 JSON
漏洞报告；D 汇总 Agent 等三份报告齐全后，对结果做 LLM 语义去重、冲突裁决、
工具验证，并写入 SQLite 记忆库，最后输出精简 JSON 报告，供后续修复 Agent 使用。

> 本仓库是**可运行的架构骨架 + 关键接口**。所有需要你补充的地方都以
> `TODO` 显式标注，并集中记录在 [QUESTION.md](QUESTION.md)。
> 未包含完整的漏洞判断逻辑、具体验证工具实现（角色 Prompt 已填写）。

---

## 目录结构

```
project/
  main.py                     # 入口
  graph.py                    # LangGraph 图编排（A/B/C 并行 fan-out -> D join）
  state.py                    # 图状态定义
  agents/
    __init__.py               # 共享机制（LLM 构造 / 报告解析 / 扫描节点，按传入模板工作）
    a.py  b.py  c.py          # 三个扫描 Agent（各自的报告结构在此定义）
  verify_agent/
    __init__.py
    d.py                      # 汇总 / 验证 Agent D（去重 / 裁决 / 验证 / 落库 / 输出；提示词内联）
  memory/
    db.py                     # SQLite 连接与建表
    ledger.py                 # ledger 表读写（原始报告）
    view.py                   # view 表读写（工具调用与推断）
    retrieval.py              # 会话内历史相似漏洞检索
  tools/
    dynamic_check.py          # 内存类 CWE 动态执行验证：编译 harness + ASan/UBSan 崩溃复现/定位/最小化/覆盖引导
    injection_runtime.py      # 命令/SQL 注入运行时探针：canary 回显 + sqlite3 拼接/绕过观测
    injection_check.py        # 注入类静态源码核验（sink 命中 / 输入直达 / 参数化）
    verify_taint.py           # 污点假设核验：触发路径可达性 + 守卫/条件 blocker 三重作用域
    analysis_backends.py      # 符号执行 / 动态污点后端抽象接口（未接真实引擎时返回 unavailable）
    call_context.py           # 单文件调用上下文工具（tree-sitter-cpp：callers / callees / body）
  prompts/
    roles.yaml                # A/B/C 角色 Prompt（已填写；留空时用内置占位）
  config/
    __init__.py               # 配置加载（补充文件，见 QUESTION.md）
    config.example.yaml       # 非敏感配置示例
    .env.example              # 环境变量示例
  observability.py            # log_event / track_time / count_tokens
  output/
    .gitkeep                  # 最终报告输出目录
  examples/
    input/sample.c            # 示例输入（C / C++ 源码）
  requirements.txt
  README.md
  QUESTION.md
```

---

## 运行环境配置

### 1. 基础环境

- **Python 3.11+**
- **Linux / WSL2** 环境（动态编译运行的目标口径；Windows 便携 clang 仅作辅助验证）
- 无需 GPU；无需向量数据库

### 1b. 动态验证工具链（可选，按需安装）

动态验证链路在缺工具链时会自动降级为 `uncertain`，不阻塞主流程；要真正跑出崩溃/注入证据，需具备：

| 用途 | 系统依赖 | 说明 |
| --- | --- | --- |
| 内存崩溃复现（ASan/UBSan） | gcc 或 clang（带 sanitizer 运行库） | 探测顺序：`DYNCHECK_CC` 显式路径 → PATH 中 clang → gcc |
| SQL 注入运行时探针 | `libsqlite3-dev`（SQLite 开发头与 `-lsqlite3`） | Ubuntu/WSL：`sudo apt install libsqlite3-dev` |
| 命令注入探针 | 目标 shell（sh/cmd 均可） | 探针载荷为固定 canary，不接真实外部输入 |

> 运行时探针默认关闭（`INJRUNTIME_ENABLED=0`）；仅在可信隔离沙箱内显式开启。

### 2. 安装依赖

```bash
cd project
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

`requirements.txt` 仅包含 Python 依赖及版本，不含 API Key / 环境变量 / 系统依赖：

| 依赖 | 版本 |
| --- | --- |
| langgraph | >=1.0,<2.0 |
| langchain-core | >=1.0,<2.0 |
| langchain-openai | >=1.0,<2.0 |
| pyyaml | >=6.0 |
| python-dotenv | >=1.0 |
| tree-sitter | >=0.25,<0.26 |
| tree-sitter-cpp | >=0.23.4,<0.24 |

> 版本为生成时的最低可用范围；若你的环境对 LangGraph / LangChain 版本有要求，
> 可在 `requirements.txt` 中改为精确固定版本。

### 3. 复制并填写环境变量

```bash
cp config/.env.example config/.env
# 然后编辑 config/.env
```

需要配置的环境变量（见 `config/.env.example`）：

| 变量 | 说明 |
| --- | --- |
| `LLM_PROVIDER` | LLM 提供商（当前实现面向 OpenAI 兼容接口，可留空） |
| `MODEL_NAME` | 模型名 |
| `OPENAI_API_KEY` | **API Key（TODO：请在此配置）** |
| `OPENAI_BASE_URL` | 兼容 OpenAI 协议的 base_url，可留空 |
| `LLM_TEMPERATURE` | 采样温度，默认 0.0 |
| `MEMORY_DB_PATH` | SQLite 记忆库路径，默认 `memory.db` |
| `INPUT_FILE` | 默认输入文件 |
| `OUTPUT_PATH` | 最终报告输出路径 |
| `MAX_RETRIES` | Agent 输出格式错误时的最大重试次数 |
| `LOG_ENABLED` | 日志开关 |

> **不硬编码密钥**：API Key 只从环境变量 / `config/.env` 读取。

### 4. `config/config.example.yaml` 的作用

非敏感配置示例。复制为 `config/config.yaml` 后生效；若 `config/config.yaml`
不存在，程序会**回退读取** `config.example.yaml`。包含：模型名、LLM 提供商、
SQLite 路径、输入文件路径、输出路径、重试次数、日志开关、角色 Prompt 路径。

配置优先级（从低到高）：**代码默认值 < YAML < 环境变量 / `.env`**。

### 5. SQLite 数据库路径

默认 `memory.db`（项目根目录下），可由 `config.yaml` 的 `memory.db_path`
或环境变量 `MEMORY_DB_PATH` 修改。首次运行自动建表。

---

## 运行

```bash
python main.py --file examples/input/sample.c
```

- **输入**：单个 C / C++ 源码文件（仅读取该文件，不读取其他文件）
- **输出**：`output/final_report.json`

未配置 `OPENAI_API_KEY` 时，系统进入**降级模式**：A/B/C 返回空报告骨架，
流水线仍能完整跑通（用于验证编排、落库与输出链路）。

---

## 图结构

```
        ┌─> A ─┐
START ──┼─> B ─┼─> D ─> END
        └─> C ─┘
```

- A/B/C 为**并行 fan-out**；D 为 **join 节点**，仅在 A/B/C 全部完成后执行。
- D 会校验三份报告是否齐全，缺失则**停止并报错**。
- 如需改为顺序调度，把 A/B/C 之间的边改成链式即可（见 `graph.py` 注释）。

---

## 记忆库（SQLite）

两张表：

- `ledger`：原始报告与生成 Agent。字段：`id, session_id, agent, report_json, code_hash, created_at`
- `"view"`：工具调用与 D 的假设验证推断。字段：`id, session_id, hypothesis_json, tool_call_json, tool_result_json, inference_json, status, confidence, reason, created_at`

历史相似漏洞检索仅在**同一会话内**进行，使用 LLM 语义相似度，**不引入向量库**，
**不保留跨会话长期记忆**。

---

## 最终输出

`output/final_report.json`（纯 JSON，不输出 Markdown / SARIF / 可读摘要）：

```json
{
  "file": "",
  "findings": [
    {
      "location": { "file": "", "line_start": 0, "line_end": 0, "function": "" },
      "taint_chain": [],
      "verification_status": "verified|rejected|uncertain",
      "verdict": "accept|reject|challenge|uncertain",
      "confidence": 0.0,
      "fix_suggestion": "",
      "evidence": {
        "path_status": "reachable|unreachable|unverifiable",
        "path": [
          { "hop": 0, "from": "", "to": "", "file": "", "line": 0,
            "code": "", "reachable": true, "note": "" }
        ],
        "conditions": [
          { "id": "cond-1", "kind": "null_check|bounds_check|sanitizer|other",
            "text": "", "holds": true, "blocker": null, "note": "" }
        ],
        "blockers": [
          { "file": "", "line": 0, "kind": "", "pattern": "", "symbol": "", "code": "" }
        ],
        "used_tools": ["get_callees", "get_callers", "get_function_body"]
      }
    }
  ]
}
```

`verification_status` 是框架统一语义（verified / rejected / uncertain），`verdict` 是工具与 LLM
双信号合并后的对抗式判定；`evidence` 记录「为什么这样判」——逐跳可达性、每条假设条件的核验结果、
以及反驳条件的守卫（blocker）。被推翻（overturn）的 finding 默认不写进本文件，但完整记录仍在
`memory.db` 的 `"view"` 表中。

---

## 动态验证链路（D 阶段）

### 证据口径（不变量）

- **只产出有罪证据，永不判 reject**：探针/复现成功 → accept；未复现、编译失败、无工具链、超时、预算耗尽一律记 `uncertain`；**未覆盖 ≠ 安全**。
- 合并阈值 τ = 0.8；仅命中启发式 blocker 时置信度封顶 0.55，单凭启发式不能单独推翻 finding。

### 置信度档位

| 证据类型 | 工具 | 置信度 | 证据字段 |
| --- | --- | --- | --- |
| 内存崩溃复现 | `dynamic_check` | 0.92 | `evidence.dynamic` |
| 注入运行时探针复现 | `injection_runtime` | 0.90 | `evidence.injection_runtime` |
| 注入静态源码核验 | `injection_check` | 0.88 | `evidence.injection` |
| 路径/条件核验通过 | `verify_taint` | 0.90 | `evidence.conditions / blockers` |

### 已闭环能力（双口径实测：Windows 便携 clang / WSL2 Ubuntu）

- **内存类动态执行**：同文件依赖闭包补齐 → 角色感知变异种子 → 分种子独立进程定位崩溃种子 → ASan/UBSan 检出越界/越界写 → 崩溃输入二分最小化 → 覆盖反馈邻域变异第二轮。
- **命令注入探针（CWE-78）**：首个 `char*` 传 canary 载荷，观测命令回显。
- **SQL 注入探针（CWE-89）**：build 型观测载荷是否进入拼接结果；exec 型读取被测函数回传的命中行数（`ROWS`），布尔绕过可见行从 1 升到 2 才复现；参数化安全样例不误报。

### 成熟度分级

| 层级 | 模块 | 状态 |
| --- | --- | --- |
| 已实测闭环 | `dynamic_check` 崩溃链路、命令探针、SQL build/exec 探针 | 双口径编译运行跑通，离线断言覆盖 |
| 静态启发式核验 | `verify_taint` 路径可达 + blocker 三重作用域 | 离线断言覆盖，不执行二进制 |
| 接口预留 | `analysis_backends` 符号执行 / 动态污点 | **未接真实引擎**，工厂返回 `unavailable`，不产出结论 |
| 已知边界 | 见下节「已知限制」 | 不阻塞主链路交付 |

### 相关开关

| 变量 / 配置 | 作用 |
| --- | --- |
| `VERIFY_DYNAMIC_ENABLED` | 应用层动态验证总开关（优先级高于进程级变量） |
| `VERIFY_INJECTION_ENABLED` | 应用层注入核验总开关 |
| `DYNCHECK_ENABLED` / `DYNCHECK_MAX_ITER` / `DYNCHECK_TIMEOUT` / `DYNCHECK_TOTAL_TIMEOUT` | 动态进程级兜底：开关、变异轮数、单进程/总预算超时 |
| `DYNCHECK_COVERAGE` | 1=开启覆盖反馈与邻域变异第二轮 |
| `DYNCHECK_CC` | 显式指定 C 编译器全路径；缺省按 PATH 探测 clang→gcc |
| `INJRUNTIME_ENABLED` | 注入运行时探针开关，默认关闭；须在隔离沙箱显式开启 |

---

## 需要你后续补充的内容

见 [QUESTION.md](QUESTION.md)。主要包括：

- 接入真实符号执行 / 动态污点引擎（`analysis_backends` 已预留抽象接口与注册机制）
- API Key / 环境变量填写（`config/.env`）
- 报告内容字段的生成逻辑

---

## 数据集准备（本地管理，不入库）

原始数据集与抽取产物均被 `.gitignore` 忽略，本地管理、不随代码上传；仓库内仅
`examples/input/sample.c` 占位样例（5 条良性片段，不可独立编译）。

### 检测端：PrimeVul 测试用例

- 原始三 split `.jsonl`（test / valid / train）放到 `test_data/primevul_raw/`。
- 生成索引：`python test_data/extract_cases.py --limit N`（目录 / 产物 / 状态路径见脚本
  `--help`）；split 优先级 test → valid → train；仅保留完整函数、行数 20–150，超长不截断。
- 产物：`test_data/test_cases.jsonl`（字段 `id / func / label / cwe / line_count / source`），
  脚本内置 validate 校验 JSON 可解析、字段齐全、行数区间一致。

### 修复端：APPATCH held-out 评测集

- 两评测集解压到 `other fix framework/datasets/`：
  - `extractfix_dataset/`：平铺 `*_vul.c` / `*_nonvul.c`（24 对）；
  - `zeroday_repair/`：每目录 `vul.c` / `nonvul.c`（97 对）。
- 先自检：`python test_data/build_repair_eval_cases.py --check`；通过后去掉 `--check` 写盘。
- 产物：`test_data/repair_eval_cases.jsonl`（只存文件指针、sha256 与行号记账，不复制源码），
  供 `repair/intake.py` 与 `tools/run_detection_cases.py` 消费。

---

## 已知限制

- **符号执行 / 动态污点未接真实引擎**：`analysis_backends` 仅提供抽象接口与注册机制，未注册后端时结果为 `unavailable`，不产出有罪/无罪结论。
- **拦截器覆盖差异**：`strcmp` 比较串无 NUL 终止时的读越界发生在 libc 内部，ASan 不插桩该路径，当前工具链可能漏报；`strlen`、`memcpy` 源端越界可被检出。未覆盖到的路径不判定为安全。
- **检测端数据集规模**：已提取 200 条 PrimeVul 样例（良性 68 / 漏洞 132，覆盖 CWE-476/369/787/125/190/416/415 等）；修复端评测集 121 条已就绪。
- **SQL exec 判据边界**：行数绕过判定依赖被测函数回传「被测查询命中行数」；若被测返回全表 `count(*)`，探针无法鉴别是否被绕过。void / 自建连接等无法回传行数的形态标记 `ROWS=NA`，按 uncertain 降级、不误报。
- **知识库检索降级**：未安装 faiss-cpu / sentence-transformers / torch / numpy 时，embed 退化为哈希 ngram、索引退化为 flat-python，与动态验证链路无关。
- **既有测试失败归因**：`test_kb_*` 缺训练数据集文件、`test_pipeline_assumptions` 缺可选编排依赖 langgraph；均与动态验证链路无关，不影响其离线断言。

## 测试入口

动态 / 注入 / 信号 / 工具循环相关离线断言：

```bash
# 脚本式裸断言（直接运行，末尾打印 SMOKE / OK）
python tests/test_dynamic_check.py
python tests/test_p2_framework.py

# pytest 全量收集（KB 数据集相关用例在缺数据时会跳过 / 降级，属已知限制）
python -m pytest tests/ -q
```

| 测试文件 | 覆盖范围 |
| --- | --- |
| `test_dynamic_check.py` | 动态链路：种子生成、依赖闭包、崩溃定位、最小化、覆盖排序、UBSan 收窄 |
| `test_p2_framework.py` | 覆盖率排序、邻域变异、最小化、命令/SQL 探针分流与复现解析、占位后端 |
| `test_signal_plugins.py` | 信号合并与探针/崩溃提权接入 |
| `test_verify_signals.py` | 裁决过滤与证据落报告 |
| `test_tool_loop_runtime.py` | 工具绑定、开关过滤与探针分发 |
| `test_injection_check.py` | 注入静态核验分流与降级 |
| `test_slice_location.py` | 源码位置切片 |

---

## 验收标准

编排链路在无 LLM 凭证时以降级模式完整跑通（A/B/C 空报告骨架 → D 去重裁决 → 落库 → 输出）；
动态验证链路在具备 gcc/clang（SQL 探针另需 sqlite3 开发库）的 Linux/WSL 口径下，可对内存类与注入类 finding 复现并产出带置信度的有罪证据。未覆盖到的路径不判定为安全。
