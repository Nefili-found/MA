# 多 Agent 代码漏洞扫描系统（框架骨架）

A/B/C 三个扫描 Agent 从三个视角并行扫描同一个 C 源码文件，各自生成统一 JSON
漏洞报告；D 汇总 Agent 等三份报告齐全后，对结果做 LLM 语义去重、冲突裁决、
工具验证，并写入 SQLite 记忆库，最后输出精简 JSON 报告，供后续修复 Agent 使用。

> 本仓库是**可运行的架构骨架 + 关键接口**。所有需要你补充的地方都以
> `TODO` 显式标注，并集中记录在 [QUESTION.md](QUESTION.md)。
> 未包含完整的漏洞判断逻辑、具体角色 Prompt、具体验证工具实现。

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
    verify_taint.py           # 污点验证工具接口（默认 uncertain，留白）
  prompts/
    roles.yaml                # A/B/C 角色 Prompt（默认空，使用内置占位）
  config/
    __init__.py               # 配置加载（补充文件，见 QUESTION.md）
    config.example.yaml       # 非敏感配置示例
    .env.example              # 环境变量示例
  observability.py            # log_event / track_time / count_tokens
  output/
    .gitkeep                  # 最终报告输出目录
  examples/
    input/sample.c            # 占位示例输入
  requirements.txt
  README.md
  QUESTION.md
```

---

## 运行环境配置

### 1. 基础环境

- **Python 3.11+**
- **Linux** 环境（开发/运行目标环境）
- 无需 GPU；无需向量数据库

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

- **输入**：单个 C 源码文件（仅读取该文件，不读取其他文件）
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
      "confidence": 0.0,
      "fix_suggestion": ""
    }
  ]
}
```

---

## 需要你后续补充的内容

见 [QUESTION.md](QUESTION.md)。主要包括：

- A/B/C 角色 Prompt（`prompts/roles.yaml`）
- 具体污点验证工具实现（`tools/verify_taint.py`）
- API Key / 环境变量填写（`config/.env`）
- 报告内容字段的生成逻辑

---

## 验收标准

提供一组示例数据集后，项目能够完整跑通即可（不校验漏洞判断是否正确）。
