# Framework 合并优化方案

建议以本地 Framework 为集成基线，选择性移植 GitHub 的动态执行与注入验证能力；优先统一工具执行、证据归属和预算，再优化公共代码。保留 A/B/C 三视角并行、D 独立裁决与现有修复流程。

## 0. 实施状态（2026-11-27 盘点）

一句话：**移植层已完成，机制层缺归属，Git 流程基本未动，且全部改动尚未提交。**

`git status` 实查：37 个已跟踪文件被修改（+1108/−273）＋ 22 个未跟踪新文件；`HEAD` 仍为 `64f7c5c`，**一行都没提交**。下表中✅=已落地并有证据、◐=部分、❌=未做。

| 分组 | 计分 | 说明 |
| --- | --- | --- |
| §2 移植与接线（9 项） | 9/9 ✅ | 动态/注入/探针/符号接口/非动态增量/工具信号/远端测试/文档/一等冲突手合 |
| §3 三个优先问题 | 2 完成 + 1 部分 | §3.1 ✅、§3.3 ◐、**§3.2 归属 ❌** |
| §4 公共收敛（7 行） | 5/7 ◐ | LLM 调用统一、记忆/知识库关联未动 |
| §5 数据契约（4 项） | 3.5/4 ◐ | SQLite 侧未见改动 |
| §1 Git 流程（4 步） | 1/4 ◐ | 仅 `.gitignore` 补 2 行（`baseline/`、`测评效果/`） |
| §6 分批 | 二 ✅、三 ◐、四 ◐、一 ❌、五 ❌ | 见第 6 节各批标题 |
| **合计（24 个可执行项）** | **17 完成 / 3 部分 / 4 未做** | ≈ 70% |

### 0.1 已落地（附证据）

| 项 | 证据 |
| --- | --- |
| 动态执行 | `tools/dynamic_check.py`（51 KB）已接入 `run_process`/`bounded_timeout`（5 处调用点），与远端 hash 不同即已适配 |
| 注入静态核验 | `tools/injection_check.py` 与 `origin/main` **逐字节一致**（blob `2cb6753`） |
| 注入运行探针 | `tools/injection_runtime.py` + 独立开关 `verify_injection_runtime_enabled`（与 `verify_injection_enabled` 分开可控，符合方案要求） |
| 符号执行接口 | `tools/analysis_backends.py` 与 `origin/main` **逐字节一致**（占位返回 `unavailable`） |
| 非动态增量 | `main.py:142 scan_one` + `--batch-list`/`--batch-out`；`tools/call_context.py:70 _get_language` 惰性加载 + `_parse_tree` 缓存；`tools/verify_taint.py:1028 verify_taint_batch`；`kbcore/store.py:84` faiss/embedder 降级 warning |
| 工具信号聚合 | `verify_agent/signals.py:27 tool_signal(..., dynamic_enabled, injection_enabled, injection_runtime_enabled, execution)`，三路均为“只补强不削弱” |
| §3.1 执行结果复用 | `verify_agent/execution.py`：digest 键（模块文件 hash + 模块常量 + 编译器）、**源码一致性守卫**（`context.code != 源码` 则不执行并告警）、不向模型注入任何内容；`verify_agent/verify_loop.py:165` 每份源码一个 `ExecutionSession`，D 自己的 `verify_taint` 与 `tool_signal` 共享 |
| §3.1 共享预算 | `tools/execution_budget.py`：`DEADLINE` ContextVar + `bounded_timeout`（子阶段只能用剩余）+ `run_process` 给 docker 加 `--cpus/--memory/--pids-limit/--cap-drop` 并在超时清理容器 |
| §3.1 绑定断言 | `tests/test_merge_integration.py`：`test_binding_exact_tools`（四种开关组合逐一断言）、`test_disabled_plugins_never_start_processes`（monkeypatch `subprocess.run/Popen` 直接 fail） |
| §3.3 去重（大部分） | `verify_agent/dedupe.py:126 path_safe_groups()`（同位置/源/汇/路径/条件才合并，“不完整”独立成桶）、`:64 _candidate_paths`（原始 finding_id/agent/path/assumptions）、`group_indices` 单条早退；开关 `verify_preserve_candidate_paths` 默认 `False` |
| §4 模板收敛 | 新增 `agents/templates.py`，`agents/a.py`/`b.py`/`c.py` 各减约 30 行 |
| §4 上下文构造 | `agents/context_manager.py` 改为 `copy(settings)` + `ContextManager.from_settings(effective)` |
| §4 配置 | `config/__init__.py:75-79` 新增 5 个开关（动态/注入/探针/超时/路径保留），**默认全 False** = 第二批“显式 opt-in”到位 |
| §5 证据块 | `verify_agent/schema.py:27 EVIDENCE_OPTIONAL_KEYS` 扩到 6 键（`dataflow`/`sufficiency`/`dynamic`/`injection`/`injection_runtime`/`candidate_paths`）；`repair_projection.py:160` 透传三路；`verify_loop.py:178` 挂 `candidate_paths`；`final-report/2` 版本号未动 |

### 0.2 实跑验证（项目 venv，非系统 python）

```bash
.venv\Scripts\python.exe -m pytest tests/test_merge_integration.py -q      # 21 passed
.venv\Scripts\python.exe -m pytest tests/test_signal_plugins.py \
    tests/test_tool_loop_runtime.py tests/test_p2_framework.py \
    tests/test_dynamic_check.py tests/test_injection_check.py -q           # 5 passed
.venv\Scripts\python.exe tests/test_signal_plugins.py                      # ALL_TESTS_PASS（5 条）
.venv\Scripts\python.exe tests/test_tool_loop_runtime.py                   # TOOL_LOOP_RUNTIME OK（5 条）
.venv\Scripts\python.exe tests/test_p2_framework.py                        # P2_FRAMEWORK OK（10 条）
```

同一组用例用**系统 python** 跑会 2 failed（`ModuleNotFoundError: langgraph` / `tree_sitter_cpp`）——属环境差异，不是代码缺陷；这也正好兑现了第 7 节“脚本入口要单独跑、不能拿 pytest 收集当断言已执行”：pytest 每文件只收到 1 个用例，脚本入口实际跑了 5/5/10 条断言。

### 0.3 剩余项（按阻塞程度）

1. **§3.2 崩溃归属机制：唯一零进度的必做项**。`tools/dynamic_check.py` 的改动只有 5 处 `run_process` 接入；`_is_crash(rc, blob, sanitizer_on)` 仍是 `sanitizer_on and rc != 0`，全文 grep `归属|attribut|crash_line|frame` 只命中 UBSan 类别字符串 —— **没有任何把崩溃位置映射回目标函数/sink/行号的代码**。
2. §3.3 第 1 步前半：`llm_group` 的 compact 输入仍是 `index/title/cwe/function/taint_source/taint_sink`，**未加位置与路径**；只有新的确定性 `path_safe_groups()` 用了 `line_start`。
3. §3.3 第 2 步：AND/OR 语义未做（“记录 + 分开验证”已到），`verify_agent/report_builder.py` 未改。
4. §4 两行未动：LLM 调用统一（配置/计量/超时语义）、`memory/` 与 `kbcore/` 职责关联。
5. §1 Git 流程 4 步中 3 步未做（无快照、无临时分支、无提交）；§6 第五批评估未跑；SQLite 侧（新增列/索引/迁移验证）未见改动。

### 0.4 立即动作（止血优先于补功能）

当前 1108 行改动与 22 个新文件全部裸露在工作树。先按第 1 节建 `codex/framework-merge`，再分四组提交：①工具移植（`tools/dynamic_check|injection_*|analysis_backends|execution_budget` + `docker/Dockerfile.dyncheck` + 远端 5 个测试）；②执行复用与预算（`verify_agent/execution.py` + `signals/tool_loop/verify_loop` 签名回填 + `test_merge_integration.py`）；③去重与证据块（`dedupe.py`/`schema.py`/`repair_projection.py`）；④收敛与文档（`agents/templates.py`/`context_manager.py`/`main.py`/`call_context.py`/`verify_taint.py`/`store.py`/README/QUESTION/config）。修复端 review 一组单独一个提交，不与合并混在一起。

## 1. 依据与范围

本方案将“合并”解释为：把链接仓库的有效增量整合进当前工作区，并消除整合后的重复机制。若仅做远端内部重构，第 3、4 节仍适用，第 2 节的本地能力保护作为兼容约束。

- 远端：`Nefili-found/MA`，`main`，本次读取提交 `d6f5cb57d5fe3a58f7625f7ad4f6a72cdea57f76`。
- 本地：HEAD `64f7c5c663c429223d5b848c89acfdc63f050948`，另有两批未提交改动：①修复端 review（`repair/review.py` 等）②本次合并移植（37 个已跟踪文件 +1108/−273、22 个新文件，明细见第 0 节）；两者都属于待保护的集成输入，且必须在同一工作树内分开提交。
- 远端依据：`graph.py`、扫描模板与上下文构造、D 编排/去重/双信号/工具循环、动态与注入运行模块、修复入口/契约、相关测试、README、符号执行设计。
- 本地依据：核心目录、配置与调用点、`PROJECT_MEMORY.md`、`QUESTION.md`、`docs/EVAL.md` 及修复端当前状态。实验成绩仅作为既有记录，不作为本次验证结果。

本方案原为设计交付；截至 2026-11-27，代码侧已按第 0 节推进（移植层已完成，归属机制未做），但 Git 流程（快照 / 临时分支 / 合并提交）仍未执行，也未启动模型或评测任务。第 1 节的 Git 流程与第 3、6 节的剩余项仍然有效。

修订核对：本地 `HEAD...origin/main` 为 **24 / 22** 个独有提交，已双向分叉。后续集成按以下 Git 流程执行，本次不实际运行：

1. 先保存已跟踪与未跟踪改动的可恢复快照，隔离当前修复端工作；快照范围**排除**仓库根下三个未跟踪副本目录（`Framework - 副本/`、`Framework-context-optimized/`、`keep（实验剔除文档）/`）与 `backup-pre-rewrite.bundle`，避免 `git add -A` 把整目录副本扫入提交。在独立 worktree 建立 `codex/framework-merge` 临时集成分支。
2. 从固定本地 HEAD 开始，在临时分支执行 `git merge --no-commit --no-ff <固定远端提交>`，逐项处理冲突和移植取舍，再按阶段检查；当前未提交修复改动单独恢复与回归，不能遗失。
3. `.gitignore` 只补“防新增”规则，本批不清理任何已跟踪文件。已确认 `test_data/eval_runs/`（880 件）及其外的 19 件样本/清单属于**设计上随仓提供的脱敏复现件**（依据 `docs/EVAL.md:98`、`tools/analysis/README.md:43`，以及 `tools/analysis/_full_metrics.py:54` 的 `--reports-root test_data/eval_runs` 用法），**保留入库**；`git ls-files` 核对 `runs/`、`p1_stage1/`、`memory.db` 无已跟踪文件，`output/` 仅有 `.gitkeep`，没有已跟踪运行产物。本批不执行取消跟踪操作。真正的运行产物继续由既有 `.gitignore` 规则挡住，只补缺口并逐条核对；不删除历史产物、不重写历史。
4. 评审通过后以正常合并提交接回目标分支；不 force push，不把整个远端目录覆盖到本地。

产物统计口径已对齐：`git ls-files test_data/eval_runs` = **880**（仅 eval_runs），`git ls-files test_data` = 903，`git diff --name-only origin/main HEAD -- test_data/` = **899（全部为新增 A）**，即 899 = 880（eval_runs）+ 19（eval_runs 之外的新增样本/清单，包含 `test_data/jitvul/` 子目录，不是 19 个顶层文件）；903 中另有 4 件在 `origin/main` 已存在。审查口径的 230,879 行即为这 899 件整体的合计，两项统计不再矛盾，无需再按另一种范围重算。

## 2. 合并取舍

| 范围 | 已确认差异 | 合并决策 |
| --- | --- | --- |
| 图编排 | 远端固定 A/B/C；本地已有视角子集与实验状态字段 | 保留本地编排、`arm`、`required_agents` 及对应测试；动态验证接入 D 内部 |
| D 模块 | 两边都已拆为去重、裁决、验证、工具循环和报告等模块 | 沿现有职责集成，避免重新汇成大文件 |
| 动态执行 | 远端有 `tools/dynamic_check.py`、容器镜像及动态测试 | 移植实现与直接依赖，先关闭运行验证接通链路，再在 Linux/WSL2 环境验收 |
| 注入验证 | 远端有 `injection_check.py`、`injection_runtime.py` | 静态核验与运行探针分别接入、分别记证据，保留启用条件 |
| 非动态增量 | `c690665`：`scan_one` 与 `--batch-list` / `--batch-out`；`3dac9c3`：tree-sitter 惰性加载与批量 `verify_taint`；`8b5ca5e`：faiss/embedder 失败降级 warning | 分别评估移植；批量入口保留本地实验参数，惰性加载/批量核验手合，warning 保留真实降级状态和日志 |
| 一等冲突文件（工具层） | `tools/call_context.py`（本地 +194/−20）、`tools/verify_taint.py`（本地 +566/−67）被双方实质修改，属于双向重写 | 先列函数级差异与调用方；保留本地守卫绑定、数据流/充分性核验，逐块接入远端增量，禁止整文件选 ours/theirs |
| 一等冲突文件（D 层） | `verify_agent/signals.py`（+42/−62）、`tool_loop.py`（+190/−69）、`verify_loop.py`（+141/−8）：本地静态 `tool_signal()` 为 2 参（远端 4 参），`available_tools()` 为 0 参（远端 2 参）；本地 `dispatch_tool(settings=...)` 读取强制同源开关，但没有 `dyn_on/inj_on` 插件参数和动态/注入开关透传 | 三处签名与调用点必须同步恢复插件接线，并为动态/注入能力显式定义配置和默认关闭策略；不能只搬工具模块。绑定数量由测试钉住（见第 6 节第三批）。少绑定一路不会报错，属静默回归，禁止靠人工目检 |
| 文档 | `README.md` 双向大改（本地 +31/−111）；`requirements.txt` 仅本地新增 `pytest>=8.0`，tree-sitter 钉版本两边一致 | 手合 README 并保留远端“数据集准备路径 / 依赖表实测约束”段落；`requirements.txt` 取并集，无冲突 |
| 远端独有测试 | `test_signal_plugins.py`、`test_tool_loop_runtime.py`、`test_p2_framework.py` | 与动态/注入代码一同移植，适配本地接口并执行脚本入口；不只复制工具代码 |
| 工具信号 | 远端 `signals.py` 已聚合静态、动态、注入证据 | 移植新增信号来源，保留本地已有数据流、充分性与同源核验能力；逐条对照判定规则 |
| 修复端 | 远端 CLI 的主路径止于检索；本地已有生成、验证、审查闭环 | 保留本地修复端，新增证据按契约适配；禁止用远端目录覆盖 |
| 报告 | 本地已有 `final-report/2`、双信号与可诊断字段 | 保留现有键和语义，动态证据作为可选块增量加入 |
| 数据与评测 | 本地有固定判决回放、配对评分和实验口径 | 保留原实验基线；新验证能力独立设实验臂 |
| 符号执行 | 远端仅有接口预留，设计明确未接入真实引擎 | 移植 `tools/analysis_backends.py` 接口与占位实现，不安装 angr/KLEE；默认返回 `unavailable`，不接入有罪/无罪判决 |

历史目录 `ma_upload/` 来自 `5e5ae19`，已由 `6318909` 清理；最终集成不恢复该目录。非动态增量不与动态插件捆绑启用，按独立改动验收。

合并前先固定远端提交与本地工作树快照，再比较双方共同祖先及逐文件差异。不能仅根据提交新旧判断覆盖方向，也不能把全部未提交内容直接提交为一个功能变更。

## 3. 优先解决的三个问题

### 3.1 执行结果复用必做，强制同源仅保留实验入口

当前两边共有的 `verify_loop.py` 都先执行 `tool_signal()`，再进入 `invoke_verify()`。移入动态/注入插件后，确定性信号与模型工具循环可能重复编译或运行相同请求。这个成本问题与改变模型所见证据、强制替换工具参数是两件事。

**第三批必做：仅复用执行结果，不改变判定语义。**

1. 在现有执行/分发处复用同会话、同 finding 的完全相同请求，不强制把不同请求改成相同请求。
2. 复用键覆盖工具实际收到的完整 hypothesis/context、源码哈希、工具及版本、有效配置；动态工具还包含种子、harness 与工具链标识。未知或不完整的输入不得命中缓存。
3. 每次调用均保留输入摘要、结果标识和命中记录；确需追加种子时记录为新执行，计入同一 finding 预算。缓存不额外向模型注入确定性信号，不替换模型原有工具输入。
4. 超时、缺依赖和执行失败分别留痕，不长期缓存为分析结论。单文件输入边界始终由框架限制，这不依赖开启强制同源实验。

**已实测无收益的判定机制：不进入默认方案。** 本地已实现 `verify_show_tool_signal`、`verify_force_canonical_tool_args`，默认均为 `False`；复用 `deterministic_channel_block()`、`canonical_tool_inputs()` 和 `_verify_taint_args_digest()`，不另建同源机制。

按本轮审查提供的 2026-11-15 L0-B 双跑记录：错位率 53.1%→2.3%，findings 减少 25%，同批 24 条的 `pred=accept` 由 50%→33%，A/B 精确 McNemar `p=0.289`。机制归因为 accept 通道由 LLM 独占，强制同源后 D 更倾向不报。结论为“不进主配置，不再在通道一致性上花钱”。这些细项来自审查，原始运行产物本次未重算。

因此仅保留已有 opt-in 实验臂；本次不为其安排新付费实验。除非新证据提出与 L0-B 明确不同、可独立验证的假设，否则不重新启动。成本复用验收只考察重复执行减少和语义等价，不据错位率下降宣称检测收益。

### 3.2 动态异常必须归属于当前漏洞

已确认远端缺少显式崩溃归属机制：`_is_crash()` 末尾为 `return sanitizer_on and rc != 0`；harness 将被测函数、同文件被调闭包 `dep_srcs` 和初始化代码放入同一编译单元，没有把异常位置映射回当前 finding 的函数/sink/行号。直接调用目标函数只建立隐式关联，闭包或 harness 自身同样可能崩溃。

因此第三批需要**新增归属机制**，不是只补验收测试。非零退出、harness 错误、无效参数引发的异常，不能自动证明当前 finding。崩溃在被调函数内并非一律无效，但必须证明与当前目标调用路径及漏洞假设相关，否则仅记录观察，不给当前 finding 提权。

动态正证据至少需要记录：

- 当前源码与 harness 哈希、编译器/运行库、种子、命令及执行结果。
- Sanitizer 类型或可核验的注入效果，以及与当前目标函数、sink、漏洞类型的对应关系。
- 原始源码与 harness 的位置映射；无法归属时保留观察结果，判为证据不足。
- 输入约束是否成立；仅由桩函数、构造器错误或不合法测试调用引发的异常不得给目标漏洞提权。

未崩溃、未命中、编译失败、超时、不可用都不能推出安全。动态结果只补充正证据；最终与 LLM 冲突时继续遵守统一裁决表，不能由插件直接覆盖最终结论。

### 3.3 去重不能改变漏洞成立条件

当前两边共有的 `dedupe.py` fallback 使用 CWE、函数、`line_start // 5` 和标题分桶；语义分组的输入没有行号；合并保留首条 finding 为主体、第一条非空传播链，并把 assumptions 取并集。不同触发路径可能被拼成不一致的假设。这是共有问题，不是远端移植引入的回归。

优化分两步：

1. 先补充分组输入与测试：加入校正后位置、sink、源和路径；完全一致候选先确定性去重，只对仍有歧义的小组请求模型。单条候选不请求分组。
2. 同一根因下保留带原始 finding ID 的路径与条件组合。单条路径内的必要条件为 AND；已确认互为替代的路径之间为 OR。无法确认关系时分开验证，验证后仅在报告展示层聚合。

不得只按 CWE、同函数或距离近就判为同一漏洞；不同 sink 默认分开，除非有共同根因证据。多 Agent 一致仅表示多方贡献，不等于独立事实证明，也不自动提高置信度。

第 2 步涉及判定语义，必须独立于基础设施合并提交和评估。

## 4. 公共机制如何收敛

| 合并点 | 最小做法 | 必须保留的差异 |
| --- | --- | --- |
| A/B/C 报告模板 | 提取公共字段形状；三份入口保留角色、模板默认值和 prompt | 角色侧重、assumptions kind 默认值不能被统一覆盖；模板构造避免共享可变列表 |
| 上下文构造 | 核对 `ContextManager.from_settings()` 后复用；统一配置到参数的映射 | 扫描与验证按需独立实例，不能共享对话历史或可变治理状态 |
| LLM 调用 | 先统一配置来源、调用计量和超时语义，保留现有客户端 | LangChain 工具绑定与 KB 文本/JSON 调用暂不强制换成同一 SDK |
| AST 与调用上下文 | 先手合 `call_context.py` / `verify_taint.py` 的双向重写，再核对惰性加载、批量核验和语法树复用 | 一等冲突文件，不能当作简单提取公共接口；不扩大到其他源文件，保留本地核验修正 |
| 工具链辅助 | 只提取 dynamic/injection 中确定重复的编译器探测、子进程预算和临时目录处理 | harness、种子、注入效果判据仍各自维护 |
| 会话记忆与知识库 | 保留 `memory/` 审计和 `kbcore/` 修复经验检索的职责，通过证据 ID 关联 | 不混成一个向量库，不把历史相似样例当作当前代码事实 |
| 配置 | 统一有效配置快照与优先级；已有环境变量显式兼容 | 动态、注入静态核验、注入运行探针分别可控，禁用时不能执行子进程 |

这些优化以消除已确认重复为限，不新增通用 Agent 框架、插件平台或新的存储服务。

## 5. 目标链路与数据契约

目标链路：单文件读取 → A/B/C 并行 → 定位归一与候选分组 → D 裁决 → 静态证据与按需运行验证 → 双信号合并 → 检测报告/修复输入 → 现有修复流程。

动态工具仍位于 D 的验证阶段，不额外增加常驻 Agent，也不改变默认扫描输入权限。

建议新增可选证据块承载运行结果，并至少包含工具名、执行状态、输入哈希、证据 ID、目标归属和原始产物定位。区分两类状态：

- 执行状态：成功执行、未运行、不可用、超时、失败。
- 语义结果：复现、未复现、未知。成功执行但未复现不等于漏洞不存在。

具体字段在实现时与现有 `evidence.dynamic`、`evidence.injection`、`evidence.injection_runtime` 对齐，避免再建立一套平行格式。`signals.combine()` 保持为最终裁决的唯一入口。

检测报告继续保持 `final-report/2` 的既有字段，修复入口继续通过 `repair-input/1` 适配。旧报告缺少运行证据时按“未知/未提供”处理，不能回填成“检查通过”。如果新增字段改变消费者语义，则显式升级 schema，并提供旧版本适配。

SQLite 优先使用现有 JSON 字段记录扩展证据；确需新增列或索引时做可重复、非破坏性迁移，验证旧数据库仍可读取。修复端只接收与当前源码及目标匹配的事实，不能把“动态复现了原漏洞”解读为“补丁已正确修复”。

评测契约同时固定如下锚点；历史 baseline 行来自 `docs/EVAL.md` 的命令示例，不代表本次新跑成绩，正式比较必须在共同样本、同操作点与同聚合口径上重算：

| 操作点 | Recall | FPR | 判别力 | PairAcc |
| --- | --- | --- | --- | --- |
| 历史 baseline（accept） | 34.0% | 34.0% | +0.0pp | 18.0% |

表注：基线必须是**同臂、同口径**的操作点——`docs/EVAL.md` §6「禁止写法」已记录踩过的坑（曾把 50% 当基线，真实基线 69.23%）；`--pred accept`（主口径）与 `--pred wide`（附录口径）不得混列，`fn_attribution.py --row` 的四数必须来自同一口径、同一有效配对集。

各实验臂和 baseline 各自双跑，预先固定共同有效配对集；样本阳性按两次 `accept` 的交集定义，之后计算四指标及 PairAcc。另列每轮成绩、翻转率、缺报与双跑覆盖率，不能只报告稳定阳性。对每个 pair 的“漏洞侧阳性且修复侧阴性”成功状态做双侧**精确 McNemar**，报告 `only_baseline / only_variant / p`，不能用 finding 级计数替代。

审查提供的 G0 记录中，12 条 FN 有 5 条单次重跑就变 accept，自洽率为 0.5–0.84；细项本次未重算。结合 EVAL 已记录的采样翻转，这要求采用双跑交集并公开单跑结果，避免把采样噪声计作方案收益。

## 6. 分批实施与验收

### 第一批：固定版本与兼容基线 —— ❌ 未做

（无快照、无 `codex/framework-merge` 临时分支、无增量清单文件；改动直接落在工作树。仅 `.gitignore` 补了 `baseline/`、`测评效果/` 两条。）

- 按第 1 节在临时集成分支处理 24/22 双向分叉，保存工作树快照并建立提交/文件增量清单；处理 `.gitignore` 与已跟踪产物的不同作用，不 force push。
- 将 `tools/call_context.py`、`tools/verify_taint.py` 列为一等冲突文件，单列 `c690665`、`3dac9c3`、`8b5ca5e` 的适配与验收，不遗漏非动态增量。
- 固定当前模型、输入权限、报告格式、判定表及有效配置。
- 运行本地现有相关测试，记录依赖缺失、失败和跳过项。

通过条件：修复闭环、实验臂与报告契约有明确保留清单；已有失败不与合并回归混记。

### 第二批：移植工具，保持原判定 —— ✅ 已落地

（模块、容器文件、5 个远端测试、`analysis_backends.py` 占位契约均到位；三个插件开关默认 `False`；`21 + 5` 个 pytest 用例与 3 个脚本入口全绿，见 0.2 节。）

- 引入动态/注入工具、直接依赖、容器构建文件和三个远端独有测试，按本地接口适配导入；同步移植 `analysis_backends.py` 占位契约，不安装引擎依赖。
- 明确有效开关、工具绑定、分发、离线降级和配置快照。
- 新运行验证先处于显式 opt-in 模式；沿用本地静态判定。

通过条件：关闭新增能力时，固定输入与固定模型判决的输出语义不变；缺编译器或容器时输出可解释的未知状态。Windows 负责接口回归，Linux/WSL2 负责实际编译运行验收。

### 第三批：统一执行与证据 —— ◐ 部分

（执行复用、共享预算、容器限额与清理、三处签名回填 + 绑定断言均已完成；**归属机制未做**，见 0.3 节第 1 条。）

- 完成不改变工具实际输入与模型所见内容的会话内执行结果复用、执行预算；已有强制同源开关保持默认关闭，不新建机制、不新跑付费实验。
- 新增 Sanitizer/探针证据解析、源码与 harness 位置映射、目标调用链关联以及误归属回归测试；未完成归属时不允许把运行异常升级为当前 finding 的正证据。
- 给每个 finding 设置共享截止时间；编译、种子生成、运行、最小化和模型调用都消耗该预算，不能每个子阶段重置总预算。
- 动态执行使用现有容器路径核对网络、挂载与资源限制；超时后清理子进程和容器。只在临时工作区执行 harness。
- 为三处签名回填与工具绑定建立显式断言：动态/注入开关打开时 `available_tools()` 必须含 `verify_taint`、`dynamic_check`、`injection_check`、`injection_runtime`（外加上下文工具），关闭时只含 `verify_taint` 与上下文工具；某一路禁用时不得触发子进程。
- 同步报告构建、修复投影、数据库记录与相关 schema 测试。

通过条件：相同有效请求不会重复编译/运行，异输入不误命中，复用前后判定语义等价；强制同源仍为 opt-in；禁用开关无实际执行；超时和非目标异常不能产生 accept/reject；工具绑定数量与 `signals`/`tool_loop`/`verify_loop` 三处签名由测试断言（少一路绑定不报错，属静默回归）。

工作量按两项独立估算：执行结果复用/共享预算为一项，新增归属机制为另一项。后者至少覆盖证据解析、位置映射、路径关联和正反例测试四个子任务，不能按“补几个断言”估算；先以代表性样例验证可行性再给工期。若映射不可靠，维持 opt-in 观察模式，不承诺随插件移植同步上线。

### 第四批：公共代码收敛与去重优化 —— ◐ 部分

（模板与上下文收敛已完成；去重侧只做到 `path_safe_groups` + `candidate_paths`，`llm_group` 输入仍无位置/路径、AND/OR 语义未实现。）

- 先合并模板与上下文配置映射，验证行为等价。
- 再以独立提交调整候选分组及路径条件表达，保留原始贡献溯源。
- 分别回归现有修复闭环和检测回放，禁止把去重语义变化混入代码搬运。

通过条件：同一漏洞能聚合；相邻不同漏洞、同函数多 sink、不同成立路径不会误合并；所有输入候选均有去向。

### 第五批：独立配对评估后决定默认值 —— ❌ 未跑

（无新增 runs 记录；所有开关仍为默认关，因此现有基线数据不受本次合并影响。）

按相同输入、模型和预算比较五种状态：本地基线；合并后静态模式（不启用新增插件）；静态加动态；静态加注入；动态与注入组合。实验设置和样本需在正式比较前冻结。

首轮采用三臂双跑：本地基线、合并后静态、合并后组合。先比较前两臂确认合并未造成回归，再比较后两臂估算动态/注入增益；这样不会把代码合并影响与插件影响混为一谈。第二阶段才按首轮结果决定是否补跑“静态+动态”和“静态+注入”消融臂。

成本数字仅作历史负载估算，不是本次预算上限：旧实验参考为 98 runs ≈ 4.49 M token ≈ 50 min（该估算的工具/模型、并发条件需在开跑前从原始记录核实）。按此线性外推，首轮三臂双跑约 588 runs / 27 M token / 5 h；旧方案中的两臂估算约 392 runs / 18 M token / 3.3 h。新方案增加编译、运行、最小化和定向种子调用，实际 token 与墙钟时间可能不同。先用小批同配置样例（例如每臂 10 对、双跑）测量 API token、模型请求、编译/运行次数及墙钟时间；之后冻结全量的 token、运行次数、单 finding 截止时间和总墙钟上限，触顶即停并报告覆盖率。不得将上述线性折算直接当作采购预算或完工承诺。

按第 5 节双跑取交集，将 baseline 与各臂的 Recall、FPR、判别力与 PairAcc 列在同表，并报告 pair 级双侧精确 McNemar 的不一致计数与 p 值、有效配对数、超时/不可用率、目标漏洞对齐情况、模型调用与 token、编译/运行次数、耗时及成本。失败样本单列并公开分母，不能静默排除。强制同源不列入本批默认实验计划。

固定判决回放用于验证机制与兼容性，端到端评测用于估计实际效果，两者分开报告。遵守 `docs/EVAL.md` 与 `PROJECT_MEMORY.md`：独立样本无开发集泄漏、FPR 不增加、PairAcc 不下降、召回提高并达到约定配对统计门槛后，才能宣称效果提升或调整默认策略。

## 7. 必要检查清单

1. 编排：A/B/C 并行及 D join、视角子集、状态字段传递、缺报告报错。
2. 工具：新增开关、工具绑定/分发、缺依赖、共享超时、复用失效与调用追踪。
3. 证据：非零退出但无漏洞、harness 自身崩溃、崩溃位置不匹配、真实目标复现、未命中路径、输入前提不满足。
4. 去重：同根因多视角、相邻独立漏洞、不同 sink、互斥路径条件、候选完整覆盖与原始 ID 追踪。
5. 兼容：旧报告、旧 SQLite、`final-report/2` 与 `repair-input/1`、已有修复生成/验证/审查测试。
6. 范围：只读取指定源文件，不读取相邻源码；不改历史实验产物与基线。

三个测试文件为远端独有，本地 HEAD 不含，必须与对应模块一同移植并适配；其 `__main__` 入口分别执行：

```bash
python tests/test_signal_plugins.py
python tests/test_tool_loop_runtime.py
python tests/test_p2_framework.py
```

核对从 Framework 根目录执行时的导入路径，必要时适配入口。不能把 pytest 收集通过或脚本因缺依赖打印 SKIP 后退出 0 当作断言已执行；记录每个入口的实际断言执行与跳过情况。再跑相关 pytest 子集，最后运行 `python -m pytest tests/ -q` 并明确 skip/xfail 与缺失依赖。

实现每批完成后同步 `QUESTION.md` 的对应条目；README 更新为实际能力、默认开关和已知限制。方案阶段不把待做事项标为“已完成”。

## 8. 本次检查结果与剩余问题

已完成远端固定提交的核心源码阅读，以及本地相关接口、文档与差异方向核对；已明确移植范围、顺序、兼容边界与验收条件。

本次修订核对了双向提交数（24/22）、远端非动态提交列表、两个同源开关默认值、EVAL 契约与产物统计口径（899 = 880 + 19，已对齐），确认 `test_data/` 为随仓脱敏复现件、且当前无已跟踪的真实运行产物（`output/.gitkeep` 除外）；吸收审查提供的 L0/G0 实验与无归属机制结论，并明确未重算原始实验。另据审查补入 `verify_agent/` 三个一等冲突文件（含插件参数差异）、README/requirements 手合项与第五批预算边界。已执行合并接线相关测试（见 0.2 节：venv 下 21 + 5 通过、3 个脚本入口全绿）；仍未执行共同祖先级完整 diff、真实 `git merge`、Docker 构建与真实动态漏洞复现。远端缺少显式归属机制已明确，需要新增；新机制是否有效以及对召回/误报/PairAcc 的净收益仍需分阶段验证。

实施进度已单独记到第 0 节：第二批已落地、第四批大部分落地；**唯一阻塞验收的必做缺口是 §3.2 崩溃归属机制**，其次是 §3.3 的分组输入与 AND/OR 语义、§4 的 LLM 调用与记忆/知识库两行、§6 第五批评估。Git 侧仍待止血——1108 行改动与 22 个新文件均未提交，应先按第 1 节建立临时集成分支并分组提交，不直接在裸工作树上继续迭代。符号执行引擎、额外 Agent、全局存储重构留待明确收益后单独立项。
