# 符号执行 / 动态污点跟踪（DTaint）接入设计

> 状态：**未接入**。当前仅在 `tools/analysis_backends.py` 预留抽象接口与注册/工厂机制，
> 未注册任何真实引擎；工厂默认返回占位后端，结果状态为 `unavailable`，不产出有罪/无罪结论。

## 1. 定位与分工

D 层现有两条验证路径：

| 路径 | 模块 | 手段 | 局限 |
|---|---|---|---|
| 静态核验 | `tools/verify_taint.py` | 同文件调用图可达性 + 守卫作用域启发式 | 不执行，跨过程/跨文件弱，路径爆炸不求解 |
| 动态执行 | `tools/dynamic_check.py` | 编译 harness + Sanitizer 跑变异种子 | 依赖种子覆盖，未覆盖到的路径看不到 |

预留的第三条路径：

- **符号执行**：把输入当作符号值，沿分支路径做约束求解，判断是否存在一条源到汇的可行路径；
- **动态污点跟踪（DTaint）**：运行时标记污点源，追踪其传播到汇点的过程。

二者用于补静态可达性判断与动态样本覆盖不到的路径，证据口径仍遵循本仓库
"只补强、从不削弱、永不 reject"：后端不可用 / 证据不足 → `unknown` 或 `unavailable`，
不据此判无罪。

## 2. 候选引擎

### 2.1 符号执行

| 引擎 | 形态 | 优势 | 接入代价 / 风险 |
|---|---|---|---|
| angr | Python 库 | 与现有 Python 编排同栈，API 友好 | 重量级依赖，加载慢，复杂二进制路径爆炸明显 |
| KLEE | LLVM 编译期符号虚拟机 | 路径覆盖严谨，支持内存模型 | 需把被测 C 编译为 LLVM bitcode，工具链改造大 |
| Manticore | Python 库 | 支持二进制 / EVM | 社区活跃度一般，性能有限 |

### 2.2 动态污点跟踪

| 方案 | 形态 | 说明 |
|---|---|---|
| libDFSan | 编译期污点传播（DataFlowSanitizer） | 需定制编译链，源码级污点标签 |
| Pin / DynamoRIO | 动态插桩框架 | 运行时插桩，部署重，平台相关 |
| angr taint | Python 层污点模拟 | 与 angr 共用环境，精度低于原生插桩 |

## 3. 接口契约（对应 `tools/analysis_backends.py`）

- `SymbolicAnalyzer.analyze(func_src, params, sinks, context) -> AnalysisResult`
- `TaintTracker.track(func_src, sources, sinks, context) -> AnalysisResult`
- `AnalysisResult.status ∈ {reachable, unreachable, unknown, unavailable}`
- 后端通过 `register_backend(kind, name, cls)` 注册；工厂
  `get_symbolic_backend(name)` / `get_taint_backend(name)` 取后端。

接入真实引擎时：实现对应抽象类 → 注册 → 在 D 层编排中作为第三路信号并入
`combine`，置信度档位参照现有证据体系（静态 0.88 / 动态崩溃 0.92）单独标定。

## 4. 接入前置条件

1. 明确目标语言子集（当前以 C/C++ 源码为主），排除不支持的语法/库调用；
2. 确定运行环境（本机 Linux 或 Docker 容器），引擎依赖与编译链可复现安装；
3. 定义源（taint_source）/ 汇（sink）的字段映射，复用 hypothesis 现有结构；
4. 设定路径步数 / 求解超时 / 内存上限，防止路径爆炸拖垮主流程；
5. 后端不可用必须降级为 `unavailable`，不得阻断 A/B/C 主链路。

## 5. 风险与边界

- **路径爆炸**：循环、深分支、复杂内存操作会让符号执行状态空间失控，必须有步数/超时截断；
- **环境建模**：外部库、系统调用、全局状态在符号环境中需建模，建模缺失会产生假阴性；
- **污点精度**：粗粒度污点可能误报（把非污点传播判为污点），需与静态/动态证据交叉确认；
- **不可替代动态执行**：符号执行给"可达性"，崩溃是否真发生仍需 Sanitizer / 运行时确认。

## 6. 当前未做的事项

- 未安装 / 调用任何上述引擎；
- 未在 D 层编排中接入第三路信号；
- 未标定符号 / 污点证据的置信度档位；
- 未做引擎结果与现有 `verify_taint` / `dynamic_check` 证据的冲突合并规则。

## 7. 环境决策记录（本轮评估）

- **当前阶段不默认启用真实引擎**：候选 angr 为 Python 重依赖（claripy / z3 / archinfo / pyvex / unicorn 等），加载慢，原生绑定在 Windows 原生环境支持有限；符号执行还存在路径爆炸风险。本交付链路以静态启发式 + 动态执行为主，符号 / 污点保持接口预留，工厂返回 `unavailable`。
- **后续接入环境**：建议在 WSL2 / Docker Linux 口径安装引擎，隔离于主链路；必须设定路径步数、求解超时与内存上限，后端不可用即降级 `unavailable`，不阻断 A/B/C 编排。
- **接入顺序**：实现后端类 → `register_backend` 注册 → 工厂取用 → 作为第三路信号并入 `combine` → 单独标定置信度档位 → 与现有 `verify_taint` / `dynamic_check` 证据做冲突合并。
