"""配置加载。

优先级（从低到高）：代码默认值 < config/config.yaml（或 example）< 环境变量 / .env。

敏感信息（API Key 等）只从环境变量 / .env 读取，绝不硬编码。
TODO: 请复制 config/.env.example 为 config/.env 并填写必要环境变量。

说明：该模块是相对提示词目录结构补充的一个 Python 包（config/__init__.py），
用于集中加载配置；已在 QUESTION.md 中标注。
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

# 项目根目录（config/ 的上一级）
ROOT = Path(__file__).resolve().parent.parent
CONFIG_DIR = ROOT / "config"

try:  # 可选依赖
    import yaml  # type: ignore
except ImportError:  # pragma: no cover
    yaml = None  # type: ignore

try:  # 可选依赖
    from dotenv import load_dotenv  # type: ignore
except ImportError:  # pragma: no cover
    load_dotenv = None  # type: ignore


@dataclass
class Settings:
    """运行期配置。"""

    # LLM
    llm_provider: str = "openai"
    model_name: str = "gpt-4o-mini"
    api_key: str = ""
    base_url: Optional[str] = None
    temperature: float = 0.0

    # 记忆库 / IO
    db_path: str = "memory.db"
    input_file: str = "examples/input/sample.c"
    output_path: str = "output/final_report.json"
    repair_input_path: str = "output/repair_input.json"  # 修复端输入投影（repair-input/1）
    roles_path: str = "prompts/roles.yaml"

    # 【优化 O-10】上下文治理（A 篇第 09 章）：窗口 / 阈值 / 外存 / 裁剪 / 压缩
    context_window: int = 128_000          # 模型上下文窗口（token），按实际模型调整
    context_threshold_ratio: float = 0.8   # 压力阈值：占用 >= 80% 触发治理
    context_retain_ratio: float = 0.16     # 压缩时保留最近 16% 原文
    context_enable_spill: bool = True      # 是否启用大结果外存
    context_enable_compaction: bool = True # 是否启用摘要压缩（需 LLM）
    spill_root: str = "output/spill"       # 外存文件目录
    spill_max_inline_bytes: int = 4096     # 工具结果 / 大输入内联字节上限
    prune_threshold_chars: int = 8192      # 历史工具结果裁剪字符阈值
    prune_head_chars: int = 4096           # 裁剪保留头部字符
    prune_tail_chars: int = 1024           # 裁剪保留尾部字符

    # 其他
    max_retries: int = 3
    log_enabled: bool = True

    # 【假设条件 + 触发路径核验】双信号合并（父设计 §3.3）
    verify_tau: float = 0.8            # 工具信号单方 overturn 的置信度阈值 τ
    verify_drop_rejected: bool = True  # overturn 的 finding 是否从最终输出剔除


def _as_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in ("1", "true", "yes", "on")


def resolve(path: "str | Path") -> Path:
    """把相对路径解析为相对项目根目录的绝对路径。"""
    p = Path(path)
    return p if p.is_absolute() else (ROOT / p)


def _load_yaml(path: Path) -> dict:
    if yaml is None or not path.exists():
        return {}
    try:
        with path.open("r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh) or {}
        return data if isinstance(data, dict) else {}
    except Exception:  # pragma: no cover
        return {}


def load_settings(config_path: Optional[str] = None) -> Settings:
    """加载配置。

    :param config_path: 可选的 yaml 路径；默认 config/config.yaml，
                        不存在时回退到 config/config.example.yaml。
    """
    # 1) .env
    env_file = CONFIG_DIR / ".env"
    if load_dotenv is not None and env_file.exists():
        load_dotenv(env_file, override=False)

    # 2) YAML
    yaml_path = Path(config_path) if config_path else (CONFIG_DIR / "config.yaml")
    if not yaml_path.exists():
        yaml_path = CONFIG_DIR / "config.example.yaml"
    data = _load_yaml(yaml_path)

    llm = data.get("llm", {}) or {}
    memory = data.get("memory", {}) or {}
    inp = data.get("input", {}) or {}
    out = data.get("output", {}) or {}
    retries = data.get("retries", {}) or {}
    logging = data.get("logging", {}) or {}
    prompts = data.get("prompts", {}) or {}
    ctx_cfg = data.get("context", {}) or {}  # 【优化 O-10】上下文治理段
    verify_cfg = data.get("verify", {}) or {}  # 【双信号合并】验证环节阈值 / 丢弃开关

    return Settings(
        llm_provider=os.getenv("LLM_PROVIDER", llm.get("provider", "openai")),
        model_name=os.getenv("MODEL_NAME", llm.get("model", "gpt-4o-mini")),
        api_key=os.getenv("OPENAI_API_KEY", ""),
        base_url=(os.getenv("OPENAI_BASE_URL") or llm.get("base_url") or None),
        temperature=float(os.getenv("LLM_TEMPERATURE", llm.get("temperature", 0.0) or 0.0)),
        db_path=os.getenv("MEMORY_DB_PATH", memory.get("db_path", "memory.db")),
        input_file=os.getenv("INPUT_FILE", inp.get("file", "examples/input/sample.c")),
        output_path=os.getenv("OUTPUT_PATH", out.get("path", "output/final_report.json")),
        repair_input_path=os.getenv(
            "REPAIR_INPUT_PATH", out.get("repair_input_path", "output/repair_input.json")
        ),
        roles_path=os.getenv("ROLES_PATH", prompts.get("roles_path", "prompts/roles.yaml")),
        # 【优化 O-10】上下文治理配置：默认 < yaml(context 段) < 环境变量
        context_window=int(os.getenv("CONTEXT_WINDOW", ctx_cfg.get("window", 128_000) or 128_000)),
        context_threshold_ratio=float(
            os.getenv("CONTEXT_THRESHOLD_RATIO", ctx_cfg.get("threshold_ratio", 0.8) or 0.8)
        ),
        context_retain_ratio=float(
            os.getenv("CONTEXT_RETAIN_RATIO", ctx_cfg.get("retain_ratio", 0.16) or 0.16)
        ),
        context_enable_spill=_as_bool(
            os.getenv("CONTEXT_ENABLE_SPILL", ctx_cfg.get("enable_spill", True))
        ),
        context_enable_compaction=_as_bool(
            os.getenv("CONTEXT_ENABLE_COMPACTION", ctx_cfg.get("enable_compaction", True))
        ),
        spill_root=os.getenv("SPILL_ROOT", ctx_cfg.get("spill_root", "output/spill")),
        spill_max_inline_bytes=int(
            os.getenv("SPILL_MAX_INLINE_BYTES", ctx_cfg.get("spill_max_inline_bytes", 4096) or 4096)
        ),
        prune_threshold_chars=int(
            os.getenv("PRUNE_THRESHOLD_CHARS", ctx_cfg.get("prune_threshold_chars", 8192) or 8192)
        ),
        prune_head_chars=int(
            os.getenv("PRUNE_HEAD_CHARS", ctx_cfg.get("prune_head_chars", 4096) or 4096)
        ),
        prune_tail_chars=int(
            os.getenv("PRUNE_TAIL_CHARS", ctx_cfg.get("prune_tail_chars", 1024) or 1024)
        ),
        max_retries=int(os.getenv("MAX_RETRIES", retries.get("max", 3) or 3)),
        log_enabled=_as_bool(os.getenv("LOG_ENABLED", logging.get("enabled", True))),
        verify_tau=float(os.getenv("VERIFY_TAU", verify_cfg.get("tau", 0.8) or 0.8)),
        verify_drop_rejected=_as_bool(
            os.getenv("VERIFY_DROP_REJECTED", verify_cfg.get("drop_rejected", True))
        ),
    )
