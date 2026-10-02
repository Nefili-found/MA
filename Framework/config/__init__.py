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
    roles_path: str = "prompts/roles.yaml"

    # 其他
    max_retries: int = 3
    log_enabled: bool = True


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

    return Settings(
        llm_provider=os.getenv("LLM_PROVIDER", llm.get("provider", "openai")),
        model_name=os.getenv("MODEL_NAME", llm.get("model", "gpt-4o-mini")),
        api_key=os.getenv("OPENAI_API_KEY", ""),
        base_url=(os.getenv("OPENAI_BASE_URL") or llm.get("base_url") or None),
        temperature=float(os.getenv("LLM_TEMPERATURE", llm.get("temperature", 0.0) or 0.0)),
        db_path=os.getenv("MEMORY_DB_PATH", memory.get("db_path", "memory.db")),
        input_file=os.getenv("INPUT_FILE", inp.get("file", "examples/input/sample.c")),
        output_path=os.getenv("OUTPUT_PATH", out.get("path", "output/final_report.json")),
        roles_path=os.getenv("ROLES_PATH", prompts.get("roles_path", "prompts/roles.yaml")),
        max_retries=int(os.getenv("MAX_RETRIES", retries.get("max", 3) or 3)),
        log_enabled=_as_bool(os.getenv("LOG_ENABLED", logging.get("enabled", True))),
    )
