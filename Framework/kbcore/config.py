"""知识库侧配置：``configs/kb.yaml`` < 环境变量 / ``config/.env``。

默认值与设计文档 §6.2 对齐。这里只读**知识库自己的**键，不复用检测端的
``config.Settings``——两边模型与预算独立，混用会让"库是怎么建的"不可追溯。

自带一个极小的 ``.env`` 解析器：``python-dotenv`` 在部分环境缺失，
而知识库是长跑批处理，不能因为缺一个可选依赖就整批失败。
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field, fields
from pathlib import Path
from typing import Any, Dict, Optional

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_CONFIG = ROOT / "configs" / "kb.yaml"
DEFAULT_ENV_FILE = ROOT / "config" / ".env"

_ENV_LINE = re.compile(r"^\s*(?:export\s+)?([A-Za-z_]\w*)\s*=\s*(.*)$")


def load_env_file(path: Path, *, override: bool = False) -> Dict[str, str]:
    """读 ``KEY=VALUE`` 形式的 .env（支持引号、# 注释、行内注释）。"""
    out: Dict[str, str] = {}
    if not path.exists():
        return out
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        m = _ENV_LINE.match(line)
        if not m:
            continue
        key, value = m.group(1), m.group(2).strip()
        if value[:1] in ("'", '"') and value[-1:] == value[:1] and len(value) >= 2:
            value = value[1:-1]
        else:
            value = value.split(" #", 1)[0].strip()
        if override or key not in os.environ:
            out[key] = value
    return out


def _as_bool(value: Any, default: bool = False) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return default
    return str(value).strip().lower() in ("1", "true", "yes", "on")


def _as_path(value: Any, default: Path) -> Path:
    p = Path(str(value)) if value not in (None, "") else default
    return p if p.is_absolute() else (ROOT / p)


@dataclass
class KBConfig:
    """建库全部开关。未知 YAML 键会在 :func:`load_config` 里报错（防静默跑默认值）。"""

    # 路径 / 版本
    pairs_root: Path = ROOT / "other fix framework" / "datasets" / "patchdb_cvefixes_for_appatch_train"
    out_dir: Path = ROOT / "artifacts" / "kb-v1"
    runs_dir: Path = ROOT / "runs"
    cache_dir: Path = ROOT / ".cache" / "kb"
    prompts_dir: Path = ROOT / "prompts"
    kb_ver: str = "kb-v1"

    # LLM（抽取 + 抽象）
    # 注意：这里**不允许**出现任何密钥/供应商的硬编码默认值。
    # 凭证一律来自 config/.env 或进程环境，供应商由 --provider / kb.yaml 决定。
    provider: str = "openai"  # openai | deepseek（决定用哪组凭证，不做静默回退）
    model: str = ""
    api_key: str = ""
    base_url: Optional[str] = None
    temperature: float = 0.0
    max_tokens: int = 2048
    prompt_ver: str = "kb-extract-v1"
    abstract_prompt_ver: str = "kb-abstract-v1"
    llm_timeout_s: float = 90.0
    llm_retries: int = 2

    # 抽象化
    abstract_enabled: bool = True
    abstract_max_retry: int = 1

    # 证据
    evidence_mode: str = "tree_sitter"  # tree_sitter | none
    max_df_items: int = 40
    max_cf_items: int = 20

    # 嵌入
    embed_model: str = "sentence-transformers/all-MiniLM-L6-v2"
    embed_dim: int = 384
    embed_batch: int = 64

    # 门禁
    max_root_cause_chars: int = 300
    max_strategy_chars: int = 500
    max_behavior_chars: int = 300
    max_calls: int = 8

    # 运行
    concurrency: int = 4
    cache: bool = True
    extract_retries: int = 1

    extra: Dict[str, Any] = field(default_factory=dict)

    def resolve_paths(self) -> "KBConfig":
        """把相对路径统一解析到仓库根。"""
        for f in fields(self):
            if f.type in ("Path", Path) or f.name.endswith(("_dir", "_root")):
                value = getattr(self, f.name)
                if isinstance(value, Path) and not value.is_absolute():
                    setattr(self, f.name, ROOT / value)
        return self


# YAML 段 → dataclass 字段
_YAML_MAP: Dict[str, str] = {
    "pairs_root": "pairs_root",
    "out_dir": "out_dir",
    "runs_dir": "runs_dir",
    "cache_dir": "cache_dir",
    "kb_ver": "kb_ver",
    "provider": "provider",
    "extract.provider": "provider",
    "extract.model": "model",
    "extract.temperature": "temperature",
    "extract.max_tokens": "max_tokens",
    "extract.prompt_ver": "prompt_ver",
    "extract.retries": "extract_retries",
    "abstract.enabled": "abstract_enabled",
    "abstract.max_retry": "abstract_max_retry",
    "abstract.prompt_ver": "abstract_prompt_ver",
    "evidence.mode": "evidence_mode",
    "evidence.max_df_items": "max_df_items",
    "evidence.max_cf_items": "max_cf_items",
    "embed.model": "embed_model",
    "embed.dim": "embed_dim",
    "embed.batch": "embed_batch",
    "gate.max_root_cause_chars": "max_root_cause_chars",
    "gate.max_strategy_chars": "max_strategy_chars",
    "gate.max_behavior_chars": "max_behavior_chars",
    "gate.max_calls": "max_calls",
    "run.concurrency": "concurrency",
    "run.cache": "cache",
    "run.runs_dir": "runs_dir",
    "run.cache_dir": "cache_dir",
}

# 环境变量覆盖（.env / 进程环境均可）
_ENV_MAP: Dict[str, str] = {
    "KB_PAIRS_ROOT": "pairs_root",
    "KB_PROVIDER": "provider",
    "KB_OUT_DIR": "out_dir",
    "KB_VER": "kb_ver",
    "KB_MODEL": "model",
    "KB_BASE_URL": "base_url",
    "KB_TEMPERATURE": "temperature",
    "KB_MAX_TOKENS": "max_tokens",
    "KB_PROMPT_VER": "prompt_ver",
    "KB_EVIDENCE_MODE": "evidence_mode",
    "KB_EMBED_MODEL": "embed_model",
    "KB_CONCURRENCY": "concurrency",
    "KB_CACHE": "cache",
}


def _flatten(data: Dict[str, Any], prefix: str = "") -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for key, value in (data or {}).items():
        name = f"{prefix}{key}"
        if isinstance(value, dict):
            out.update(_flatten(value, prefix=f"{name}."))
        else:
            out[name] = value
    return out


def load_config(
    path: Optional[str | Path] = None,
    *,
    strict_yaml: bool = True,
    provider: Optional[str] = None,
) -> KBConfig:
    """加载配置：默认值 < YAML < 环境变量。

    :param strict_yaml: 未知 YAML 键报错（默认）。写错开关键名会静默跑默认值，
        这类错误在批量建库时极难发现，所以宁可早失败。
    """
    cfg = KBConfig()

    # 1) YAML
    yaml_path = Path(path) if path else DEFAULT_CONFIG
    if yaml_path.exists():
        try:
            import yaml  # type: ignore
        except ImportError:  # pragma: no cover
            yaml = None  # type: ignore
        if yaml is not None:
            data = yaml.safe_load(yaml_path.read_text(encoding="utf-8")) or {}
            flat = _flatten(data if isinstance(data, dict) else {})
            unknown = [k for k in flat if k not in _YAML_MAP]
            if unknown and strict_yaml:
                raise ValueError(f"configs/kb.yaml 含未知键：{sorted(unknown)}")
            for key, value in flat.items():
                attr = _YAML_MAP.get(key)
                if attr:
                    setattr(cfg, attr, value)

    # 2) .env + 环境变量
    env = load_env_file(DEFAULT_ENV_FILE)
    env.update({k: v for k, v in os.environ.items() if k not in env})
    for env_key, attr in _ENV_MAP.items():
        if env_key in env and env[env_key] != "":
            setattr(cfg, attr, env[env_key])

    # 3) LLM 凭证：按 provider 选**一组**凭证，不做静默回退。
    #    openai   → OPENAI_API_KEY / OPENAI_BASE_URL / MODEL_NAME（默认，与检测端共用 .env）
    #    deepseek → DEEPSEEK_API_KEY，base 默认 https://api.deepseek.com/v1，model 默认 deepseek-chat
    #    选了 provider 却缺该组凭证时直接报错，避免"用了 A 家的 key 打 B 家的服务"这类 401 迷宫。
    if provider:
        cfg.provider = str(provider).strip().lower()
    provider = str(cfg.provider or "openai").strip().lower()
    if provider == "deepseek":
        dy_key = env.get("KB_API_KEY") or env.get("DEEPSEEK_API_KEY", "")
        cfg.api_key = str(dy_key)
        cfg.model = str(env.get("KB_MODEL") or cfg.model or "deepseek-chat")
        if cfg.model.startswith("gpt-"):  # .env 里的 MODEL_NAME 属于 openai 一侧，不能带过来
            cfg.model = env.get("KB_MODEL") or "deepseek-chat"
        cfg.base_url = env.get("KB_BASE_URL") or cfg.base_url or "https://api.deepseek.com/v1"
    else:
        cfg.api_key = str(env.get("KB_API_KEY") or env.get("OPENAI_API_KEY", ""))
        cfg.model = str(env.get("KB_MODEL") or cfg.model or env.get("MODEL_NAME", ""))
        cfg.base_url = env.get("KB_BASE_URL") or cfg.base_url or env.get("OPENAI_BASE_URL") or None
    cfg.provider = provider
    cfg.temperature = float(cfg.temperature)
    cfg.max_tokens = int(cfg.max_tokens)
    cfg.concurrency = int(cfg.concurrency)
    cfg.abstract_enabled = _as_bool(cfg.abstract_enabled, True)
    cfg.cache = _as_bool(cfg.cache, True)

    # 4) 路径归一
    cfg.pairs_root = _as_path(cfg.pairs_root, KBConfig.pairs_root)
    cfg.out_dir = _as_path(cfg.out_dir, KBConfig.out_dir)
    cfg.runs_dir = _as_path(cfg.runs_dir, KBConfig.runs_dir)
    cfg.cache_dir = _as_path(cfg.cache_dir, KBConfig.cache_dir)
    cfg.prompts_dir = _as_path(cfg.prompts_dir, KBConfig.prompts_dir)
    return cfg


def require_llm(cfg: KBConfig) -> None:
    """建库前检查凭证；缺失时给可操作的报错，而不是等 306 次调用全 401。"""
    missing = [name for name, value in (("model", cfg.model), ("api_key", cfg.api_key)) if not value]
    if missing:
        raise RuntimeError(
            "缺少 LLM 凭据：" + "、".join(missing)
            + "（在 config/.env 里填 MODEL_NAME / OPENAI_API_KEY / OPENAI_BASE_URL，"
            "或用 KB_MODEL / KB_API_KEY 覆盖）"
        )


__all__ = ["KBConfig", "ROOT", "DEFAULT_CONFIG", "load_config", "load_env_file", "require_llm"]
