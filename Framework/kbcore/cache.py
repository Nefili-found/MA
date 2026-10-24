"""内容寻址缓存：同一输入不重复花钱（§8-G6 要求"重跑 0 次 LLM 调用"）。

键 = sha256(所有影响输出的要素)。**漏带任何一个要素，重跑就会静默复用旧结果**，
所以 :func:`cache_key` 只接受显式列出的片段，不做隐式默许。
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Optional


def cache_key(*parts: Any) -> str:
    """稳定键：按传入顺序序列化（dict 按键排序），与进程无关。"""
    payload = json.dumps(parts, ensure_ascii=False, sort_keys=True, default=str)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


class Cache:
    """目录式 JSON 缓存。``enabled=False`` 时全部 miss（消融 / 复现实验用）。"""

    def __init__(self, root: Path, *, enabled: bool = True):
        self.root = Path(root)
        self.enabled = enabled
        self.hits = 0
        self.misses = 0

    def _path(self, key: str) -> Path:
        return self.root / key[:2] / f"{key}.json"

    def get(self, key: str) -> Optional[dict]:
        if not self.enabled:
            self.misses += 1
            return None
        path = self._path(key)
        if not path.exists():
            self.misses += 1
            return None
        try:
            self.hits += 1
            return json.loads(path.read_text(encoding="utf-8"))
        except Exception:  # pragma: no cover - 损坏的缓存当作 miss
            self.misses += 1
            return None

    def put(self, key: str, value: dict) -> None:
        if not self.enabled:
            return
        path = self._path(key)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding="utf-8")


__all__ = ["Cache", "cache_key"]
