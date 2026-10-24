"""知识库侧（Phase 1：双视图抽取 / 抽象 / 嵌入 / 存储）。

与修复端的分工见 `change_process/design/知识库_双视图抽取与存储_代码方案_设计.md`：
本包只负责"把 306 对历史修复对变成两个 FAISS 库 + meta.jsonl"，
不负责检索、重排、补丁生成与验证。

模块分层（确定性 → LLM）：

* ``pairs``   数据集扫描（无 LLM）
* ``anchor``  漏洞行定位（无 LLM，difflib）
* ``views``   DF / CF 视图证据（无 LLM，tree-sitter）
* ``extract`` 双视图五类知识项抽取（LLM）
* ``abstract`` 抽象化 + 实现无关性判定（LLM 改写 + 确定性判定）
* ``gate``    入库门禁（无 LLM）
* ``embed``   384 维嵌入（all-MiniLM-L6-v2）
* ``store``   faiss / 兜底后端落盘 + manifest
"""

from __future__ import annotations

__version__ = "0.1.0"
SCHEMA_VER = "kb-v1"

__all__ = ["__version__", "SCHEMA_VER"]
