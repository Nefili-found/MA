"""修复端结构重构 —— 以检测端结构化事实为诊断。

分层（见 ``change_process/summery/修复端_结构重构_2026-10-24_设计.md`` §3）::

    repair_input.json → intake → facts → query → retrieve → generate → correct → validate
                          │        │
                          │        └─(不足)→ reverify → 检测端 D 复核

本包只实现阶段 A（R1 检索可验）所需的模块：``schema`` / ``intake`` / ``facts`` /
``query`` / ``retrieve`` / ``report`` / ``cli``。``generate`` / ``correct`` /
``validate`` / ``loop`` 为待施工空壳。
"""

__all__: list[str] = []
