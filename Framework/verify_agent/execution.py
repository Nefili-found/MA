"""单 finding 的执行复用：只复用完全相同输入，不改模型所见证据或参数。"""
from __future__ import annotations

from copy import deepcopy
import hashlib
import inspect
import json
import math
import os
import time
from pathlib import Path
from typing import Any

from observability import log_event
from tools.execution_budget import DEADLINE, RUNTIME_INPUTS, bounded_timeout


def _digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=False,
                                     allow_nan=False).encode("utf-8")).hexdigest()


class ExecutionSession:
    def __init__(self, code: str, settings: Any):
        self.code = code
        self.settings = dict(vars(settings)) if hasattr(settings, "__dict__") else {}
        self.cache = {}
        self.records = []
        enabled = any(self.settings.get(k, False) for k in (
            "verify_dynamic_enabled", "verify_injection_enabled", "verify_injection_runtime_enabled"))
        seconds = float(self.settings.get("verify_execution_timeout", 120))
        if enabled and (not math.isfinite(seconds) or seconds <= 0):
            raise ValueError("verify.execution_timeout 必须为正有限秒数")
        self.deadline = time.monotonic() + seconds if enabled else None

    def remaining(self):
        if self.deadline is None:
            return None
        token = DEADLINE.set(self.deadline)
        try:
            return bounded_timeout(float("inf"))
        finally:
            DEADLINE.reset(token)

    def call(self, name, fn, hypothesis, context, **kwargs):
        if (name in ("dynamic_check", "injection", "injection_runtime")
                and kwargs.get("enabled") and
                (not isinstance(context, dict) or context.get("code") != self.code)):
            log_event("verify.source_mismatch", level="warn", tool=name)
            return {"status": "uncertain", "verdict": "uncertain", "confidence": 0.0,
                    "reason": "工具源码与当前扫描文件不一致，未执行", "evidence": {"skipped": True}}
        key = None
        try:
            module = inspect.getmodule(fn)
            # 模块常量包含有效开关、种子、预算、harness/工具链选择配置。
            constants = {k: v for k, v in vars(module).items()
                         if k.upper() == k and isinstance(v, (str, int, float, bool, type(None)))}
            version = hashlib.sha256(Path(module.__file__).read_bytes()).hexdigest()
            import shutil
            compiler = os.environ.get("DYNCHECK_CC") or shutil.which("clang") or shutil.which("gcc")
            compiler_identity = None
            if compiler:
                stat = Path(compiler).stat()
                compiler_identity = [str(Path(compiler).resolve()), stat.st_size, stat.st_mtime_ns]
            key = _digest([name, fn.__qualname__, version, constants, self.settings, dict(os.environ),
                           compiler_identity, hypothesis, context, kwargs])
            # 缺源码或字段形态不完整时绝不复用；不猜测缺省源码。
            if (not isinstance(context, dict) or not context.get("code")
                    or not isinstance(hypothesis, dict) or not hypothesis):
                key = None
            # 可变镜像 tag 不能证明工具链同一；仅固定 digest 的容器可复用。
            if name == "dynamic_check" and constants.get("DOCKER_MODE") != "off":
                import shutil
                if shutil.which("docker") and "@sha256:" not in constants.get("DOCKER_IMAGE", ""):
                    key = None
        except (TypeError, ValueError, AttributeError, OSError):
            key = None
        hit = key is not None and key in self.cache
        token = DEADLINE.set(self.deadline)
        runtime_inputs = deepcopy(self.cache[key]["runtime_inputs"]) if hit else []
        runtime_token = RUNTIME_INPUTS.set(runtime_inputs)
        try:
            self.remaining()
            result = deepcopy(self.cache[key]["result"]) if hit else fn(hypothesis, context, **kwargs)
            self.remaining()
        except Exception as exc:
            record = {"tool": name, "input_digest": key, "cache_hit": False,
                      "error": f"{type(exc).__name__}: {exc}"}
            self.records.append(record)
            log_event("verify.execution", level="warn", **record)
            raise
        finally:
            DEADLINE.reset(token)
            RUNTIME_INPUTS.reset(runtime_token)
        result_id = None
        try:
            result_id = _digest(result)
        except (TypeError, ValueError):
            pass
        execution_digest = _digest([key, runtime_inputs]) if key else None
        record = {"tool": name, "input_digest": execution_digest, "result_id": result_id, "cache_hit": hit}
        self.records.append(record)
        log_event("verify.execution", **record)
        # 实际种子/harness 未留痕时不能复用动态请求；同请求复用已冻结的准备结果。
        prepared = name not in ("dynamic_check", "injection_runtime") or bool(runtime_inputs)
        if key and prepared and isinstance(result, dict):
            outcome = result.get("outcome") or (result.get("evidence") or {}).get("outcome")
            if (result.get("verdict") in ("accept", "reject", "challenge")
                    or outcome == "safe") and not (result.get("raw_output") or {}).get("error"):
                self.cache[key] = {"result": deepcopy(result), "runtime_inputs": deepcopy(runtime_inputs)}
        return result


def execute(execution, name, fn, hypothesis, context, **kwargs):
    if execution is None:
        return fn(hypothesis, context, **kwargs)
    return execution.call(name, fn, hypothesis, context, **kwargs)
