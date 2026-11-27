"""验证阶段共享截止时间；子阶段只能使用剩余预算。"""
from contextvars import ContextVar
import os
import signal
import subprocess
import time
import uuid

DEADLINE = ContextVar("verification_deadline", default=None)
RUNTIME_INPUTS = ContextVar("verification_runtime_inputs", default=None)


def record_runtime_input(value):
    inputs = RUNTIME_INPUTS.get()
    if inputs is not None:
        inputs.append(value)


def bounded_timeout(seconds):
    deadline = DEADLINE.get()
    if deadline is None:
        return seconds
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise subprocess.TimeoutExpired("finding execution budget", seconds)
    return min(seconds, remaining)


def run_process(command, *, timeout, capture_output=False, **kwargs):
    """限时执行；超时清理进程树和本次 Docker 容器，不触碰其它执行。"""
    timeout = bounded_timeout(timeout)
    command = list(command)
    container = None
    if len(command) > 1 and command[:2] == ["docker", "run"]:
        container = "ma-verify-" + uuid.uuid4().hex
        limits = ["--name", container, "--cpus=1", "--cap-drop=ALL", "--security-opt=no-new-privileges"]
        if not any(str(arg).startswith("--memory") for arg in command):
            limits.append("--memory=512m")
        if not any(str(arg).startswith("--pids-limit") for arg in command):
            limits.append("--pids-limit=64")
        command[2:2] = limits
    if capture_output:
        kwargs.update(stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if os.name == "nt":
        kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
    else:
        kwargs["start_new_session"] = True
    with subprocess.Popen(command, **kwargs) as process:
        try:
            stdout, stderr = process.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            try:
                if os.name == "nt":
                    subprocess.run(["taskkill", "/PID", str(process.pid), "/T", "/F"],
                                   capture_output=True, timeout=5)
                else:
                    os.killpg(process.pid, signal.SIGKILL)
            except (OSError, subprocess.TimeoutExpired):
                process.kill()
            finally:
                process.kill()
                try:
                    process.communicate(timeout=5)
                except subprocess.TimeoutExpired:
                    # Windows 子进程可能仍持有管道句柄，回收输出也必须限时。
                    for pipe in (process.stdout, process.stderr):
                        if pipe is not None:
                            pipe.close()
                if container:
                    try:
                        subprocess.run(["docker", "rm", "-f", container], capture_output=True, timeout=5)
                    except (OSError, subprocess.TimeoutExpired):
                        pass
            raise
        return subprocess.CompletedProcess(command, process.returncode, stdout, stderr)
