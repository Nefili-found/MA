"""OpenAI 兼容的薄 LLM 客户端（唯一触达外网的地方，§0-D4）。

* 优先用 ``openai`` SDK，缺失时退到 ``requests`` 直连 ``/chat/completions``；
* 每次调用返回 :class:`TokenUsage`（token 来自服务端 usage，usd 由价目表换算，
  没有价目表就记 0——**不编造金额**）；
* 失败抛 :class:`LLMError`，由上层决定是重试、记账还是整批中止。
"""

from __future__ import annotations

import json
import time
from typing import Optional

from .interfaces import LLMError, TokenUsage

# 每百万 token 的美元价目（留空表示"不估算"，manifest 里 usd 记 0）
DEFAULT_PRICES: dict[str, tuple[float, float]] = {}


class OpenAICompatClient:
    """同步客户端。并发由调用方用线程池实现（本类无共享可变状态）。"""

    def __init__(
        self,
        model: str,
        api_key: str,
        base_url: Optional[str] = None,
        *,
        temperature: float = 0.0,
        max_tokens: int = 1024,
        timeout_s: float = 90.0,
        retries: int = 2,
        prices: Optional[dict[str, tuple[float, float]]] = None,
    ):
        if not model:
            raise ValueError("LLMClient 需要 model")
        if not api_key:
            raise ValueError("LLMClient 需要 api_key")
        self.model = model
        self.api_key = api_key
        self.base_url = (base_url or "").rstrip("/") or None
        self.temperature = float(temperature)
        self.max_tokens = int(max_tokens)
        self.timeout_s = float(timeout_s)
        self.retries = max(0, int(retries))
        self.prices = dict(DEFAULT_PRICES if prices is None else prices)
        self._sdk = None
        self._mode = "sdk"
        try:  # pragma: no cover - 取决于环境
            from openai import OpenAI  # type: ignore

            self._sdk = OpenAI(api_key=self.api_key, base_url=self.base_url, timeout=self.timeout_s)
        except Exception:
            self._sdk = None
            self._mode = "http"

    # -- 计量 ---------------------------------------------------------------
    def _cost(self, in_tokens: int, out_tokens: int) -> float:
        price = self.prices.get(self.model)
        if not price:
            return 0.0
        return (in_tokens * price[0] + out_tokens * price[1]) / 1_000_000.0

    # -- 调用 ---------------------------------------------------------------
    def complete(
        self,
        system: str,
        user: str,
        *,
        tag: str = "",
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
    ) -> tuple[str, TokenUsage]:
        messages = [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ]
        temp = self.temperature if temperature is None else float(temperature)
        limit = self.max_tokens if max_tokens is None else int(max_tokens)

        last_err: Optional[Exception] = None
        for attempt in range(self.retries + 1):
            try:
                text, in_tok, out_tok = self._call(messages, temp, limit)
                usage = TokenUsage(
                    in_tokens=in_tok,
                    out_tokens=out_tok,
                    usd=self._cost(in_tok, out_tok),
                    calls=1,
                )
                return text, usage
            except Exception as exc:  # noqa: BLE001 - 统一收敛为 LLMError
                last_err = exc
                if attempt < self.retries:
                    time.sleep(min(8.0, 1.5 * (attempt + 1)))
        raise LLMError(f"[{tag or 'llm'}] 调用失败（{self._mode}）：{last_err}")

    def _call(self, messages: list[dict], temperature: float, max_tokens: int) -> tuple[str, int, int]:
        if self._sdk is not None:
            resp = self._sdk.chat.completions.create(
                model=self.model,
                messages=messages,
                temperature=temperature,
                max_tokens=max_tokens,
            )
            text = (resp.choices[0].message.content or "").strip()
            usage = getattr(resp, "usage", None)
            in_tok = int(getattr(usage, "prompt_tokens", 0) or 0)
            out_tok = int(getattr(usage, "completion_tokens", 0) or 0)
            return text, in_tok, out_tok

        # 退化路径：requests 直连
        import requests  # type: ignore

        url = (self.base_url or "https://api.openai.com/v1") + "/chat/completions"
        resp = requests.post(
            url,
            headers={"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"},
            json={
                "model": self.model,
                "messages": messages,
                "temperature": temperature,
                "max_tokens": max_tokens,
            },
            timeout=self.timeout_s,
        )
        resp.raise_for_status()
        data = resp.json()
        text = (data["choices"][0]["message"]["content"] or "").strip()
        usage = data.get("usage") or {}
        return text, int(usage.get("prompt_tokens", 0)), int(usage.get("completion_tokens", 0))


def strip_code_fence(text: str) -> str:
    """去掉 ```json / ``` 围栏（模型最常见的一处格式偏差）。"""
    body = (text or "").strip()
    if not body.startswith("```"):
        return body
    lines = body.splitlines()
    if len(lines) >= 2 and lines[0].startswith("```"):
        lines = lines[1:]
    if lines and lines[-1].strip().startswith("```"):
        lines = lines[:-1]
    return "\n".join(lines).strip()


def parse_json_object(text: str) -> dict:
    """从模型输出里抠出第一个 JSON 对象；失败抛 ``ValueError``。"""
    body = strip_code_fence(text)
    try:
        data = json.loads(body)
        if isinstance(data, dict):
            return data
    except Exception:
        pass
    start = body.find("{")
    end = body.rfind("}")
    if start >= 0 and end > start:
        data = json.loads(body[start : end + 1])
        if isinstance(data, dict):
            return data
    raise ValueError(f"模型输出不是 JSON 对象：{body[:200]!r}")


__all__ = ["OpenAICompatClient", "strip_code_fence", "parse_json_object", "DEFAULT_PRICES"]
