from __future__ import annotations

from functools import wraps
from time import perf_counter
from typing import Any, Callable

from server.logging import get_logger

logger = get_logger("mcp.aegis.audit")



def audit_tool_call(tool_name: str) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Decorator that emits structured audit records for every tool invocation."""

    def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
        @wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            started = perf_counter()
            logger.info(
                "tool_call_started",
                extra={
                    "extra_payload": {
                        "event": "tool_call_started",
                        "tool": tool_name,
                        "args": str(args),
                        "kwargs": kwargs,
                    }
                },
            )
            try:
                result = func(*args, **kwargs)
                duration_ms = int((perf_counter() - started) * 1000)
                logger.info(
                    "tool_call_succeeded",
                    extra={
                        "extra_payload": {
                            "event": "tool_call_succeeded",
                            "tool": tool_name,
                            "duration_ms": duration_ms,
                        }
                    },
                )
                return result
            except Exception as exc:  # noqa: BLE001
                duration_ms = int((perf_counter() - started) * 1000)
                logger.error(
                    "tool_call_failed",
                    extra={
                        "extra_payload": {
                            "event": "tool_call_failed",
                            "tool": tool_name,
                            "duration_ms": duration_ms,
                            "error": str(exc),
                        }
                    },
                )
                raise

        return wrapper

    return decorator
