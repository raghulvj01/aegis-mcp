"""Telegram bot bridge to test and invoke tools on an MCP server.

Environment variables:
    TELEGRAM_BOT_TOKEN        Required Telegram bot token from BotFather.
    MCP_SERVER_URL            MCP streamable HTTP URL (default: http://127.0.0.1:8000/mcp).
    MCP_HEALTH_URL            Optional health endpoint URL. If unset, derived from MCP_SERVER_URL.
    MCP_HTTP_AUTH_BEARER      Optional HTTP bearer token sent in Authorization header.
    MCP_TOOL_TOKEN            Optional MCP tool token argument injected as "token" when absent.
    TELEGRAM_ALLOWED_CHAT_IDS Optional comma-separated list of numeric chat IDs allowed to use the bot.
    MISTRAL_API_KEY           Optional Mistral key for /ask AI command.
    MISTRAL_MODEL             Optional model name (default: mistral-small-latest).
    MISTRAL_API_BASE_URL      Optional base URL (default: https://api.mistral.ai/v1).
"""
from __future__ import annotations

import json
import logging
import os
import re
from dataclasses import dataclass
from typing import Any

import requests
from mcp.client.session import ClientSession
from mcp.client.streamable_http import streamablehttp_client
from telegram import Update
from telegram.ext import Application, CommandHandler, ContextTypes


MAX_TELEGRAM_MESSAGE_LEN = 3900


@dataclass(frozen=True)
class BotConfig:
    telegram_bot_token: str
    mcp_server_url: str
    mcp_health_url: str
    mcp_http_auth_bearer: str | None
    mcp_tool_token: str | None
    allowed_chat_ids: set[int] | None
    mcp_timeout_seconds: float
    mcp_sse_timeout_seconds: float
    mistral_api_key: str | None
    mistral_model: str
    mistral_base_url: str

    @staticmethod
    def from_env() -> "BotConfig":
        token = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
        if not token:
            raise RuntimeError("TELEGRAM_BOT_TOKEN is required.")

        mcp_server_url = os.getenv("MCP_SERVER_URL", "http://127.0.0.1:8000/mcp").strip()
        mcp_health_url = os.getenv("MCP_HEALTH_URL", _derive_health_url(mcp_server_url)).strip()
        mcp_http_auth_bearer = os.getenv("MCP_HTTP_AUTH_BEARER", "").strip() or None
        mcp_tool_token = os.getenv("MCP_TOOL_TOKEN", "").strip() or None

        raw_chat_ids = os.getenv("TELEGRAM_ALLOWED_CHAT_IDS", "").strip()
        allowed_chat_ids: set[int] | None = None
        if raw_chat_ids:
            try:
                allowed_chat_ids = {int(v.strip()) for v in raw_chat_ids.split(",") if v.strip()}
            except ValueError as exc:
                raise RuntimeError("TELEGRAM_ALLOWED_CHAT_IDS must be comma-separated integers.") from exc

        timeout_seconds = float(os.getenv("MCP_HTTP_TIMEOUT_SECONDS", "30"))
        sse_timeout_seconds = float(os.getenv("MCP_SSE_TIMEOUT_SECONDS", "300"))
        mistral_api_key = os.getenv("MISTRAL_API_KEY", "").strip() or None
        mistral_model = os.getenv("MISTRAL_MODEL", "mistral-small-latest").strip()
        mistral_base_url = os.getenv("MISTRAL_API_BASE_URL", "https://api.mistral.ai/v1").strip()

        return BotConfig(
            telegram_bot_token=token,
            mcp_server_url=mcp_server_url,
            mcp_health_url=mcp_health_url,
            mcp_http_auth_bearer=mcp_http_auth_bearer,
            mcp_tool_token=mcp_tool_token,
            allowed_chat_ids=allowed_chat_ids,
            mcp_timeout_seconds=timeout_seconds,
            mcp_sse_timeout_seconds=sse_timeout_seconds,
            mistral_api_key=mistral_api_key,
            mistral_model=mistral_model,
            mistral_base_url=mistral_base_url,
        )


@dataclass
class BridgeState:
    config: BotConfig

    def _headers(self) -> dict[str, str] | None:
        if not self.config.mcp_http_auth_bearer:
            return None
        return {"Authorization": f"Bearer {self.config.mcp_http_auth_bearer}"}

    async def list_tools(self) -> list[dict[str, Any]]:
        async with streamablehttp_client(
            url=self.config.mcp_server_url,
            headers=self._headers(),
            timeout=self.config.mcp_timeout_seconds,
            sse_read_timeout=self.config.mcp_sse_timeout_seconds,
        ) as (read_stream, write_stream, _get_session_id):
            async with ClientSession(read_stream, write_stream) as session:
                await session.initialize()
                result = await session.list_tools()
                return [_to_jsonable(tool) for tool in result.tools]

    async def call_tool(self, tool_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        payload = dict(arguments)
        if self.config.mcp_tool_token and "token" not in payload:
            payload["token"] = self.config.mcp_tool_token

        async with streamablehttp_client(
            url=self.config.mcp_server_url,
            headers=self._headers(),
            timeout=self.config.mcp_timeout_seconds,
            sse_read_timeout=self.config.mcp_sse_timeout_seconds,
        ) as (read_stream, write_stream, _get_session_id):
            async with ClientSession(read_stream, write_stream) as session:
                await session.initialize()
                result = await session.call_tool(name=tool_name, arguments=payload)
                return _to_jsonable(result)

    def health(self) -> dict[str, Any]:
        response = requests.get(self.config.mcp_health_url, timeout=10)
        response.raise_for_status()
        try:
            return response.json()
        except requests.JSONDecodeError:
            return {"status_code": response.status_code, "body": response.text}

    def _mistral_chat(self, messages: list[dict[str, str]], temperature: float = 0.1, max_tokens: int = 800) -> str:
        if not self.config.mistral_api_key:
            raise RuntimeError("MISTRAL_API_KEY is not configured. Set it to use /ask.")

        base_url = self.config.mistral_base_url.rstrip("/")
        response = requests.post(
            f"{base_url}/chat/completions",
            headers={
                "Authorization": f"Bearer {self.config.mistral_api_key}",
                "Content-Type": "application/json",
            },
            json={
                "model": self.config.mistral_model,
                "temperature": temperature,
                "max_tokens": max_tokens,
                "messages": messages,
            },
            timeout=30,
        )
        response.raise_for_status()
        payload = response.json()

        choices = payload.get("choices", [])
        if not choices:
            raise RuntimeError("Mistral returned no choices.")

        content = choices[0].get("message", {}).get("content", "")
        if isinstance(content, list):
            parts: list[str] = []
            for item in content:
                if isinstance(item, dict):
                    parts.append(str(item.get("text", "")))
                else:
                    parts.append(str(item))
            return "".join(parts).strip()
        return str(content).strip()

    async def ask(self, question: str) -> dict[str, Any]:
        tools = await self.list_tools()
        tool_names = {str(t.get("name", "")) for t in tools}
        tool_catalog = _build_tool_catalog(tools)

        planner_messages = [
            {
                "role": "system",
                "content": (
                    "You are a DevSecOps MCP assistant planner. "
                    "Return only one compact JSON object with this exact shape: "
                    "{\"action\":\"answer\"|\"tool_call\",\"answer\":\"...\",\"tool_name\":\"...\",\"arguments\":{}}. "
                    "Use action=tool_call only when real MCP data is needed. "
                    "For tool_call, tool_name must exactly match a listed tool and arguments must be a JSON object."
                ),
            },
            {
                "role": "user",
                "content": (
                    f"User question:\n{question}\n\n"
                    f"Available MCP tools:\n{tool_catalog}\n\n"
                    "Now return the JSON plan."
                ),
            },
        ]

        plan_raw = self._mistral_chat(planner_messages, temperature=0.0, max_tokens=600)
        plan = _extract_json_object(plan_raw)
        action = str(plan.get("action", "answer")).strip().lower()

        if action != "tool_call":
            answer = str(plan.get("answer", "")).strip()
            if not answer:
                answer = "I could not generate an answer."
            return {"action": "answer", "answer": answer}

        tool_name = str(plan.get("tool_name", "")).strip()
        arguments = plan.get("arguments", {})
        if tool_name not in tool_names:
            return {
                "action": "answer",
                "answer": f"Requested tool '{tool_name}' is not available on this MCP server.",
            }
        if not isinstance(arguments, dict):
            arguments = {}

        tool_result = await self.call_tool(tool_name, arguments)
        tool_result_clip = _truncate_text(_format_json(tool_result), 6000)

        summarizer_messages = [
            {
                "role": "system",
                "content": (
                    "You are a concise DevSecOps assistant. "
                    "Summarize MCP tool output for an operator. "
                    "Provide: what was checked, key findings, and next action."
                ),
            },
            {
                "role": "user",
                "content": (
                    f"Question: {question}\n"
                    f"Tool: {tool_name}\n"
                    f"Arguments: {_format_json(arguments)}\n"
                    f"Tool result JSON:\n{tool_result_clip}"
                ),
            },
        ]
        summary = self._mistral_chat(summarizer_messages, temperature=0.2, max_tokens=450)
        if not summary:
            summary = "Tool executed successfully, but summary generation returned empty output."

        return {
            "action": "tool_call",
            "tool_name": tool_name,
            "arguments": arguments,
            "answer": summary,
            "tool_result": tool_result,
        }


def _derive_health_url(mcp_server_url: str) -> str:
    url = mcp_server_url.rstrip("/")
    if url.endswith("/mcp"):
        return f"{url[:-4]}/health"
    return f"{url}/health"


def _to_jsonable(value: Any) -> Any:
    if hasattr(value, "model_dump"):
        return value.model_dump(mode="json", exclude_none=True)
    if isinstance(value, dict):
        return {k: _to_jsonable(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_to_jsonable(v) for v in value]
    return value


def _split_chunks(text: str, max_len: int = MAX_TELEGRAM_MESSAGE_LEN) -> list[str]:
    if len(text) <= max_len:
        return [text]

    chunks: list[str] = []
    start = 0
    while start < len(text):
        end = min(start + max_len, len(text))
        split_at = text.rfind("\n", start, end)
        if split_at <= start:
            split_at = end
        chunks.append(text[start:split_at].strip())
        start = split_at
    return [c for c in chunks if c]


def _format_json(data: Any) -> str:
    return json.dumps(data, indent=2, ensure_ascii=False, default=str)


def _truncate_text(text: str, max_chars: int) -> str:
    if len(text) <= max_chars:
        return text
    return text[: max_chars - 3] + "..."


def _extract_json_object(text: str) -> dict[str, Any]:
    stripped = text.strip()
    try:
        parsed = json.loads(stripped)
        if isinstance(parsed, dict):
            return parsed
    except json.JSONDecodeError:
        pass

    match = re.search(r"\{[\s\S]*\}", stripped)
    if not match:
        raise RuntimeError(f"Failed to parse JSON from model output: {stripped[:200]}")

    candidate = match.group(0)
    try:
        parsed = json.loads(candidate)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"Failed to parse JSON from model output: {candidate[:200]}") from exc
    if not isinstance(parsed, dict):
        raise RuntimeError("Model JSON output is not an object.")
    return parsed


def _build_tool_catalog(tools: list[dict[str, Any]]) -> str:
    lines: list[str] = []
    for tool in tools:
        name = str(tool.get("name", ""))
        description = str(tool.get("description", "") or "No description")
        input_schema = tool.get("inputSchema", {}) if isinstance(tool, dict) else {}
        properties = input_schema.get("properties", {}) if isinstance(input_schema, dict) else {}
        required = input_schema.get("required", []) if isinstance(input_schema, dict) else []
        if isinstance(required, list):
            required_args = [str(arg) for arg in required]
        else:
            required_args = []

        arg_names = sorted(str(arg) for arg in properties.keys()) if isinstance(properties, dict) else []
        lines.append(
            f"- {name}: {description} | args={arg_names or []} | required={required_args or []}"
        )
    return "\n".join(lines)


def _parse_call_command(text: str) -> tuple[str, dict[str, Any]]:
    parts = text.split(maxsplit=2)
    if len(parts) < 2:
        raise ValueError("Usage: /call <tool_name> [json_arguments]")

    tool_name = parts[1].strip()
    if not tool_name:
        raise ValueError("Tool name is required. Example: /call security_check_ssl_certificate {\"hostname\":\"example.com\"}")

    raw_json = parts[2].strip() if len(parts) > 2 else "{}"
    try:
        parsed = json.loads(raw_json)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid JSON arguments: {exc}") from exc

    if not isinstance(parsed, dict):
        raise ValueError("JSON arguments must be an object. Example: {\"hostname\":\"example.com\"}")
    return tool_name, parsed


def _parse_ask_command(text: str) -> str:
    parts = text.split(maxsplit=1)
    if len(parts) < 2 or not parts[1].strip():
        raise ValueError("Usage: /ask <question>")
    return parts[1].strip()


def _usage_text() -> str:
    return (
        "Aegis MCP Telegram Bot\n"
        "\n"
        "Commands:\n"
        "/health - Check MCP health endpoint\n"
        "/tools - List MCP tools\n"
        "/call <tool_name> [json_arguments] - Invoke a tool\n"
        "/ask <question> - Use Mistral AI to choose and run an MCP tool\n"
        "\n"
        "Examples:\n"
        "/call security_check_ssl_certificate {\"hostname\":\"example.com\"}\n"
        "/call git_recent_commits {\"limit\":5}\n"
        "/call k8s_list_pods {\"namespace\":\"default\"}\n"
        "/ask check ssl cert status for example.com"
    )


def _bridge(context: ContextTypes.DEFAULT_TYPE) -> BridgeState:
    return context.application.bot_data["bridge_state"]


async def _ensure_allowed_chat(update: Update, context: ContextTypes.DEFAULT_TYPE) -> bool:
    bridge = _bridge(context)
    allowed = bridge.config.allowed_chat_ids
    chat_id = update.effective_chat.id if update.effective_chat else None

    if not allowed or chat_id is None:
        return True

    if chat_id in allowed:
        return True

    if update.message:
        await update.message.reply_text("This chat is not allowed for this bot.")
    return False


async def start_handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not await _ensure_allowed_chat(update, context):
        return
    if update.message:
        await update.message.reply_text(_usage_text())


async def help_handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await start_handler(update, context)


async def health_handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not await _ensure_allowed_chat(update, context):
        return
    if not update.message:
        return

    bridge = _bridge(context)
    try:
        result = bridge.health()
        await update.message.reply_text(_format_json(result))
    except Exception as exc:  # noqa: BLE001
        logging.exception("Health check failed")
        await update.message.reply_text(f"Health check failed: {exc}")


async def tools_handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not await _ensure_allowed_chat(update, context):
        return
    if not update.message:
        return

    bridge = _bridge(context)
    try:
        tools = await bridge.list_tools()
        if not tools:
            await update.message.reply_text("No tools exposed by MCP server.")
            return

        lines = []
        for tool in tools:
            name = tool.get("name", "<unknown>")
            description = tool.get("description", "") or "No description"
            lines.append(f"- {name}: {description}")

        text = "Available MCP tools:\n" + "\n".join(lines)
        for chunk in _split_chunks(text):
            await update.message.reply_text(chunk)
    except Exception as exc:  # noqa: BLE001
        logging.exception("Failed to list tools")
        await update.message.reply_text(f"Failed to list tools: {exc}")


async def call_handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not await _ensure_allowed_chat(update, context):
        return
    if not update.message or not update.message.text:
        return

    bridge = _bridge(context)

    try:
        tool_name, tool_args = _parse_call_command(update.message.text)
    except ValueError as exc:
        await update.message.reply_text(str(exc))
        return

    await update.message.reply_text(f"Running tool '{tool_name}'...")

    try:
        result = await bridge.call_tool(tool_name, tool_args)
        output = _format_json(result)
        for chunk in _split_chunks(output):
            await update.message.reply_text(chunk)
    except Exception as exc:  # noqa: BLE001
        logging.exception("Tool invocation failed for %s", tool_name)
        await update.message.reply_text(f"Tool invocation failed: {exc}")


async def ask_handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not await _ensure_allowed_chat(update, context):
        return
    if not update.message or not update.message.text:
        return

    bridge = _bridge(context)
    try:
        question = _parse_ask_command(update.message.text)
    except ValueError as exc:
        await update.message.reply_text(str(exc))
        return

    await update.message.reply_text("Thinking and checking MCP tools...")
    try:
        answer = await bridge.ask(question)
        if answer.get("action") == "tool_call":
            header = (
                f"Tool used: {answer.get('tool_name')}\n"
                f"Args: {_format_json(answer.get('arguments', {}))}\n\n"
            )
            text = header + str(answer.get("answer", ""))
        else:
            text = str(answer.get("answer", ""))

        for chunk in _split_chunks(text):
            await update.message.reply_text(chunk)
    except Exception as exc:  # noqa: BLE001
        logging.exception("AI ask flow failed")
        await update.message.reply_text(f"/ask failed: {exc}")


async def error_handler(_update: object, context: ContextTypes.DEFAULT_TYPE) -> None:
    logging.exception("Telegram application error", exc_info=context.error)


def main() -> None:
    logging.basicConfig(
        level=os.getenv("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )

    config = BotConfig.from_env()
    app = Application.builder().token(config.telegram_bot_token).build()
    app.bot_data["bridge_state"] = BridgeState(config=config)

    app.add_handler(CommandHandler("start", start_handler))
    app.add_handler(CommandHandler("help", help_handler))
    app.add_handler(CommandHandler("health", health_handler))
    app.add_handler(CommandHandler("tools", tools_handler))
    app.add_handler(CommandHandler("call", call_handler))
    app.add_handler(CommandHandler("ask", ask_handler))
    app.add_error_handler(error_handler)

    app.run_polling(allowed_updates=Update.ALL_TYPES)


if __name__ == "__main__":
    main()
