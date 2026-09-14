"""Thin LangChain structured invocation boundary; no provider or transport policy."""

import re
from json import JSONDecodeError
from typing import Generic, TypeVar

from langchain_core.language_models import BaseChatModel
from langchain_core.messages import AIMessage, HumanMessage, SystemMessage
from pydantic import BaseModel, ValidationError

Report = TypeVar("Report", bound=BaseModel)


class AgentExecutionError(RuntimeError):
    """Model setup/invocation or context construction failed."""


class AgentStructuredOutputError(AgentExecutionError):
    """The response could not satisfy the requested output contract."""

    def __init__(self, message: str, *, failure_category: str = "agent_post_validation") -> None:
        super().__init__(message)
        self.failure_category = failure_category


class StructuredReportRuntime(Generic[Report]):
    def __init__(self, model: BaseChatModel, schema: type[Report], system_prompt: str,
                 *, structured_output_method: str | None = None) -> None:
        self.schema = schema
        self.system_prompt = system_prompt
        self.last_usage: dict[str, int] = {}
        self.last_response_metadata: dict[str, str] = {}
        self.last_parse_stage: str | None = None
        try:
            options = {"method": structured_output_method} if structured_output_method is not None else {}
            self.runnable = model.with_structured_output(schema, include_raw=True, **options)
        except Exception as exc:
            raise AgentExecutionError("Model does not support the structured invocation setup") from exc

    def invoke(self, context: str) -> Report:
        self.last_usage = {}
        self.last_response_metadata = {}
        self.last_parse_stage = None
        try:
            result = self.runnable.invoke([
                SystemMessage(content=self.system_prompt), HumanMessage(content=context),
            ])
        except Exception as exc:
            # Do not copy provider exception text into public workflow errors.
            raise AgentExecutionError("Model invocation failed") from exc

        parse_stage = "unknown"
        try:
            if not isinstance(result, dict):
                raise ValueError("Expected LangChain include_raw result")
            raw = result.get("raw")
            if isinstance(raw, AIMessage) and raw.usage_metadata:
                # Allowlist scalar counters only; retain no raw message or provider metadata.
                self.last_usage = {key: raw.usage_metadata[key]
                                   for key in ("input_tokens", "output_tokens", "total_tokens")
                                   if type(raw.usage_metadata.get(key)) is int}
            if isinstance(raw, AIMessage):
                finish = raw.response_metadata.get("finish_reason")
                if finish is not None:
                    self.last_response_metadata["finish_reason"] = (
                        finish if isinstance(finish, str) and finish in
                        {"stop", "length", "tool_calls", "content_filter", "unknown"} else "unknown"
                    )
                for key in ("request_id", "id", "model_name", "model"):
                    value = raw.response_metadata.get(key)
                    if isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9_-]{1,128}", value):
                        self.last_response_metadata[key] = value
            error = result.get("parsing_error")
            if isinstance(raw, AIMessage) and raw.invalid_tool_calls:
                parse_stage = "malformed_tool_arguments"
            if isinstance(error, Exception):
                raise error
            if error is not None or result.get("parsed") is None:
                if error is None and parse_stage == "unknown":
                    parse_stage = "missing_structured_result"
                raise ValueError("Missing structured response")
            if isinstance(raw, AIMessage) and (raw.invalid_tool_calls or len(raw.tool_calls) > 1):
                raise ValueError("Invalid or ambiguous structured response tool calls")
            # Revalidate model instances as data, including nested constraints.
            parsed = result["parsed"]
            data = parsed.model_dump(warnings="error") if isinstance(parsed, BaseModel) else parsed
            return self.schema.model_validate(data)
        except Exception as exc:
            if isinstance(exc, ValidationError):
                parse_stage = "pydantic_validation"
            elif isinstance(exc, JSONDecodeError):
                parse_stage = "malformed_tool_arguments"
            self.last_parse_stage = parse_stage
            raise AgentStructuredOutputError("Model response failed structured-output validation",
                                             failure_category="structured_output_parsing") from exc


Output = TypeVar("Output", bound=BaseModel)


def validate_agent_output(schema: type[Output], **fields: object) -> Output:
    """Validate report/IR assembly without leaking response contents in errors."""
    try:
        return schema.model_validate(fields)
    except ValidationError as exc:
        raise AgentStructuredOutputError("Model response failed the Agent output contract") from exc
