"""Thin LangChain structured invocation boundary; no provider or transport policy."""

from typing import Generic, TypeVar

from langchain_core.language_models import BaseChatModel
from langchain_core.messages import AIMessage, HumanMessage, SystemMessage
from pydantic import BaseModel, ValidationError

Report = TypeVar("Report", bound=BaseModel)


class AgentExecutionError(RuntimeError):
    """Model setup/invocation or context construction failed."""


class AgentStructuredOutputError(AgentExecutionError):
    """The response could not satisfy the requested output contract."""


class StructuredReportRuntime(Generic[Report]):
    def __init__(self, model: BaseChatModel, schema: type[Report], system_prompt: str) -> None:
        self.schema = schema
        self.system_prompt = system_prompt
        try:
            self.runnable = model.with_structured_output(schema, include_raw=True)
        except Exception as exc:
            raise AgentExecutionError("Model does not support the structured invocation setup") from exc

    def invoke(self, context: str) -> Report:
        try:
            result = self.runnable.invoke([
                SystemMessage(content=self.system_prompt), HumanMessage(content=context),
            ])
        except Exception as exc:
            # Do not copy provider exception text into public workflow errors.
            raise AgentExecutionError("Model invocation failed") from exc

        try:
            if not isinstance(result, dict):
                raise ValueError("Expected LangChain include_raw result")
            error = result.get("parsing_error")
            if isinstance(error, Exception):
                raise error
            if error is not None or result.get("parsed") is None:
                raise ValueError("Missing structured response")
            raw = result.get("raw")
            if isinstance(raw, AIMessage) and (raw.invalid_tool_calls or len(raw.tool_calls) > 1):
                raise ValueError("Invalid or ambiguous structured response tool calls")
            # Revalidate model instances as data, including nested constraints.
            parsed = result["parsed"]
            data = parsed.model_dump(warnings="error") if isinstance(parsed, BaseModel) else parsed
            return self.schema.model_validate(data)
        except Exception as exc:
            raise AgentStructuredOutputError("Model response failed structured-output validation") from exc


Output = TypeVar("Output", bound=BaseModel)


def validate_agent_output(schema: type[Output], **fields: object) -> Output:
    """Validate report/IR assembly without leaking response contents in errors."""
    try:
        return schema.model_validate(fields)
    except ValidationError as exc:
        raise AgentStructuredOutputError("Model response failed the Agent output contract") from exc
