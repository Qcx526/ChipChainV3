"""Test-only tool binding on LangChain's official deterministic fake chat model."""

from collections.abc import Callable, Sequence
from itertools import repeat
from typing import Any

from langchain_core.callbacks import CallbackManagerForLLMRun
from langchain_core.language_models.fake_chat_models import GenericFakeChatModel
from langchain_core.messages import AIMessage, BaseMessage
from langchain_core.outputs import ChatResult
from langchain_core.tools import BaseTool
from pydantic import BaseModel, Field


class StructuredFakeChatModel(GenericFakeChatModel):
    seen_messages: list[list[BaseMessage]] = Field(default_factory=list)
    bound_schema_names: list[str] = Field(default_factory=list)
    failure: Exception | None = None

    def bind_tools(
        self, tools: Sequence[dict[str, Any] | type | Callable[..., Any] | BaseTool],
        *, tool_choice: str | None = None, **kwargs: Any,
    ) -> "StructuredFakeChatModel":
        # No parser override: inherited with_structured_output runs the real
        # LangChain PydanticToolsParser on the scripted AIMessage tool call.
        assert len(tools) == 1 and isinstance(tools[0], type)
        self.bound_schema_names.append(tools[0].__name__)
        return self

    def _generate(
        self, messages: list[BaseMessage], stop: list[str] | None = None,
        run_manager: CallbackManagerForLLMRun | None = None, **kwargs: Any,
    ) -> ChatResult:
        self.seen_messages.append(list(messages))
        if self.failure is not None:
            raise self.failure
        return super()._generate(messages, stop=stop, run_manager=run_manager, **kwargs)


def fake_model(
    schema: type[BaseModel], payload: BaseModel | dict[str, object] | AIMessage,
    *, failure: Exception | None = None,
) -> StructuredFakeChatModel:
    if isinstance(payload, AIMessage):
        message = payload
    else:
        args = payload.model_dump(mode="json") if isinstance(payload, BaseModel) else payload
        message = AIMessage(content="", tool_calls=[{
            "name": schema.__name__, "args": args, "id": "synthetic-response",
        }])
    return StructuredFakeChatModel(messages=repeat(message), failure=failure)
