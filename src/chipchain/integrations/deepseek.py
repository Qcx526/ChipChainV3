"""Small explicit configuration/factory for the official DeepSeek integration."""

import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path

from dotenv import dotenv_values
from langchain_core.globals import get_debug, get_verbose
from langchain_deepseek import ChatDeepSeek
from pydantic import SecretStr

from chipchain.domain.provenance import ModelDescriptor


class DeepSeekConfigurationError(ValueError):
    """Safe configuration error without values or credentials."""


@dataclass(frozen=True)
class DeepSeekConfig:
    api_key: SecretStr = field(repr=False)
    model: str = "deepseek-v4-pro"
    temperature: float = 0
    max_tokens: int = 8192
    timeout: float = 180

    def __post_init__(self) -> None:
        if not isinstance(self.api_key, SecretStr) or not self.api_key.get_secret_value().strip():
            raise DeepSeekConfigurationError("DEEPSEEK_API_KEY is required for an explicit real run")
        if (not re.fullmatch(r"deepseek-[a-z0-9]+(?:-[a-z0-9]+)*", self.model)
                or self.model in {"deepseek-chat", "deepseek-reasoner"}):
            raise DeepSeekConfigurationError("Configure a supported DeepSeek model identifier")
        if not 0 <= self.temperature <= 2 or not 1 <= self.max_tokens <= 32768 or not 0 < self.timeout <= 600:
            raise DeepSeekConfigurationError("Invalid generation limits")

    def descriptor(self) -> ModelDescriptor:
        return ModelDescriptor(agent_role="hardware", provider_identifier="deepseek",
                               model_identifier=self.model, mode="real")


def require_real_opt_in(enabled: bool) -> None:
    if enabled is not True:
        raise DeepSeekConfigurationError("Real calls require CHIPCHAIN_ENABLE_REAL_LLM=1 at the explicit run command")


def load_deepseek_config(environment: Mapping[str, str], *, env_file: Path | None = None) -> DeepSeekConfig:
    """Explicit read only; no os.environ mutation, discovery, or interpolation.

    Shell values override the selected file. The file never grants network opt-in.
    """
    values = {}
    if env_file is not None:
        if not env_file.is_file():
            raise DeepSeekConfigurationError("The explicitly selected environment file is missing")
        values = dotenv_values(env_file, interpolate=False)
    key = environment.get("DEEPSEEK_API_KEY", values.get("DEEPSEEK_API_KEY") or "")
    model = environment.get("CHIPCHAIN_HARDWARE_MODEL", values.get("CHIPCHAIN_HARDWARE_MODEL") or "deepseek-v4-pro")
    return DeepSeekConfig(api_key=SecretStr(key), model=model)


def build_deepseek_chat_model(config: DeepSeekConfig) -> ChatDeepSeek:
    """Construct only. Never invoke or create an alternative transport/provider."""
    if get_debug() or get_verbose():
        raise DeepSeekConfigurationError("Disable LangChain debug/verbose before a real run")
    try:
        return ChatDeepSeek(
            model=config.model, api_key=config.api_key, api_base="https://api.deepseek.com",
            temperature=config.temperature, max_tokens=config.max_tokens, timeout=config.timeout,
            max_retries=0, streaming=False, verbose=False,
            # Single structured function response, no thinking/tool execution loop.
            extra_body={"thinking": {"type": "disabled"}},
        )
    except Exception:
        raise DeepSeekConfigurationError("DeepSeek model construction failed") from None
