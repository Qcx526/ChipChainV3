"""Provider-neutral execution descriptors; no credentials or framework objects."""

from enum import StrEnum
from typing import Self

from pydantic import Field, model_validator

from chipchain.domain.common import Contract, Identifier, Sha256


class AgentRole(StrEnum):
    HARDWARE = "hardware"
    FIRMWARE = "firmware"
    CROSS_LAYER = "cross_layer"


class PromptDescriptor(Contract):
    agent_role: AgentRole
    prompt_id: Identifier
    prompt_version: Identifier


class ModelDescriptor(Contract):
    agent_role: AgentRole
    model_identifier: Identifier = "unknown"
    provider_identifier: Identifier | None = None
    mode: Identifier = "unknown"


class ToolDescriptor(Contract):
    tool_name: Identifier
    tool_version: Identifier | None = None
    tool_role: Identifier
    configuration_sha256: Sha256 | None = None


class RunProvenance(Contract):
    package_identifier: Identifier = "chipchain"
    package_version: Identifier | None = None
    python_version: Identifier
    platform: Identifier
    runtime_packages: dict[Identifier, Identifier | None] = Field(default_factory=dict)
    prompts: list[PromptDescriptor] = Field(default_factory=list)
    models: list[ModelDescriptor] = Field(default_factory=list)
    tools: list[ToolDescriptor] = Field(default_factory=list)

    @model_validator(mode="after")
    def unique_agent_roles(self) -> Self:
        for descriptors in (self.prompts, self.models):
            roles = [item.agent_role for item in descriptors]
            if len(roles) != len(set(roles)):
                raise ValueError("Provenance requires at most one descriptor per agent role")
        return self
