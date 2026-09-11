"""Explicit descriptors plus a small Python-API dependency snapshot."""

from collections.abc import Sequence
from importlib import metadata
import platform

from chipchain.domain.provenance import AgentRole, ModelDescriptor, PromptDescriptor, RunProvenance, ToolDescriptor

RUNTIME_PACKAGES = ("pydantic", "langchain", "langchain-core", "langgraph", "langgraph-prebuilt")


def _version(package: str) -> str | None:
    try:
        return metadata.version(package)
    except metadata.PackageNotFoundError:
        return None


def capture_provenance(
    *, prompts: Sequence[PromptDescriptor] = (), models: Sequence[ModelDescriptor] = (),
    tools: Sequence[ToolDescriptor] = (),
) -> RunProvenance:
    """Never inspect model objects, environment variables, credentials or tool configs."""
    supplied_roles = {model.agent_role for model in models}
    return RunProvenance(
        package_version=_version("chipchain"), python_version=platform.python_version(),
        platform=f"{platform.system()}/{platform.machine()}",
        runtime_packages={package: _version(package) for package in RUNTIME_PACKAGES},
        prompts=list(prompts),
        models=[*models, *(ModelDescriptor(agent_role=role) for role in AgentRole if role not in supplied_roles)],
        tools=list(tools),
    ).model_copy(deep=True)


def stub_provenance() -> RunProvenance:
    # Descriptors describe configured components; stage records say what ran.
    # Stub agents do not invoke prompts or models.
    return capture_provenance(
        models=[ModelDescriptor(agent_role=role, model_identifier="stub", mode="stub") for role in AgentRole],
        tools=[ToolDescriptor(tool_name=f"{role}-observation-stub", tool_version="r0", tool_role=role)
               for role in ("hardware", "firmware")],
    )
