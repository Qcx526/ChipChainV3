"""Synthetic fixtures and a suite-wide offline execution boundary."""

import os
import socket
import subprocess
from collections.abc import Iterator

import pytest

# Set before importing any workflow: ambient tracing must not create network traffic.
os.environ["LANGSMITH_TRACING"] = "false"
os.environ["LANGCHAIN_TRACING_V2"] = "false"
os.environ["LANGCHAIN_TRACING"] = "false"


@pytest.fixture(autouse=True)
def offline_only(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    def forbidden(*args: object, **kwargs: object) -> None:
        raise AssertionError("Tests must not access the network or start external tools")

    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket.socket, "connect_ex", forbidden)
    monkeypatch.setattr(socket.socket, "sendto", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(os, "system", forbidden)
    for name in ("OPENAI_API_KEY", "ANTHROPIC_API_KEY", "QWEN_API_KEY", "DASHSCOPE_API_KEY", "LANGSMITH_API_KEY",
                 "DEEPSEEK_API_KEY", "CHIPCHAIN_ENABLE_REAL_LLM"):
        monkeypatch.delenv(name, raising=False)
    yield
