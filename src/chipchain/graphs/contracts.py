"""Bounded graph contexts keep agents independent of future graph backends."""

from typing import Protocol

from pydantic import Field

from chipchain.domain.common import Contract, Identifier
from chipchain.domain.evidence import EvidenceRef


class BehaviorGraphContext(Contract):
    graph_id: Identifier
    case_id: Identifier
    processor_behavior_ids: list[Identifier] = Field(default_factory=list, max_length=256)
    summary: str | None = Field(default=None, max_length=8000)


class RetrievedKnowledgeContext(Contract):
    retrieval_id: Identifier
    knowledge_graph_id: Identifier
    node_ids: list[Identifier] = Field(default_factory=list, max_length=256)
    evidence: list[EvidenceRef] = Field(default_factory=list, max_length=256)
    summary: str | None = Field(default=None, max_length=8000)


class CrossLayerBehaviorGraph(Protocol):
    def context_for(
        self, *, case_id: str, processor_behavior_ids: list[str]
    ) -> BehaviorGraphContext: ...


class VulnerabilityKnowledgeGraph(Protocol):
    def retrieve(self, *, query: str, limit: int = 20) -> RetrievedKnowledgeContext: ...
