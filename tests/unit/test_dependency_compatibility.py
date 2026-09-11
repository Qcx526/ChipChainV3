"""Public imports catch runtime mismatches that package metadata checks miss."""


def test_langchain_langgraph_public_imports() -> None:
    import langchain
    import langgraph
    from langchain.agents import create_agent
    from langchain_core.language_models import BaseChatModel
    from langgraph.graph import StateGraph

    assert langchain is not None and langgraph is not None
    assert callable(create_agent)
    assert callable(BaseChatModel.with_structured_output)
    assert callable(StateGraph)
