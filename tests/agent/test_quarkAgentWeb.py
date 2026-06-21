import importlib
import sys
from unittest.mock import MagicMock, patch

import pytest
from langchain_core.messages import AIMessage, HumanMessage


@pytest.fixture
def quarkAgentWebModule():
    sys.modules.pop("quark.agent.quarkAgentWeb", None)

    with patch("langchain_openai.ChatOpenAI"), patch(
        "langchain.agents.create_agent"
    ) as mockCreateAgent:
        mockAgentExecutor = MagicMock()
        mockCreateAgent.return_value = mockAgentExecutor
        module = importlib.import_module("quark.agent.quarkAgentWeb")
        yield module, mockAgentExecutor

    sys.modules.pop("quark.agent.quarkAgentWeb", None)


def testGetResponseReturnsAgentReply(quarkAgentWebModule):
    module, mockAgentExecutor = quarkAgentWebModule
    mockAgentExecutor.invoke.return_value = {
        "messages": [AIMessage(content="Hello from agent")]
    }

    client = module.app.test_client()
    response = client.get("/get_response", query_string={"message": "hi"})

    assert response.status_code == 200
    assert response.get_json()["plain_text"] == "Hello from agent"

    mockAgentExecutor.invoke.assert_called_once()
    # conversation_history is the same list object passed to invoke() and
    # mutated afterwards, so check membership rather than indexing it
    # after the fact.
    assert HumanMessage(content="hi") in module.conversation_history
    assert AIMessage(content="Hello from agent") in module.conversation_history
    assert module.conversation_history[-1] == "Hello from agent"
