"""Run every scenario with the guard off, on (human denies) and on (human approves), and summarise."""

from __future__ import annotations

from typing import Any, Callable

from agent_firebreak.agents.obedient import ObedientAgent
from agent_firebreak.policy import Policy
from agent_firebreak.runner import RunResult, run_scenario
from agent_firebreak.scenarios import Scenario, load_scenarios

MODES = (("off", False, "deny"), ("on_deny", True, "deny"), ("on_approve", True, "approve"))


async def run_bench(scenarios: list[Scenario] | None = None, *, policy: Policy | None = None,
                    detectors: bool = True, agent_factory: Callable[[], Any] = ObedientAgent) -> dict[str, Any]:
    scenarios = scenarios or load_scenarios()
    runs: dict[str, dict[str, RunResult]] = {}
    for s in scenarios:
        runs[s.id] = {}
        for mode, guard_on, approver in MODES:
            runs[s.id][mode] = await run_scenario(s, agent_factory(), guard_on=guard_on, approver=approver,
                                                  policy=policy, detectors=detectors)
    return {"runs": runs, "summary": summarise(scenarios, runs)}


def summarise(scenarios: list[Scenario], runs: dict[str, dict[str, RunResult]]) -> dict[str, Any]:
    attacks = [s for s in scenarios if s.kind == "attack"]
    benign = [s for s in scenarios if s.kind == "benign"]
    limits = [s for s in scenarios if s.kind == "limit"]

    def landed(mode: str, group: list[Scenario]) -> int:
        return sum(runs[s.id][mode].landed for s in group)

    def done(mode: str) -> int:
        return sum(runs[s.id][mode].completed for s in benign)

    asks = {m: sum(runs[s.id][m].asks for s in benign) for m in ("on_deny", "on_approve")}
    guard_ms = [r.ms / max(1, len(r.trace)) for s in scenarios for m in ("on_deny", "on_approve")
                for r in [runs[s.id][m]] if r.trace]
    return {
        "attacks": len(attacks), "benign": len(benign), "limits": len(limits),
        "attacks_landed": {m: landed(m, attacks) for m in ("off", "on_deny", "on_approve")},
        "limits_landed": {m: landed(m, limits) for m in ("off", "on_deny", "on_approve")},
        "benign_completed": {m: done(m) for m in ("off", "on_deny", "on_approve")},
        "benign_asks": asks,
        "avg_guard_ms_per_call": round(sum(guard_ms) / len(guard_ms), 3) if guard_ms else 0.0,
    }


def format_table(bench: dict[str, Any], scenarios: list[Scenario]) -> str:
    rows = [f"{'scenario':26} {'guard off':14} {'on, deny':14} {'on, approve':14}"]
    for s in scenarios:
        cells = []
        for mode, _, _ in MODES:
            r = bench["runs"][s.id][mode]
            tag = r.outcome if s.is_attack else ("done" if r.completed else "NOT DONE")
            cells.append(f"{tag} ({r.asks} ask)" if r.asks else tag)
        rows.append(f"{s.id:26} {cells[0]:14} {cells[1]:14} {cells[2]:14}")
    m = bench["summary"]
    rows += ["", f"Attacks landed (of {m['attacks']}):   off {m['attacks_landed']['off']}, "
                 f"guard on {m['attacks_landed']['on_deny']} (human denies), "
                 f"{m['attacks_landed']['on_approve']} (human approves)",
             f"Normal tasks done (of {m['benign']}): off {m['benign_completed']['off']}, "
             f"guard on {m['benign_completed']['on_deny']} (deny), {m['benign_completed']['on_approve']} (approve)",
             f"Approval prompts on normal tasks: {m['benign_asks']['on_approve']}",
             f"Guard time per call: {m['avg_guard_ms_per_call']} ms"]
    return "\n".join(rows)
