"""Command line: list scenarios, run one, run the benchmark, print the policy, verify an audit log."""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

from agent_firebreak import __version__
from agent_firebreak.agents.obedient import ObedientAgent
from agent_firebreak.audit import AuditLog
from agent_firebreak.bench import format_table, run_bench
from agent_firebreak.policy import Policy
from agent_firebreak.runner import RunResult, run_scenario
from agent_firebreak.scenarios import get_scenario, load_scenarios


def _policy(path: str | None) -> Policy | None:
    if not path:
        return None
    text = Path(path).read_text(encoding="utf-8")
    return Policy.from_json(text) if path.endswith(".json") else Policy.from_toml(text)


def _print_run(result: RunResult) -> None:
    for e in result.trace:
        d = e["decision"]
        verdict = "no guard" if d is None else d["effect"].upper()
        suffix = ""
        if e["approved"] is not None:
            suffix = " -> approved" if e["approved"] else " -> denied"
        mark = " [injected]" if e["injected"] else ""
        print(f"  {e['step'] + 1}. {e['tool']}({json.dumps(e['args'], ensure_ascii=False)[:90]}){mark}")
        print(f"     {verdict}{suffix}" + (f": {d['reason']}" if d and d["effect"] != "allow" else ""))
    print(f"  outcome: {result.outcome}" + (" (the attack's goal was reached)" if result.landed else ""))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="agent-firebreak", description=__doc__)
    parser.add_argument("--version", action="version", version=f"agent-firebreak {__version__}")
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("scenarios", help="list the built-in scenarios")
    run = sub.add_parser("run", help="run one scenario")
    run.add_argument("scenario")
    run.add_argument("--no-guard", action="store_true")
    run.add_argument("--approve", action="store_true", help="a human approves every 'ask'")
    run.add_argument("--policy")
    run.add_argument("--audit-log", help="write the hash-chained audit log here")
    bench = sub.add_parser("bench", help="run every scenario with the guard off and on")
    bench.add_argument("--policy")
    bench.add_argument("--no-detectors", action="store_true")
    bench.add_argument("--json", action="store_true")
    sub.add_parser("policy", help="print the default policy")
    verify = sub.add_parser("verify-log", help="check an audit log's hash chain")
    verify.add_argument("path")
    args = parser.parse_args(argv)

    if args.cmd == "scenarios":
        for s in load_scenarios():
            print(f"{s.id:26} {s.kind:7} {s.title}")
        return 0
    if args.cmd == "policy":
        from agent_firebreak.policy import DEFAULT_POLICY_TOML
        print(DEFAULT_POLICY_TOML)
        return 0
    if args.cmd == "verify-log":
        ok, bad = AuditLog.verify_entries(AuditLog.from_jsonl(Path(args.path).read_text(encoding="utf-8")).entries)
        print("audit log intact" if ok else f"audit log TAMPERED at entry {bad}")
        return 0 if ok else 1
    if args.cmd == "run":
        try:
            scenario = get_scenario(args.scenario)
        except KeyError:
            print(f"No scenario {args.scenario!r}. Try: agent-firebreak scenarios", file=sys.stderr)
            return 2
        result = asyncio.run(run_scenario(scenario, ObedientAgent(), guard_on=not args.no_guard,
                                          approver="approve" if args.approve else "deny",
                                          policy=_policy(args.policy)))
        print(f"{scenario.id}: {scenario.title}\nTask: {scenario.user_task}")
        _print_run(result)
        if args.audit_log and result.audit:
            Path(args.audit_log).write_text(result.audit.to_jsonl(), encoding="utf-8")
        return 0
    scenarios = load_scenarios()
    out = asyncio.run(run_bench(scenarios, policy=_policy(args.policy), detectors=not args.no_detectors))
    if args.json:
        print(json.dumps({"summary": out["summary"],
                          "runs": {sid: {m: r.to_dict() for m, r in modes.items()} for sid, modes in out["runs"].items()}},
                         indent=2, ensure_ascii=False))
    else:
        print(format_table(out, scenarios))
    m = out["summary"]
    regressed = m["attacks_landed"]["on_deny"] or m["attacks_landed"]["on_approve"]         or m["benign_completed"]["on_approve"] != m["benign"]
    return 1 if regressed else 0  # CI fails if an attack lands or a normal task breaks


if __name__ == "__main__":
    raise SystemExit(main())
