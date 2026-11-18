# Contributing

Thanks for helping. The most valuable contribution is a **bypass**: a tool call that should have been blocked or held and was allowed. Open a [Bypass or false negative](https://github.com/builditwithgk/agent-firebreak/issues/new?template=bypass_report.yml) issue with a fictional example (`attacker.example`), or send a failing test.

## Set up

```bash
git clone https://github.com/builditwithgk/agent-firebreak
cd agent-firebreak
python -m venv .venv && . .venv/bin/activate     # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
pytest -q
agent-firebreak bench     # must show 0 attacks landing with the guard on
```

## Guidelines

- The core stays **pure standard library** (it also runs in the browser through Pyodide). Please do not add runtime dependencies.
- Add a test for every behaviour change. Bypass fixes need a regression test (see `tests/test_hardening.py`).
- Keep `agent-firebreak bench` green: no attack may land with the guard on, and every normal task must still finish when the human approves.
- New scenarios live in `src/agent_firebreak/data/scenarios.json` (attack, limit or benign). Say in the scenario why it matters.
- Be honest about limits. If your change does not fully close a gap, say what remains in `README.md` under Limits.

## Pull requests

Small and focused is best. Describe what the change protects against or fixes, and how you tested it.
