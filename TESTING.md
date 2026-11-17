# Help test agent-firebreak (about 10 minutes)

Thanks for trying it. agent-firebreak is new, and the most useful thing you can give is an honest first impression: where you got stuck, and what you would have expected instead. You do not need an API key or an agent of your own for steps 1 and 2.

## 1. See it work (2 minutes)

```bash
pip install agent-firebreak
agent-firebreak bench
```

You should see a table of 18 scenarios and a summary like "Attacks landed (of 8): off 8, guard on 0". Then watch one attack step by step:

```bash
agent-firebreak run A1
```

Each step shows what the agent tried and whether the guard allowed, asked or blocked, with the reason. No install? The same thing runs in your browser: https://huggingface.co/spaces/builditwithgk/agent-firebreak

## 2. Try to break it (5 minutes)

The simulated agent obeys any instruction it reads. Your job is to find a tool call that should have been stopped and was not. Ideas:

- Write an address in an unusual way (spaces, entities, other alphabets) and see if a call to it slips through.
- Use the Python API from the README, with your own tool declarations, and try odd addresses, links and extra arguments.
- Or clone the repo, change a scenario in `src/agent_firebreak/data/scenarios.json`, and run `agent-firebreak run <id>`.
- Check the two documented limits (L1, L2): do they behave as the README says?

Found a bypass? Open a [Bypass or false negative](https://github.com/builditwithgk/agent-firebreak/issues/new?template=bypass_report.yml) issue. Use fictional values only (`attacker.example`). This is the most valuable report you can send.

## 3. Wrap your own tool calls (optional, 5 minutes)

If you have an agent, put two calls around its tool execution:

```python
guard.observe(Segment("email.body", text), tool="read_email")   # everything the model reads
decision = guard.evaluate(ToolCall("send_email", args))          # before running any tool
```

The README has a runnable example. Was it clear how to describe your tools and which fields are untrusted?

## Tell us how it went

Open a [First-run feedback](https://github.com/builditwithgk/agent-firebreak/issues/new?template=first_run_feedback.yml) issue, or reply in [Discussions](https://github.com/builditwithgk/agent-firebreak/discussions). Useful answers to any of these:

- Where did you get stuck or confused?
- What did you expect that was missing?
- Would you use this on a real agent, and what would need to change first?

Negative feedback is welcome. Please do not star the repo to be nice; tell us what is wrong instead.
