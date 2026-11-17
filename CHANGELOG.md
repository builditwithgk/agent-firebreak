# Changelog

## 0.1.1
- Fix: an address such as `me@corp.example@attacker.example` no longer inherits trust from its trusted-looking prefix; look-alike (non-ASCII) characters inside an address are treated as a new value.
- Fix: arguments a tool spec did not declare (for example a model-invented `bcc`) are now checked for untrusted addresses and links.
- Fix: guard reasons escape non-ASCII characters, so look-alikes are visible and a narrow Windows console cannot crash on them; the CLI no longer raises on non-ASCII output.
- Docs: how to declare sinks, tags and risk; what to do with `ask`; a runnable agent loop; a note that hosts are matched by host and path only.
- Found by a fresh-agent walkthrough of the 0.1.0 README.

## 0.1.0
- First release.
