# Changelog

## 0.1.2
- Fix (availability): one very long unbroken token in untrusted content could stall indexing for minutes (quadratic regex work). Indexing is now linear; a 400 KB token takes about half a second.
- Fix: a backslash or tab inside a URL (`https://evil.example\@good.example/`) is read the way browsers read it, so the real host is judged.
- New sink kinds `handle`, `path`, `command` and `literal`: chat handles, file paths and shell commands must come from the user. Previously `handle` was documented but only email-shaped values were traced.
- Fix: parameters listed in `params` but not declared as sinks are now scanned like undeclared ones (declaring a parameter no longer weakens protection); bare account ids in them are checked.
- Fix: `[at]`/`[dot]` spellings in call arguments are normalised before checking.
- Docs: tags are trusted blindly; what is out of scope; fail closed on timeouts.
- Found by a second fresh-agent walkthrough.

## 0.1.1
- Fix: an address such as `me@corp.example@attacker.example` no longer inherits trust from its trusted-looking prefix; look-alike (non-ASCII) characters inside an address are treated as a new value.
- Fix: arguments a tool spec did not declare (for example a model-invented `bcc`) are now checked for untrusted addresses and links.
- Fix: guard reasons escape non-ASCII characters, so look-alikes are visible and a narrow Windows console cannot crash on them; the CLI no longer raises on non-ASCII output.
- Docs: how to declare sinks, tags and risk; what to do with `ask`; a runnable agent loop; a note that hosts are matched by host and path only.
- Found by a fresh-agent walkthrough of the 0.1.0 README.

## 0.1.0
- First release.
