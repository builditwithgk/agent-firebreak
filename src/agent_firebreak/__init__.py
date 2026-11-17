"""agent-firebreak: assume the model will be fooled by prompt injection, and limit the damage."""

from agent_firebreak.audit import AuditLog
from agent_firebreak.guard import Guard
from agent_firebreak.models import (Decision, Effect, Finding, Origin, Risk, Segment, SinkSpec, ToolCall, ToolSpec,
                                    Trust)
from agent_firebreak.policy import Policy

__version__ = "0.1.2"
__all__ = ["AuditLog", "Guard", "Policy", "Decision", "Effect", "Finding", "Origin", "Risk", "Segment", "SinkSpec",
           "ToolCall", "ToolSpec", "Trust", "__version__"]
