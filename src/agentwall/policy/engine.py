"""YAML policy engine.

A policy is an ordered list of rules. A rule applies when its ``when`` selector matches the tool and all of
its ``if`` predicates hold. Outcome precedence: block > ask > redact > allow; with no matching rule, the
policy's ``default`` applies.

``redact`` lets the call go ahead with secrets or personal data masked in its arguments. A redact rule
may say what to mask::

    action: redact
    redact: {kinds: [secrets], scope: data}   # the default; scope "any" also covers control arguments

Masking from every matching redact rule is applied whenever the call executes, including after a human
approves an ``ask``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from fnmatch import fnmatch
from importlib import resources
from pathlib import Path
from typing import Any

import yaml

from agentwall.policy.context import CallContext
from agentwall.policy.predicates import PREDICATES
from agentwall.redaction import resolve_kinds

ACTIONS = ("allow", "redact", "ask", "block")
_PRECEDENCE = {"allow": 0, "redact": 1, "ask": 2, "block": 3}
REDACT_SCOPES = ("data", "any")


class PolicyError(ValueError):
    pass


@dataclass(frozen=True)
class Condition:
    name: str
    params: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class RedactSpec:
    kinds: tuple[str, ...] = ("secrets",)
    scope: str = "data"


@dataclass(frozen=True)
class Rule:
    id: str
    action: str
    conditions: tuple[Condition, ...]
    tool_classes: frozenset[str] | None = None
    tool_glob: str | None = None
    server_glob: str | None = None
    reason: str = ""
    redact: RedactSpec | None = None

    def selects(self, ctx: CallContext) -> bool:
        if self.tool_classes is not None and ctx.capability not in self.tool_classes:
            return False
        if self.tool_glob and not fnmatch(ctx.tool, self.tool_glob):
            return False
        return not (self.server_glob and not fnmatch(ctx.server, self.server_glob))


@dataclass(frozen=True)
class RuleMatch:
    rule_id: str
    action: str
    reason: str
    details: tuple[str, ...]
    redact: RedactSpec | None = None


@dataclass(frozen=True)
class Decision:
    action: str
    matches: tuple[RuleMatch, ...] = ()

    @property
    def allowed(self) -> bool:
        """The call may run without a human: allowed outright or with masking."""
        return self.action in ("allow", "redact")

    def redaction(self) -> RedactSpec | None:
        """What to mask if the call runs: the union of every matching redact rule."""
        specs = [m.redact for m in self.matches if m.redact is not None]
        if not specs:
            return None
        kinds = tuple(sorted({k for s in specs for k in s.kinds}))
        scope = "any" if any(s.scope == "any" for s in specs) else "data"
        return RedactSpec(kinds, scope)

    def explain(self) -> str:
        if not self.matches:
            return "no rule matched; default applied"
        lines = []
        for m in self.matches:
            lines.append(f"[{m.action}] {m.rule_id}: {m.reason}")
            lines.extend(f"    {d}" for d in m.details if d)
        return "\n".join(lines)


def _parse_condition(raw: Any, rule_id: str) -> Condition:
    params: dict[str, Any]
    if isinstance(raw, str):
        name, params = raw, {}
    elif isinstance(raw, dict) and len(raw) == 1:
        name, params = next(iter(raw.items()))
        params = params or {}
    else:
        raise PolicyError(f"rule {rule_id}: bad condition {raw!r}")
    if name not in PREDICATES:
        raise PolicyError(
            f"rule {rule_id}: unknown predicate {name!r} (known: {sorted(PREDICATES)})"
        )
    return Condition(name, dict(params))


def _parse_rule(raw: dict[str, Any]) -> Rule:
    rule_id = raw.get("id") or "unnamed"
    action = raw.get("action", "block")
    if action not in ACTIONS:
        raise PolicyError(f"rule {rule_id}: action must be one of {ACTIONS}")
    when = raw.get("when") or {}
    classes = when.get("tool_class")
    if isinstance(classes, str):
        classes = [classes]
    conditions = tuple(_parse_condition(c, rule_id) for c in raw.get("if") or [])
    if not conditions:
        raise PolicyError(f"rule {rule_id}: needs at least one condition under 'if'")
    redact = None
    if "redact" in raw and action != "redact":
        raise PolicyError(f"rule {rule_id}: 'redact' options need action: redact")
    if action == "redact":
        spec = raw.get("redact") or {}
        kinds = spec.get("kinds", ["secrets"])
        scope = spec.get("scope", "data")
        try:
            resolve_kinds(kinds)
        except ValueError as exc:
            raise PolicyError(f"rule {rule_id}: {exc}") from exc
        if scope not in REDACT_SCOPES:
            raise PolicyError(f"rule {rule_id}: redact scope must be one of {REDACT_SCOPES}")
        redact = RedactSpec(tuple(kinds), scope)
    return Rule(
        id=rule_id,
        action=action,
        conditions=conditions,
        tool_classes=frozenset(classes) if classes else None,
        tool_glob=when.get("tool"),
        server_glob=when.get("server"),
        reason=raw.get("reason", ""),
        redact=redact,
    )


class Policy:
    def __init__(self, rules: list[Rule], default: str = "allow", name: str = "policy") -> None:
        if default not in ACTIONS:
            raise PolicyError(f"default must be one of {ACTIONS}")
        self.rules = rules
        self.default = default
        self.name = name

    @classmethod
    def from_dict(cls, data: dict[str, Any], name: str = "policy") -> Policy:
        rules = [_parse_rule(r) for r in data.get("rules") or []]
        ids = [r.id for r in rules]
        if len(ids) != len(set(ids)):
            raise PolicyError("rule ids must be unique")
        return cls(rules, data.get("default", "allow"), name)

    @classmethod
    def load(cls, path_or_name: str | Path) -> Policy:
        """Load a policy file, or a built-in policy by name (``default``, ``detector_only``, ``none``)."""
        path = Path(path_or_name)
        if path.suffix in (".yaml", ".yml") and path.exists():
            return cls.from_dict(yaml.safe_load(path.read_text(encoding="utf-8")) or {}, path.stem)
        builtin = resources.files("agentwall.policies") / f"{path_or_name}.yaml"
        if not builtin.is_file():
            raise PolicyError(f"no policy file or built-in policy named {path_or_name!r}")
        return cls.from_dict(
            yaml.safe_load(builtin.read_text(encoding="utf-8")) or {}, str(path_or_name)
        )

    def evaluate(self, ctx: CallContext) -> Decision:
        matches: list[RuleMatch] = []
        for rule in self.rules:
            if not rule.selects(ctx):
                continue
            details: list[str] = []
            for cond in rule.conditions:
                holds, detail = PREDICATES[cond.name](ctx, cond.params)
                if not holds:
                    break
                details.append(detail)
            else:
                matches.append(
                    RuleMatch(rule.id, rule.action, rule.reason, tuple(details), rule.redact)
                )
        if not matches:
            return Decision(self.default)
        action = max((m.action for m in matches), key=_PRECEDENCE.__getitem__)
        return Decision(action, tuple(matches))
