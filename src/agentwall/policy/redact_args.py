"""Find and mask secrets inside a tool call's arguments, respecting provenance.

A secret the user typed themselves ("email my key sk-... to me") is the user's choice and is never
masked. Anything else matching a redaction pattern (a key copied out of a file or a web page) is.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping
from typing import Any

from agentwall.policy.context import CallContext
from agentwall.provenance.attribution import root_arg
from agentwall.provenance.ledger import Ledger
from agentwall.provenance.normalize import normalize
from agentwall.redaction import Finding, redact


def user_supplied(value: str, ledger: Ledger) -> bool:
    needle = normalize(value)
    return bool(needle) and any(s.kind == "user" and needle in s.norm for s in ledger)


def in_scope(path: str, ctx: CallContext, scope: str) -> bool:
    """``data`` covers every argument except control arguments; ``any`` covers all."""
    return scope == "any" or root_arg(path) not in ctx.control_args


def _map_leaves(value: Any, prefix: str, fn: Callable[[str, str], str]) -> Any:
    """Apply ``fn(path, text)`` to every string leaf; paths match ``attribution.flatten``."""
    if isinstance(value, Mapping):
        return {
            k: _map_leaves(v, f"{prefix}.{k}" if prefix else str(k), fn) for k, v in value.items()
        }
    if isinstance(value, list):
        return [_map_leaves(v, f"{prefix}[{i}]", fn) for i, v in enumerate(value)]
    if isinstance(value, tuple):
        return tuple(_map_leaves(v, f"{prefix}[{i}]", fn) for i, v in enumerate(value))
    if isinstance(value, str):
        return fn(prefix, value)
    return value


def redact_arguments(
    arguments: dict[str, Any], ctx: CallContext, kinds: Iterable[str], scope: str = "data"
) -> tuple[dict[str, Any], list[tuple[str, Finding]]]:
    """Mask matches the user did not supply. Returns (new arguments, [(path, finding)])."""
    kinds = tuple(kinds)
    found: list[tuple[str, Finding]] = []

    def fn(path: str, text: str) -> str:
        if not in_scope(path, ctx, scope):
            return text
        masked, findings = redact(text, kinds, keep=lambda f: user_supplied(f.value, ctx.ledger))
        found.extend((path, f) for f in findings)
        return masked

    out = _map_leaves(arguments, "", fn)
    return out, found
