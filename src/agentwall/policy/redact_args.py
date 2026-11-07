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
    """The user typed this value themselves, so it is their choice and is never masked.

    Matched on whitespace boundaries: a secret that merely happens to occur inside a longer word of
    a long prompt must not win a permanent exemption from masking.
    """
    needle = normalize(value)
    if not needle:
        return False
    return any(span.kind == "user" and f" {needle} " in f" {span.norm} " for span in ledger)


def in_scope(path: str, ctx: CallContext, scope: str) -> bool:
    """``data`` covers every argument except control arguments; ``any`` covers all."""
    return scope == "any" or root_arg(path) not in ctx.control_args


def _map_leaves(value: Any, prefix: str, fn: Callable[[str, str], str]) -> Any:
    """Apply ``fn(path, text)`` to every leaf; paths match ``attribution.flatten``.

    Numbers are masked too (a card number sent as JSON number is still a card number), and so are
    mapping keys, which attribution folds into the path and would otherwise never be examined.
    """
    if isinstance(value, Mapping):
        out = {}
        for k, v in value.items():
            path = f"{prefix}.{k}" if prefix else str(k)
            key = fn(path, k) if isinstance(k, str) else k
            out[key] = _map_leaves(v, path, fn)
        return out
    if isinstance(value, list):
        return [_map_leaves(v, f"{prefix}[{i}]", fn) for i, v in enumerate(value)]
    if isinstance(value, tuple):
        return tuple(_map_leaves(v, f"{prefix}[{i}]", fn) for i, v in enumerate(value))
    if isinstance(value, str):
        return fn(prefix, value)
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        # attribute_value stringifies these, so the predicate can match what we must also mask.
        text = str(value)
        masked = fn(prefix, text)
        return masked if masked != text else value
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
