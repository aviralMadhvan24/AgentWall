"""Everything a policy rule can look at when a tool call is evaluated."""

from __future__ import annotations

from dataclasses import dataclass, field
from fnmatch import fnmatch

from agentwall.labels import Label
from agentwall.provenance.attribution import ValueAttribution, root_arg
from agentwall.provenance.ledger import Ledger


@dataclass
class CallContext:
    server: str
    tool: str
    capability: str
    attributions: dict[str, ValueAttribution]
    ledger: Ledger
    server_label: Label
    control_args: tuple[str, ...] = ()
    data_args: tuple[str, ...] = ()
    destination_allowlist: tuple[str, ...] = field(default_factory=tuple)

    @property
    def qualified_name(self) -> str:
        return f"{self.server}/{self.tool}"

    def control_attributions(self) -> list[ValueAttribution]:
        """Attributions of arguments that choose targets or actions.

        A write or egress tool that declares no argument roles is treated as all-control: without a
        manifest saying otherwise, any argument might pick the destination.
        """
        if not self.control_args:
            return [a for a in self.attributions.values() if a.method != "trivial"]
        return [a for p, a in self.attributions.items() if root_arg(p) in self.control_args]

    def destination_allowed(self, entity: str) -> bool:
        bare = entity.split(":", 1)[1] if ":" in entity else entity
        return any(
            fnmatch(bare, pattern) or fnmatch(entity, pattern)
            for pattern in self.destination_allowlist
        )
