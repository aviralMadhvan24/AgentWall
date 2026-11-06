"""Manifest registry: decides which advertised tools the agent may see.

Every ``tools/list`` from a server is checked against that server's signed manifest. A description or
schema that no longer matches its pin is a rug pull: the whole server is quarantined until an operator
re-approves it.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass
from pathlib import Path

from agentwall.labels import UNTRUSTED_PUBLIC, Label
from agentwall.registry.crypto import verify_manifest
from agentwall.registry.manifest import Manifest, ToolPin
from agentwall.types import ToolInfo

STATES = (
    "approved",
    "unknown_server",
    "bad_signature",
    "unpinned",
    "rug_pull",
    "quarantined",
    "flagged",
)


@dataclass(frozen=True)
class ToolStatus:
    server: str
    tool: str
    state: str
    reason: str = ""

    @property
    def visible(self) -> bool:
        return self.state == "approved"


@dataclass(frozen=True)
class Incident:
    kind: str
    server: str
    tool: str
    detail: str


class Registry:
    def __init__(
        self,
        manifests: Iterable[Manifest] = (),
        public_keys: Iterable[str] = (),
        *,
        require_signatures: bool = True,
    ) -> None:
        self.manifests: dict[str, Manifest] = {m.server: m for m in manifests}
        self.public_keys = list(public_keys)
        self.require_signatures = require_signatures
        self.quarantined: dict[str, str] = {}
        self.incidents: list[Incident] = []

    @classmethod
    def from_dir(
        cls, directory: str | Path, public_keys: Iterable[str], *, require_signatures: bool = True
    ) -> Registry:
        paths = sorted(Path(directory).glob("*.y*ml")) + sorted(Path(directory).glob("*.json"))
        return cls(
            [Manifest.load(p) for p in paths], public_keys, require_signatures=require_signatures
        )

    def label_for(self, server: str) -> Label:
        manifest = self.manifests.get(server)
        return manifest.output_label if manifest else UNTRUSTED_PUBLIC

    def pin_for(self, server: str, tool: str) -> ToolPin | None:
        manifest = self.manifests.get(server)
        return manifest.tools.get(tool) if manifest else None

    def approve(self, manifest: Manifest) -> None:
        """Install a (re-)approved manifest and lift any quarantine on its server."""
        self.manifests[manifest.server] = manifest
        self.quarantined.pop(manifest.server, None)

    def check_listing(
        self,
        server: str,
        tools: list[ToolInfo],
        detector: Callable[[str], float] | None = None,
        threshold: float = 0.5,
    ) -> list[ToolStatus]:
        manifest = self.manifests.get(server)
        if manifest is None:
            return [ToolStatus(server, t.name, "unknown_server", "no manifest") for t in tools]
        if self.require_signatures and not verify_manifest(manifest, self.public_keys):
            return [
                ToolStatus(server, t.name, "bad_signature", "manifest signature invalid")
                for t in tools
            ]

        drifted = [
            t for t in tools if t.name in manifest.tools and not manifest.tools[t.name].matches(t)
        ]
        for tool in drifted:
            if server not in self.quarantined:
                self.quarantined[server] = f"tool {tool.name!r} changed after approval"
            self.incidents.append(
                Incident("rug_pull", server, tool.name, "description or schema hash mismatch")
            )

        statuses: list[ToolStatus] = []
        for tool in tools:
            if server in self.quarantined:
                state = "rug_pull" if tool in drifted else "quarantined"
                statuses.append(ToolStatus(server, tool.name, state, self.quarantined[server]))
            elif tool.name not in manifest.tools:
                statuses.append(ToolStatus(server, tool.name, "unpinned", "tool not in manifest"))
            elif detector is not None and detector(tool.description) >= threshold:
                self.incidents.append(
                    Incident(
                        "poisoned_description", server, tool.name, "detector flagged description"
                    )
                )
                statuses.append(
                    ToolStatus(
                        server, tool.name, "flagged", "description looks like injected instructions"
                    )
                )
            else:
                statuses.append(ToolStatus(server, tool.name, "approved"))
        return statuses


def draft_manifest(
    server: str,
    tools: list[ToolInfo],
    label: Label,
    capabilities: dict[str, str] | None = None,
    roles: dict[str, tuple[tuple[str, ...], tuple[str, ...]]] | None = None,
) -> Manifest:
    """Pin the tools a server advertises right now. Review before signing."""
    capabilities = capabilities or {}
    roles = roles or {}
    pins = {}
    for tool in tools:
        control, data = roles.get(tool.name, ((), ()))
        pins[tool.name] = ToolPin.from_tool(
            tool, capabilities.get(tool.name, "read"), control, data
        )
    return Manifest(server=server, output_label=label, tools=pins)
