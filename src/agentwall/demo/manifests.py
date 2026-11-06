"""Draft and sign manifests for the demo servers."""

from __future__ import annotations

from collections.abc import Iterable

from agentwall.demo.servers import DEMO_TOOL_POLICY
from agentwall.labels import Label
from agentwall.registry.crypto import sign_manifest
from agentwall.registry.manifest import Manifest, ToolPin
from agentwall.registry.registry import draft_manifest
from agentwall.types import ToolInfo


def demo_manifest(server: str, tools: Iterable[ToolInfo]) -> Manifest:
    spec = DEMO_TOOL_POLICY[server]
    label = Label.parse(*spec["label"])
    caps = {name: v[0] for name, v in spec["tools"].items()}
    roles = {name: (v[1], v[2]) for name, v in spec["tools"].items()}
    return draft_manifest(server, list(tools), label, caps, roles)


def signed_demo_manifest(server: str, tools: Iterable[ToolInfo], private_key_hex: str) -> Manifest:
    return sign_manifest(demo_manifest(server, tools), private_key_hex)


def pin(tool: ToolInfo, server: str) -> ToolPin:
    capability, control, data = DEMO_TOOL_POLICY[server]["tools"][tool.name]
    return ToolPin.from_tool(tool, capability, control, data)
