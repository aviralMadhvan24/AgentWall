"""Server manifests: what each server and tool is allowed to be, pinned by hash."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from agentwall.labels import Label
from agentwall.types import ToolInfo

CAPABILITIES = ("read", "write", "egress")


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def sha256_schema(schema: dict[str, Any]) -> str:
    return sha256_text(json.dumps(schema, sort_keys=True, separators=(",", ":")))


@dataclass(frozen=True)
class ToolPin:
    name: str
    capability: str
    description_sha256: str
    schema_sha256: str
    control_args: tuple[str, ...] = ()
    data_args: tuple[str, ...] = ()
    output_label: Label | None = None  # overrides the server's label for this tool's output

    def __post_init__(self) -> None:
        if self.capability not in CAPABILITIES:
            raise ValueError(f"tool {self.name}: capability must be one of {CAPABILITIES}")

    @classmethod
    def from_tool(
        cls,
        tool: ToolInfo,
        capability: str,
        control_args: tuple[str, ...] = (),
        data_args: tuple[str, ...] = (),
        output_label: Label | None = None,
    ) -> ToolPin:
        return cls(
            tool.name,
            capability,
            sha256_text(tool.description),
            sha256_schema(tool.input_schema),
            tuple(control_args),
            tuple(data_args),
            output_label,
        )

    def matches(self, tool: ToolInfo) -> bool:
        return self.description_sha256 == sha256_text(
            tool.description
        ) and self.schema_sha256 == sha256_schema(tool.input_schema)

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "capability": self.capability,
            "description_sha256": self.description_sha256,
            "schema_sha256": self.schema_sha256,
            "control_args": list(self.control_args),
            "data_args": list(self.data_args),
        }
        if self.output_label is not None:
            data["output_integrity"] = str(self.output_label.integrity)
            data["output_confidentiality"] = str(self.output_label.confidentiality)
        return data


@dataclass
class Manifest:
    server: str
    output_label: Label
    tools: dict[str, ToolPin]
    version: int = 1
    signature: str | None = None
    notes: str = ""
    extra: dict[str, Any] = field(default_factory=dict)

    def to_dict(self, include_signature: bool = True) -> dict[str, Any]:
        data: dict[str, Any] = {
            "server": self.server,
            "version": self.version,
            "integrity": str(self.output_label.integrity),
            "confidentiality": str(self.output_label.confidentiality),
            "tools": {name: pin.to_dict() for name, pin in sorted(self.tools.items())},
        }
        if self.notes:
            data["notes"] = self.notes
        if include_signature and self.signature:
            data["signature"] = self.signature
        return data

    def canonical_bytes(self) -> bytes:
        """Bytes that are signed: everything except the signature, keys sorted."""
        return json.dumps(
            self.to_dict(include_signature=False), sort_keys=True, separators=(",", ":")
        ).encode("utf-8")

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Manifest:
        tools = {
            name: ToolPin(
                name,
                spec["capability"],
                spec["description_sha256"],
                spec["schema_sha256"],
                tuple(spec.get("control_args", ())),
                tuple(spec.get("data_args", ())),
                Label.parse(spec["output_integrity"], spec["output_confidentiality"])
                if "output_integrity" in spec
                else None,
            )
            for name, spec in (data.get("tools") or {}).items()
        }
        return cls(
            server=data["server"],
            output_label=Label.parse(data["integrity"], data["confidentiality"]),
            tools=tools,
            version=int(data.get("version", 1)),
            signature=data.get("signature"),
            notes=data.get("notes", ""),
        )

    @classmethod
    def load(cls, path: str | Path) -> Manifest:
        return cls.from_dict(yaml.safe_load(Path(path).read_text(encoding="utf-8")))

    def save(self, path: str | Path) -> None:
        Path(path).write_text(yaml.safe_dump(self.to_dict(), sort_keys=False), encoding="utf-8")
