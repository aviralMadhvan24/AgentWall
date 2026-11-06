"""Load a gateway from a YAML config file."""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from agentwall.audit.log import AuditLog
from agentwall.detector import build_detector
from agentwall.gateway.backends import MCPBackend
from agentwall.gateway.core import Gateway, GatewayConfig
from agentwall.policy.engine import Policy
from agentwall.redaction import resolve_kinds
from agentwall.registry.crypto import read_key
from agentwall.registry.registry import Registry


@dataclass
class ServerSpec:
    name: str
    command: str
    args: list[str] = field(default_factory=list)
    env: dict[str, str] | None = None

    def backend(self) -> MCPBackend:
        command = sys.executable if self.command in ("python", "python3") else self.command
        return MCPBackend.stdio(self.name, command, self.args, self.env)


@dataclass
class FileConfig:
    path: Path
    servers: list[ServerSpec]
    raw: dict[str, Any]

    def resolve(self, value: str) -> Path:
        p = Path(value)
        return p if p.is_absolute() else (self.path.parent / p)


def load_file_config(path: str | Path) -> FileConfig:
    path = Path(path)
    raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    servers = [
        ServerSpec(name, spec["command"], list(spec.get("args", [])), spec.get("env"))
        for name, spec in (raw.get("servers") or {}).items()
    ]
    return FileConfig(path, servers, raw)


def build_gateway(cfg: FileConfig) -> Gateway:
    raw = cfg.raw
    keys = [read_key(cfg.resolve(k)) for k in raw.get("public_keys", [])]
    manifests_dir = raw.get("manifests")
    registry = (
        Registry.from_dir(
            cfg.resolve(manifests_dir), keys, require_signatures=raw.get("require_signatures", True)
        )
        if manifests_dir and cfg.resolve(manifests_dir).exists()
        else Registry([], keys)
    )
    policy_ref = str(raw.get("policy", "default"))
    policy = Policy.load(
        cfg.resolve(policy_ref) if policy_ref.endswith((".yaml", ".yml")) else policy_ref
    )
    detector_name = raw.get("detector", "heuristic")
    detector = None if detector_name in (None, "none", False) else build_detector(detector_name)
    audit_path = raw.get("audit_log")
    approvals = raw.get("approvals") or {}
    approver = None
    if approvals:
        from agentwall.approvals import ApprovalStore, StoreApprover

        approver = StoreApprover(
            ApprovalStore(cfg.resolve(approvals.get("store", ".agentwall/approvals.json"))),
            wait_seconds=float(approvals.get("wait_seconds", 0)),
        )
    config = GatewayConfig(
        policy=policy,
        registry=registry,
        detector=detector,
        flag_threshold=float(raw.get("flag_threshold", 0.5)),
        attribution=bool(raw.get("attribution", True)),
        enforce_manifests=bool(raw.get("enforce_manifests", True)),
        destination_allowlist=tuple(raw.get("destination_allowlist", [])),
        audit=AuditLog(cfg.resolve(audit_path) if audit_path else None),
        redact_outputs=tuple(sorted(resolve_kinds(raw.get("redact_outputs") or []))),
        approver=approver,
    )
    return Gateway([s.backend() for s in cfg.servers], config)
