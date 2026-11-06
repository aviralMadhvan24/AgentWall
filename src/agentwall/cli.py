"""Command-line interface: ``agentwall <command>``."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path
from typing import Any

import anyio
import yaml

DEMO_SERVERS = ("web", "portfolio", "email", "http", "files", "weather")


def _cmd_serve(args: argparse.Namespace) -> int:
    from agentwall.gateway.config import build_gateway, load_file_config
    from agentwall.gateway.proxy import run_stdio

    run_stdio(build_gateway(load_file_config(args.config)))
    return 0


def _cmd_keygen(args: argparse.Namespace) -> int:
    from agentwall.registry.crypto import write_keypair

    private, public = write_keypair(args.out, args.name)
    print(f"private key: {private}  (keep secret, never commit)\npublic key:  {public}")
    return 0


def _cmd_sign(args: argparse.Namespace) -> int:
    from agentwall.registry.crypto import read_key, sign_manifest
    from agentwall.registry.manifest import Manifest

    key = read_key(args.key)
    for path in args.manifests:
        manifest = Manifest.load(path)
        sign_manifest(manifest, key).save(path)
        print(f"signed {path}")
    return 0


async def _list(config_path: str) -> list[tuple[str, str, str]]:
    from agentwall.gateway.config import build_gateway, load_file_config

    async with build_gateway(load_file_config(config_path)) as gateway:
        await gateway.refresh()
        return [(t.qualified, t.status.state, t.status.reason) for t in gateway.tools.values()]


def _cmd_verify(args: argparse.Namespace) -> int:
    rows = anyio.run(_list, args.config)
    width = max((len(r[0]) for r in rows), default=10)
    bad = 0
    for name, state, reason in rows:
        bad += state != "approved"
        print(f"{name:<{width}}  {state:<14} {reason}")
    return 1 if bad else 0


async def _pin(config_path: str, server: str, out: Path, caps: dict[str, str], roles: dict) -> Path:
    from agentwall.gateway.config import load_file_config
    from agentwall.labels import UNTRUSTED_PUBLIC
    from agentwall.registry.registry import draft_manifest

    cfg = load_file_config(config_path)
    spec = next((s for s in cfg.servers if s.name == server), None)
    if spec is None:
        raise SystemExit(f"server {server!r} not in {config_path}")
    async with spec.backend() as backend:
        tools = await backend.list_tools()
    manifest = draft_manifest(server, tools, UNTRUSTED_PUBLIC, caps, roles)
    manifest.notes = "DRAFT: review capability, argument roles and labels, then sign."
    out.mkdir(parents=True, exist_ok=True)
    path = out / f"{server}.yaml"
    manifest.save(path)
    return path


def _parse_pairs(pairs: list[str]) -> dict[str, str]:
    out = {}
    for pair in pairs or []:
        key, _, value = pair.partition("=")
        out[key] = value
    return out


def _cmd_pin(args: argparse.Namespace) -> int:
    caps = _parse_pairs(args.capability)
    control = {k: tuple(v.split(",")) for k, v in _parse_pairs(args.control).items()}
    data = {k: tuple(v.split(",")) for k, v in _parse_pairs(args.data).items()}
    roles = {t: (control.get(t, ()), data.get(t, ())) for t in set(control) | set(data)}
    path = anyio.run(_pin, args.config, args.server, Path(args.out), caps, roles)
    print(f"wrote draft manifest {path}; review it, then run `agentwall sign`")
    return 0


async def _demo_setup(directory: Path) -> None:
    from agentwall.demo.manifests import signed_demo_manifest
    from agentwall.demo.servers import build
    from agentwall.gateway.backends import MCPBackend
    from agentwall.registry.crypto import read_key, write_keypair

    keys_dir, manifests_dir = directory / "keys", directory / "manifests"
    private_path, public_path = write_keypair(keys_dir, "operator")
    manifests_dir.mkdir(parents=True, exist_ok=True)
    for name in DEMO_SERVERS:
        async with MCPBackend(name, build(name)) as backend:
            tools = await backend.list_tools()
        signed_demo_manifest(name, tools, read_key(private_path)).save(
            manifests_dir / f"{name}.yaml"
        )
    config = {
        "servers": {
            n: {"command": "python", "args": ["-m", "agentwall.demo.servers", n]}
            for n in ("web", "portfolio", "email", "files")
        },
        "manifests": "manifests",
        "public_keys": [f"keys/{public_path.name}"],
        "require_signatures": True,
        "enforce_manifests": True,
        "policy": "default",
        "detector": "heuristic",
        "attribution": True,
        "destination_allowlist": [],
        "audit_log": ".agentwall/audit.jsonl",
    }
    (directory / "agentwall.yaml").write_text(
        yaml.safe_dump(config, sort_keys=False), encoding="utf-8"
    )


def _cmd_demo_setup(args: argparse.Namespace) -> int:
    directory = Path(args.dir)
    anyio.run(_demo_setup, directory)
    print(f"demo keys, signed manifests and config written to {directory}/")
    return 0


def _model_client(args: argparse.Namespace) -> Any:
    """Cache -> throttle -> Gemini. In replay-only mode no key is needed and nothing is sent."""
    from agentwall.agent.model import CachedClient, ThrottledClient

    inner = None
    if not args.replay_only:
        from agentwall.agent.gemini import GeminiClient

        inner = ThrottledClient(GeminiClient(), rpm=args.rpm, budget=args.budget)
    return CachedClient(inner, args.cache, replay_only=args.replay_only)


def _add_model_args(p: argparse.ArgumentParser, default_cache: str, turns: bool = True) -> None:
    from agentwall.agent.gemini import DEFAULT_MODEL

    p.add_argument("--model", default=os.environ.get("AGENTWALL_GEMINI_MODEL", DEFAULT_MODEL))
    p.add_argument("--cache", default=default_cache, help="JSONL cache of model responses")
    p.add_argument("--replay-only", action="store_true", help="never call the API; use the cache")
    p.add_argument("--rpm", type=float, default=8.0, help="max model requests per minute")
    p.add_argument("--budget", type=int, default=0, help="max API calls this run (0: no limit)")
    if turns:
        p.add_argument("--max-turns", type=int, default=10)


def _cmd_bench(args: argparse.Namespace) -> int:
    from agentwall.harness.runner import ModelAgentSpec, run_cli

    if args.agent == "obedient":
        return run_cli(suite=args.suite, out=args.out or "results", configs=args.configs)
    client = _model_client(args)
    spec = ModelAgentSpec(client, args.model, max_turns=args.max_turns)
    code = run_cli(
        suite=args.suite,
        out=args.out or "results/gemini",
        configs=args.configs or ["none", "full"],
        agent=spec,
        repeats=args.repeats,
    )
    print(f"model cache: {client.hits} hits, {client.misses} new calls, {len(client)} entries")
    return code


def _cmd_dojo(args: argparse.Namespace) -> int:
    try:
        from agentwall.integrations.agentdojo.runner import run_dojo_cli
    except ImportError:
        print('AgentDojo is not installed: pip install -e ".[agentdojo]"', file=sys.stderr)
        return 2
    client = _model_client(args)

    def split(v: str | None) -> tuple[str, ...] | None:
        return tuple(x.strip() for x in v.split(",") if x.strip()) if v else None

    code = run_dojo_cli(
        client,
        args.model,
        args.suite,
        args.version,
        split(args.configs) or ("none", "full"),
        split(args.injection_tasks),
        split(args.user_tasks),
        args.attack,
        Path(args.out),
    )
    print(f"model cache: {client.hits} hits, {client.misses} new calls, {len(client)} entries")
    return code


def _cmd_adaptive(args: argparse.Namespace) -> int:
    from agentwall.harness.adaptive import LLMMutator, RuleMutator
    from agentwall.harness.adaptive_run import run_adaptive_cli
    from agentwall.harness.runner import ModelAgentSpec

    needs_model = args.mutator == "gemini" or args.agent == "gemini"
    client = _model_client(args) if needs_model else None
    mutator: Any = RuleMutator()
    agent = None
    if client is not None:
        if args.mutator == "gemini":
            mutator = LLMMutator(client, args.model)
        if args.agent == "gemini":
            agent = ModelAgentSpec(client, args.model, max_turns=args.max_turns)
    configs = args.configs or ["detector_only", "attribution", "full"]
    code = run_adaptive_cli(mutator, configs, args.budget_per_seed, Path(args.out), agent)
    if client is not None:
        print(f"model cache: {client.hits} hits, {client.misses} new calls, {len(client)} entries")
    return code


def _cmd_models(args: argparse.Namespace) -> int:
    from agentwall.agent.gemini import GeminiClient

    for name in GeminiClient().list_models():
        print(name)
    return 0


def _cmd_audit_verify(args: argparse.Namespace) -> int:
    from agentwall.audit.log import AuditLog, verify_chain

    ok, index = verify_chain(AuditLog(args.path).entries)
    print("audit log intact" if ok else f"audit log broken at entry {index}")
    return 0 if ok else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="agentwall", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("serve", help="run the stdio MCP proxy")
    p.add_argument("--config", required=True)
    p.set_defaults(fn=_cmd_serve)

    p = sub.add_parser("keygen", help="create an Ed25519 operator keypair")
    p.add_argument("--out", default="keys")
    p.add_argument("--name", default="operator")
    p.set_defaults(fn=_cmd_keygen)

    p = sub.add_parser("pin", help="draft a manifest from a server's current tools")
    p.add_argument("--config", required=True)
    p.add_argument("--server", required=True)
    p.add_argument("--out", default="manifests")
    p.add_argument("--capability", nargs="*", metavar="TOOL=CLASS", help="read, write or egress")
    p.add_argument("--control", nargs="*", metavar="TOOL=ARG[,ARG]")
    p.add_argument("--data", nargs="*", metavar="TOOL=ARG[,ARG]")
    p.set_defaults(fn=_cmd_pin)

    p = sub.add_parser("sign", help="sign manifests with the operator key")
    p.add_argument("--key", required=True)
    p.add_argument("manifests", nargs="+")
    p.set_defaults(fn=_cmd_sign)

    p = sub.add_parser("verify", help="show which tools the gateway would expose")
    p.add_argument("--config", required=True)
    p.set_defaults(fn=_cmd_verify)

    p = sub.add_parser("demo-setup", help="write keys, signed demo manifests and a config")
    p.add_argument("--dir", default="examples")
    p.set_defaults(fn=_cmd_demo_setup)

    p = sub.add_parser("bench", help="run the evaluation harness")
    p.add_argument("--suite", default="quick", choices=["quick", "full", "adaptive"])
    p.add_argument(
        "--out", default=None, help="results directory (default: results, or results/gemini)"
    )
    p.add_argument("--configs", nargs="*", help="subset of ablation configs to run")
    p.add_argument("--agent", default="obedient", choices=["obedient", "gemini"])
    p.add_argument("--repeats", type=int, default=1, help="runs per scenario (model agents)")
    _add_model_args(p, "results/gemini/cache.jsonl")
    p.set_defaults(fn=_cmd_bench)

    p = sub.add_parser("dojo", help="run an AgentDojo suite subset with and without AgentWall")
    p.add_argument("--suite", default="banking")
    p.add_argument("--version", default="v1.2.1", help="AgentDojo benchmark version")
    p.add_argument("--configs", default="none,full", help="comma-separated: none and/or ablations")
    p.add_argument("--injection-tasks", default=None, help="comma-separated ids (default: preset)")
    p.add_argument("--user-tasks", default=None, help="comma-separated ids (default: all)")
    p.add_argument("--attack", default="important_instructions")
    p.add_argument("--out", default="results/agentdojo")
    _add_model_args(p, "results/agentdojo/cache.jsonl", turns=False)
    p.set_defaults(fn=_cmd_dojo)

    p = sub.add_parser("adaptive", help="rewrite attacks until they get through")
    p.add_argument("--mutator", default="rules", choices=["rules", "gemini"])
    p.add_argument("--agent", default="obedient", choices=["obedient", "gemini"])
    p.add_argument("--configs", nargs="*", help="default: detector_only attribution full")
    p.add_argument("--budget-per-seed", type=int, default=8, help="attempts per seed attack")
    p.add_argument("--out", default="results/adaptive")
    _add_model_args(p, "results/adaptive/cache.jsonl")
    p.set_defaults(fn=_cmd_adaptive)

    p = sub.add_parser("models", help="list Gemini models your API key can call")
    p.set_defaults(fn=_cmd_models)

    p = sub.add_parser("audit-verify", help="check an audit log's hash chain")
    p.add_argument("path")
    p.set_defaults(fn=_cmd_audit_verify)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:  # GEMINI_API_KEY etc. from ./.env; variables already set in the shell win
        from dotenv import find_dotenv, load_dotenv

        load_dotenv(find_dotenv(usecwd=True))
    except ImportError:
        pass
    # Reports contain characters a Windows console code page may lack; never crash printing them.
    reconfigure = getattr(sys.stdout, "reconfigure", None)
    if reconfigure is not None:
        reconfigure(errors="replace")
    return int(args.fn(args) or 0)


if __name__ == "__main__":
    sys.exit(main())
