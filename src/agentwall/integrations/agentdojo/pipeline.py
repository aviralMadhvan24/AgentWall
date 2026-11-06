"""AgentDojo pipeline elements that route every tool call through the AgentWall gateway.

AgentDojo stays in charge of the run: it builds the environment, plants the injections, runs the agent
pipeline and scores utility and attack success from the final environment. AgentWall replaces only the
tool executor, so the model sees AgentDojo's own tool names, descriptions and output format, and a
blocked call comes back as a tool error.

AgentDojo pipelines are synchronous; the gateway is async but never waits on I/O here (AgentDojo tools
are plain Python functions), so each gateway call runs in its own short ``anyio.run``.
"""

from __future__ import annotations

from ast import literal_eval
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

import anyio
from agentdojo.agent_pipeline import (
    AgentPipeline,
    BasePipelineElement,
    InitQuery,
    SystemMessage,
    ToolsExecutionLoop,
    ToolsExecutor,
)
from agentdojo.agent_pipeline.agent_pipeline import load_system_message
from agentdojo.agent_pipeline.tool_execution import is_string_list, tool_result_to_str
from agentdojo.functions_runtime import EmptyEnv, Env, Function, FunctionCall, FunctionsRuntime
from agentdojo.types import (
    ChatAssistantMessage,
    ChatMessage,
    ChatToolResultMessage,
    get_text_content_as_str,
    text_content_block_from_string,
)

from agentwall.agent.model import ModelClient, ModelRequest, ToolSpec
from agentwall.detector import HeuristicDetector
from agentwall.gateway.core import CallOutcome, Gateway, GatewayConfig, Session, qualify
from agentwall.harness.runner import Ablation
from agentwall.integrations.agentdojo.manifests import SUITE_SERVERS, server_of
from agentwall.labels import Label
from agentwall.policy.engine import Policy
from agentwall.registry.crypto import generate_keypair, sign_manifest
from agentwall.registry.registry import Registry, draft_manifest
from agentwall.types import ToolInfo, ToolResult

SESSION_KEY = "agentwall_session"
SIGNATURES_KEY = "agentwall_signatures"


def tool_info(fn: Function) -> ToolInfo:
    return ToolInfo(fn.name, fn.description, fn.parameters.model_json_schema())


@dataclass
class _TaskState:
    """The environment and runtime of the task being run; tools act on these."""

    env: Env
    runtime: FunctionsRuntime


class DojoBackend:
    """One AgentWall pseudo-server backed by a subset of an AgentDojo suite's tools."""

    def __init__(self, name: str, functions: Sequence[Function], state: _TaskState) -> None:
        self.name = name
        self.functions = list(functions)
        self.state = state

    async def list_tools(self) -> list[ToolInfo]:
        return [tool_info(f) for f in self.functions]

    async def call_tool(self, tool: str, arguments: dict[str, Any]) -> ToolResult:
        result, error = self.state.runtime.run_function(self.state.env, tool, arguments)
        if error:
            return ToolResult(error, is_error=True)
        return ToolResult(tool_result_to_str(result))


class AgentWallToolsExecutor(BasePipelineElement):
    """Drop-in replacement for AgentDojo's ``ToolsExecutor`` with the gateway in the path."""

    def __init__(self, suite: str, functions: Sequence[Function], ablation: Ablation) -> None:
        self.suite = suite
        self.functions = {f.name: f for f in functions}
        self.ablation = ablation
        self.server_of = server_of(suite)
        missing = set(self.functions) - set(self.server_of)
        if missing:
            raise ValueError(f"{suite}: no AgentWall manifest entry for tools {sorted(missing)}")
        private, self._public = generate_keypair()
        self._manifests = []
        for server, spec in SUITE_SERVERS[suite].items():
            tools = [tool_info(self.functions[t]) for t in spec.tools]
            caps = {t: role[0] for t, role in spec.tools.items()}
            roles = {t: (role[1], role[2]) for t, role in spec.tools.items()}
            manifest = draft_manifest(server, tools, Label.parse(*spec.label), caps, roles)
            self._manifests.append(sign_manifest(manifest, private))
        self.last_session: Session | None = None

    def _new_session(self, state: _TaskState, query: str) -> Session:
        backends = [
            DojoBackend(server, [self.functions[t] for t in spec.tools], state)
            for server, spec in SUITE_SERVERS[self.suite].items()
        ]
        config = GatewayConfig(
            policy=Policy.load(self.ablation.policy),
            registry=Registry(self._manifests, [self._public]),
            detector=HeuristicDetector() if self.ablation.detector else None,
            attribution=self.ablation.attribution,
            enforce_manifests=self.ablation.enforce_manifests,
        )
        gateway = Gateway(backends, config)
        anyio.run(gateway.refresh)
        session = gateway.new_session()
        session.add_user_message(query)
        return session

    def _call(self, session: Session, name: str, args: dict[str, Any]) -> CallOutcome:
        async def go() -> CallOutcome:
            return await session.call_tool(qualify(self.server_of[name], name), args)

        return anyio.run(go)

    def query(
        self,
        query: str,
        runtime: FunctionsRuntime,
        env: Env = EmptyEnv(),
        messages: Sequence[ChatMessage] = [],
        extra_args: dict = {},
    ) -> tuple[str, FunctionsRuntime, Env, Sequence[ChatMessage], dict]:
        if not messages or messages[-1]["role"] != "assistant":
            return query, runtime, env, messages, extra_args
        calls = messages[-1]["tool_calls"]
        if not calls:
            return query, runtime, env, messages, extra_args

        if SESSION_KEY not in extra_args:
            state = _TaskState(env, runtime)
            # A new dict: AgentDojo's default extra_args is one shared object.
            extra_args = {**extra_args, SESSION_KEY: (self._new_session(state, query), state)}
        session, state = extra_args[SESSION_KEY]
        state.env, state.runtime = env, runtime
        self.last_session = session

        results = []
        for call in calls:
            content, error = "", None
            if not call.function:
                error = "Empty function name provided. Provide a valid function name."
            elif call.function not in runtime.functions:
                error = f"Invalid tool {call.function} provided."
            else:
                for k, v in call.args.items():  # same list coercion as AgentDojo's executor
                    if isinstance(v, str) and is_string_list(v):
                        call.args[k] = literal_eval(v)
                outcome = self._call(session, call.function, dict(call.args))
                if not outcome.executed or outcome.result is None:
                    error = outcome.message_for_agent()
                elif outcome.result.is_error:
                    error = outcome.result.text
                else:
                    content = outcome.result.text
            results.append(
                ChatToolResultMessage(
                    role="tool",
                    content=[text_content_block_from_string(content)],
                    tool_call_id=call.id,
                    tool_call=call,
                    error=error,
                )
            )
        return query, runtime, env, [*messages, *results], extra_args


def to_plain_messages(
    messages: Sequence[ChatMessage], signatures: dict[str, str | None]
) -> tuple[str, list[dict[str, Any]]]:
    """AgentDojo chat messages -> (system prompt, provider-neutral messages)."""
    system = ""
    out: list[dict[str, Any]] = []
    for msg in messages:
        role = msg["role"]
        if role == "system":
            system = get_text_content_as_str(msg["content"])
        elif role == "user":
            out.append({"role": "user", "text": get_text_content_as_str(msg["content"])})
        elif role == "assistant":
            text = get_text_content_as_str(msg["content"] or []) or None
            calls = [
                {
                    "id": c.id or "",
                    "name": c.function,
                    "args": dict(c.args),
                    "signature": signatures.get(c.id or ""),
                }
                for c in msg["tool_calls"] or []
            ]
            out.append({"role": "model", "text": text, "calls": calls})
        elif role == "tool":
            error = msg["error"]
            output = f"Error: {error}" if error else get_text_content_as_str(msg["content"])
            result = {
                "id": msg["tool_call_id"] or "",
                "name": msg["tool_call"].function,
                "output": output,
            }
            if out and out[-1]["role"] == "tool":
                out[-1]["results"].append(result)
            else:
                out.append({"role": "tool", "results": [result]})
    return system, out


class ModelLLM(BasePipelineElement):
    """AgentDojo LLM element backed by AgentWall's cached, throttled model client."""

    def __init__(self, client: ModelClient, model: str, seed: int | None = None) -> None:
        self.client = client
        self.model = model
        self.seed = seed
        self.name = model

    def query(
        self,
        query: str,
        runtime: FunctionsRuntime,
        env: Env = EmptyEnv(),
        messages: Sequence[ChatMessage] = [],
        extra_args: dict = {},
    ) -> tuple[str, FunctionsRuntime, Env, Sequence[ChatMessage], dict]:
        signatures: dict[str, str | None] = dict(extra_args.get(SIGNATURES_KEY, {}))
        system, plain = to_plain_messages(messages, signatures)
        tools = tuple(
            ToolSpec(f.name, f.description, f.parameters.model_json_schema())
            for f in runtime.functions.values()
        )
        response = self.client.generate(
            ModelRequest(self.model, system, tools, tuple(plain), seed=self.seed)
        )
        calls = []
        for c in response.calls:
            signatures[c["id"]] = c.get("signature")
            calls.append(FunctionCall(function=c["name"], args=dict(c["args"]), id=c["id"]))
        reply = ChatAssistantMessage(
            role="assistant",
            # Always a content list: AgentDojo re-runs the whole task when the content is None.
            content=[text_content_block_from_string(response.text or "")],
            tool_calls=calls or None,
        )
        return query, runtime, env, [*messages, reply], {**extra_args, SIGNATURES_KEY: signatures}


def build_pipeline(
    client: ModelClient,
    model: str,
    suite: str,
    functions: Sequence[Function],
    ablation: Ablation | None,
    max_iters: int = 15,
) -> tuple[AgentPipeline, AgentWallToolsExecutor | None]:
    """AgentDojo's standard tool-calling pipeline, with AgentWall's executor unless ``ablation`` is None."""
    llm = ModelLLM(client, model)
    executor = AgentWallToolsExecutor(suite, functions, ablation) if ablation else None
    pipeline = AgentPipeline(
        [
            SystemMessage(load_system_message(None)),
            InitQuery(),
            llm,
            ToolsExecutionLoop([executor or ToolsExecutor(), llm], max_iters=max_iters),
        ]
    )
    pipeline.name = f"{model}+agentwall-{ablation.name if ablation else 'none'}"
    return pipeline, executor
