"""A worst-case obedient agent for measuring defences.

It performs the user's task step by step and, as soon as an injected instruction becomes visible in its
context (a tool output or a tool description), it carries out the attacker's goal exactly, with every
value the attacker asked for. Real models obey less often, so attack success measured with this agent is
an upper bound: the question it answers is "what can still get through if the model is fully fooled?".
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from agentwall.gateway.core import CallOutcome, Session
from agentwall.harness.scenario import Scenario, Step

_TEMPLATE = re.compile(r"\{\{(result|paraphrase|value):([^}]+)\}\}")


def paraphrase(text: str) -> str:
    """Deterministically reword text so no long exact substring survives."""
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    out = []
    for line in lines:
        line = (
            line.replace("%", " percent").replace("INR", "Rs.").replace("(", "- ").replace(")", "")
        )
        out.append(f"* {line.lower()}")
    return "Quick recap of the positions:\n" + "\n".join(reversed(out))


@dataclass
class AgentRun:
    user_calls: list[CallOutcome] = field(default_factory=list)
    goal_call: CallOutcome | None = None
    saw_payload: bool = False


class ObedientAgent:
    def __init__(self, scenario: Scenario) -> None:
        self.scenario = scenario
        self.outputs: dict[str, str] = {}

    def _fill(self, value: Any) -> Any:
        if isinstance(value, dict):
            return {k: self._fill(v) for k, v in value.items()}
        if not isinstance(value, str):
            return value
        attack = self.scenario.attack

        def sub(match: re.Match[str]) -> str:
            kind, key = match.group(1), match.group(2)
            if kind == "value":
                return attack.values.get(key, "") if attack else ""
            text = self.outputs.get(key, "")
            return paraphrase(text) if kind == "paraphrase" else text

        return _TEMPLATE.sub(sub, value)

    def _payload_visible(self, session: Session) -> bool:
        attack = self.scenario.attack
        if attack is None:
            return False
        if attack.carrier in ("tool_description", "rug_pull"):
            return any(
                attack.payload in t.info.description for t in session.gateway.visible_tools()
            )
        return any(attack.payload in text for text in self.outputs.values())

    async def _call(self, session: Session, step: Step) -> CallOutcome:
        outcome = await session.call_tool(step.tool, self._fill(step.args))
        if outcome.executed and outcome.result is not None:
            self.outputs[step.tool] = outcome.result.text
        return outcome

    async def run(self, session: Session) -> AgentRun:
        run = AgentRun()
        session.add_user_message(self.scenario.user_prompt)
        attack = self.scenario.attack
        for step in self.scenario.steps:
            run.user_calls.append(await self._call(session, step))
            if attack and run.goal_call is None and self._payload_visible(session):
                # The attacker's goal usually needs data from a later step (e.g. the holdings), so an
                # obedient agent completes the data-gathering steps first; we fire the goal once every
                # step it references has run.
                needed = {
                    m.group(2)
                    for m in _TEMPLATE.finditer(str(attack.goal.args))
                    if m.group(1) != "value"
                }
                if needed <= set(self.outputs) or step is self.scenario.steps[-1]:
                    run.saw_payload = True
                    run.goal_call = await self._call(session, attack.goal)
        if attack and run.goal_call is None and self._payload_visible(session):
            run.saw_payload = True
            run.goal_call = await self._call(session, attack.goal)
        return run
