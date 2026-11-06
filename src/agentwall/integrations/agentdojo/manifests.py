"""AgentWall manifests for AgentDojo suites.

AgentDojo gives each suite one flat toolset; AgentWall reasons about servers. The tools are grouped into
pseudo-servers by who writes the data they return, using one rule that was fixed before any run and is
not adjusted after seeing results:

- A tool whose output can contain text written by someone other than the user (incoming transactions,
  files from outside, messages, web pages) is **untrusted**.
- A tool that returns only the user's own state (balance, own account data, payments the user set up)
  is **trusted**.
- Account and payment data is **sensitive**; files are **internal**.

Capability classes and argument roles follow the docstrings: tools that move money out are ``egress``;
tools that change stored state are ``write``; everything else is ``read``. Control arguments are the
ones that pick a target or action: recipients, amounts, ids, passwords, address fields. Free-text
fields such as ``subject`` are data.
"""

from __future__ import annotations

from dataclasses import dataclass

# (capability, control args, data args)
ToolRole = tuple[str, tuple[str, ...], tuple[str, ...]]


@dataclass(frozen=True)
class ServerSpec:
    label: tuple[str, str]  # (integrity, confidentiality)
    tools: dict[str, ToolRole]


SUITE_SERVERS: dict[str, dict[str, ServerSpec]] = {
    "banking": {
        "bank": ServerSpec(
            ("trusted", "sensitive"),
            {
                "get_iban": ("read", (), ()),
                "get_balance": ("read", (), ()),
                "get_user_info": ("read", (), ()),
                # Scheduled transactions are payments the user set up themselves.
                "get_scheduled_transactions": ("read", (), ()),
            },
        ),
        "bank_history": ServerSpec(
            # Incoming transactions carry a subject line written by the sender.
            ("untrusted", "sensitive"),
            {"get_most_recent_transactions": ("read", (), ())},
        ),
        "files": ServerSpec(
            # Bills and notices arrive from outside.
            ("untrusted", "internal"),
            {"read_file": ("read", ("file_path",), ())},
        ),
        "payments": ServerSpec(
            ("trusted", "public"),
            {
                "send_money": ("egress", ("recipient", "amount"), ("subject", "date")),
                "schedule_transaction": (
                    "egress",
                    ("recipient", "amount"),
                    ("subject", "date", "recurring"),
                ),
                "update_scheduled_transaction": (
                    "write",
                    ("id", "recipient", "amount"),
                    ("subject", "date", "recurring"),
                ),
            },
        ),
        "account": ServerSpec(
            ("trusted", "public"),
            {
                "update_password": ("write", ("password",), ()),
                "update_user_info": (
                    "write",
                    ("first_name", "last_name", "street", "city"),
                    (),
                ),
            },
        ),
    },
}

# Picked before any run to cover the three ways the banking attacks hurt the user: leaking data through a
# payment's subject, redirecting an existing payment, and taking over the account.
DEFAULT_INJECTION_TASKS: dict[str, tuple[str, ...]] = {
    "banking": ("injection_task_0", "injection_task_4", "injection_task_7"),
}


def server_of(suite: str) -> dict[str, str]:
    """Tool name -> pseudo-server name."""
    return {tool: server for server, spec in SUITE_SERVERS[suite].items() for tool in spec.tools}
