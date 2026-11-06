"""Telemetry sinks: send every gateway decision to OpenTelemetry or to structured JSON logs.

Sinks receive the same event dicts the audit log stores (``tool_call``, ``tool_hidden``), so telemetry
never sees more than the audit log does. Configure in the gateway YAML::

    telemetry:
      json_log: true                       # one JSON line per decision on stderr
      otel: {exporter: console | otlp, endpoint: http://localhost:4318, service_name: agentwall}

OpenTelemetry needs ``pip install -e ".[otel]"`` (and ``opentelemetry-exporter-otlp`` for ``otlp``).
Logs go to stderr because in proxy mode stdout carries the MCP protocol.
"""

from __future__ import annotations

import json
import sys
import time
from typing import Any, Protocol, TextIO

TRACKED_EVENTS = ("tool_call", "tool_hidden")


class TelemetrySink(Protocol):
    def emit(self, event: dict[str, Any]) -> None: ...


class JsonLogTelemetry:
    """Structured logs: one compact JSON object per decision."""

    def __init__(self, stream: TextIO | None = None) -> None:
        self.stream = stream or sys.stderr

    def emit(self, event: dict[str, Any]) -> None:
        if event.get("event") not in TRACKED_EVENTS:
            return
        record = {
            "ts": event.get("ts", round(time.time(), 3)),
            "event": event["event"],
            "session": event.get("session"),
            "tool": event.get("tool"),
            "action": event.get("action", event.get("state")),
            "executed": event.get("executed"),
            "rules": event.get("rules"),
            "redactions": len(event.get("redactions") or []),
            "quarantined": event.get("quarantined"),
            "overhead_ms": event.get("overhead_ms"),
        }
        self.stream.write(json.dumps({k: v for k, v in record.items() if v is not None}) + "\n")
        self.stream.flush()


class OTelTelemetry:
    """A span per decision, a decision counter and an overhead histogram.

    Uses the global tracer and meter providers unless given ones (see :func:`setup_otel`).
    """

    def __init__(
        self,
        service_name: str = "agentwall",
        tracer_provider: Any = None,
        meter_provider: Any = None,
    ) -> None:
        from opentelemetry import metrics, trace

        self._tracer = (tracer_provider or trace.get_tracer_provider()).get_tracer(service_name)
        meter = (meter_provider or metrics.get_meter_provider()).get_meter(service_name)
        self._decisions = meter.create_counter(
            "agentwall.decisions", description="Tool-call decisions by action"
        )
        self._hidden = meter.create_counter(
            "agentwall.tools_hidden", description="Tools hidden by the manifest registry"
        )
        self._overhead = meter.create_histogram(
            "agentwall.overhead", unit="ms", description="Gateway time per tool call"
        )

    def emit(self, event: dict[str, Any]) -> None:
        kind = event.get("event")
        if kind == "tool_hidden":
            self._hidden.add(
                1,
                {
                    "agentwall.tool": str(event.get("tool")),
                    "agentwall.state": str(event.get("state")),
                },
            )
            return
        if kind != "tool_call":
            return
        tool = str(event.get("tool"))
        server = str(event.get("server"))
        action = str(event.get("action"))
        attrs = {"agentwall.action": action, "agentwall.server": server}
        self._decisions.add(1, attrs)
        overhead = float(event.get("overhead_ms") or 0.0)
        self._overhead.record(overhead, attrs)
        end = time.time_ns()
        span = self._tracer.start_span(
            "agentwall.tool_call",
            start_time=end - int(overhead * 1_000_000),
            attributes={
                **attrs,
                "agentwall.tool": tool,
                "agentwall.session": str(event.get("session")),
                "agentwall.executed": bool(event.get("executed")),
                "agentwall.rules": ",".join(event.get("rules") or []),
                "agentwall.redactions": len(event.get("redactions") or []),
                "agentwall.quarantined": str(event.get("quarantined") or ""),
                "agentwall.audit_seq": int(event.get("seq") or 0),
            },
        )
        if action in ("block", "ask"):
            from opentelemetry.trace import Status, StatusCode

            span.set_status(
                Status(StatusCode.ERROR, f"{action}: {','.join(event.get('rules') or [])}")
            )
        span.end(end_time=end)


def setup_otel(
    exporter: str = "console", endpoint: str | None = None, service_name: str = "agentwall"
) -> OTelTelemetry:
    """Install SDK providers with a console or OTLP/HTTP exporter and return a sink using them."""
    from opentelemetry.sdk.metrics import MeterProvider
    from opentelemetry.sdk.metrics.export import (
        ConsoleMetricExporter,
        PeriodicExportingMetricReader,
    )
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor, ConsoleSpanExporter

    resource = Resource.create({"service.name": service_name})
    if exporter == "otlp":
        try:
            from opentelemetry.exporter.otlp.proto.http.metric_exporter import OTLPMetricExporter
            from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
        except ImportError as exc:
            raise RuntimeError(
                "pip install opentelemetry-exporter-otlp for the otlp exporter"
            ) from exc
        base = (endpoint or "http://localhost:4318").rstrip("/")
        span_exporter: Any = OTLPSpanExporter(endpoint=f"{base}/v1/traces")
        metric_exporter: Any = OTLPMetricExporter(endpoint=f"{base}/v1/metrics")
    elif exporter == "console":
        span_exporter = ConsoleSpanExporter(out=sys.stderr)
        metric_exporter = ConsoleMetricExporter(out=sys.stderr)
    else:
        raise ValueError(f"unknown OpenTelemetry exporter {exporter!r}; use console or otlp")
    tracer_provider = TracerProvider(resource=resource)
    tracer_provider.add_span_processor(BatchSpanProcessor(span_exporter))
    meter_provider = MeterProvider(
        resource=resource, metric_readers=[PeriodicExportingMetricReader(metric_exporter)]
    )
    return OTelTelemetry(service_name, tracer_provider, meter_provider)


def sinks_from_config(raw: dict[str, Any] | None) -> tuple[TelemetrySink, ...]:
    raw = raw or {}
    sinks: list[TelemetrySink] = []
    if raw.get("json_log"):
        sinks.append(JsonLogTelemetry())
    otel = raw.get("otel")
    if otel:
        otel = otel if isinstance(otel, dict) else {}
        sinks.append(
            setup_otel(
                otel.get("exporter", "console"),
                otel.get("endpoint"),
                otel.get("service_name", "agentwall"),
            )
        )
    return tuple(sinks)
