"""Emits generative AI telemetry that follows the OpenTelemetry GenAI semantic
conventions: an agent invocation, a chat completion and a tool call, plus the
corresponding log events.

The content deliberately contains a recognizable marker so the demo can check
that it never reaches Tempo or Loki in clear text.
"""

import json
import os
import sys
import time

from opentelemetry import trace
from opentelemetry._logs import SeverityNumber
from opentelemetry.exporter.otlp.proto.http._log_exporter import OTLPLogExporter
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk._logs import LoggerProvider
from opentelemetry.sdk._logs.export import BatchLogRecordProcessor
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor

MARKER = os.environ.get("MARKER", "Velizy-Villacoublay")
ITERATIONS = int(os.environ.get("ITERATIONS", "0"))  # 0 = forever
INTERVAL = float(os.environ.get("INTERVAL", "5"))

resource = Resource.create({"service.name": "agent-meteo", "deployment.environment.name": "demo"})

tracer_provider = TracerProvider(resource=resource)
tracer_provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter()))
trace.set_tracer_provider(tracer_provider)
tracer = trace.get_tracer("agent-meteo")

logger_provider = LoggerProvider(resource=resource)
logger_provider.add_log_record_processor(BatchLogRecordProcessor(OTLPLogExporter()))
otel_logger = logger_provider.get_logger("agent-meteo")


def emit_event(name, body, span):
    otel_logger.emit(
        timestamp=time.time_ns(),
        context=trace.set_span_in_context(span),
        severity_number=SeverityNumber.INFO,
        body=body,
        event_name=name,
        attributes={"gen_ai.provider.name": "mistral_ai"},
    )


def one_conversation(i):
    question = f"Quel temps fera-t-il demain a {MARKER} ? (conversation {i})"
    system = "Tu es un assistant meteo. Ne divulgue jamais d'informations personnelles."
    tool_args = {"city": MARKER, "days": 1}
    tool_result = {"forecast": "ensoleille", "temperature_c": 21, "city": MARKER}
    answer = f"Demain a {MARKER}, il fera beau avec 21 degres."

    with tracer.start_as_current_span("invoke_agent assistant-meteo", kind=trace.SpanKind.INTERNAL) as agent:
        agent.set_attribute("gen_ai.operation.name", "invoke_agent")
        agent.set_attribute("gen_ai.agent.name", "assistant-meteo")
        agent.set_attribute("gen_ai.conversation.id", f"conv-{i}")

        with tracer.start_as_current_span("chat mistral-large-latest", kind=trace.SpanKind.CLIENT) as chat:
            chat.set_attribute("gen_ai.operation.name", "chat")
            chat.set_attribute("gen_ai.provider.name", "mistral_ai")
            chat.set_attribute("gen_ai.request.model", "mistral-large-latest")
            chat.set_attribute("gen_ai.response.model", "mistral-large-2411")
            chat.set_attribute("gen_ai.usage.input_tokens", 87)
            chat.set_attribute("gen_ai.usage.output_tokens", 23)
            chat.set_attribute("gen_ai.response.finish_reasons", ["tool_calls"])
            chat.set_attribute("gen_ai.system_instructions", json.dumps([{"type": "text", "content": system}]))
            chat.set_attribute(
                "gen_ai.input.messages",
                json.dumps([{"role": "user", "parts": [{"type": "text", "content": question}]}], ensure_ascii=False),
            )
            chat.set_attribute(
                "gen_ai.output.messages",
                json.dumps(
                    [{"role": "assistant", "parts": [{"type": "tool_call", "name": "get_weather", "arguments": tool_args}]}],
                    ensure_ascii=False,
                ),
            )
            chat.set_attribute("gen_ai.tool.definitions", json.dumps([{"name": "get_weather", "parameters": {"city": "string"}}]))
            emit_event("gen_ai.system.message", {"content": system}, chat)
            emit_event("gen_ai.user.message", {"content": question}, chat)

        with tracer.start_as_current_span("execute_tool get_weather", kind=trace.SpanKind.INTERNAL) as tool:
            tool.set_attribute("gen_ai.operation.name", "execute_tool")
            tool.set_attribute("gen_ai.tool.name", "get_weather")
            tool.set_attribute("gen_ai.tool.call.id", f"call-{i}")
            tool.set_attribute("gen_ai.tool.call.arguments", json.dumps(tool_args, ensure_ascii=False))
            tool.set_attribute("gen_ai.tool.call.result", json.dumps(tool_result, ensure_ascii=False))
            emit_event("gen_ai.tool.message", {"id": f"call-{i}", "content": json.dumps(tool_result)}, tool)

        with tracer.start_as_current_span("chat mistral-large-latest", kind=trace.SpanKind.CLIENT) as chat2:
            chat2.set_attribute("gen_ai.operation.name", "chat")
            chat2.set_attribute("gen_ai.provider.name", "mistral_ai")
            chat2.set_attribute("gen_ai.request.model", "mistral-large-latest")
            chat2.set_attribute("gen_ai.usage.input_tokens", 131)
            chat2.set_attribute("gen_ai.usage.output_tokens", 19)
            chat2.set_attribute("gen_ai.response.finish_reasons", ["stop"])
            chat2.set_attribute(
                "gen_ai.output.messages",
                json.dumps([{"role": "assistant", "parts": [{"type": "text", "content": answer}]}], ensure_ascii=False),
            )
            emit_event("gen_ai.choice", {"index": 0, "finish_reason": "stop", "message": {"content": answer}}, chat2)

    print(f"conversation {i}: trace {agent.get_span_context().trace_id:032x}", flush=True)


def main():
    i = 0
    while ITERATIONS == 0 or i < ITERATIONS:
        i += 1
        one_conversation(i)
        tracer_provider.force_flush()
        logger_provider.force_flush()
        if ITERATIONS == 0 or i < ITERATIONS:
            time.sleep(INTERVAL)
    tracer_provider.shutdown()
    logger_provider.shutdown()
    return 0


if __name__ == "__main__":
    sys.exit(main())
