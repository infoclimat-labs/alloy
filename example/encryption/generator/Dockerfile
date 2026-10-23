FROM python:3.13-slim
RUN pip install --no-cache-dir \
    "opentelemetry-sdk>=1.45,<2" \
    "opentelemetry-exporter-otlp-proto-http>=1.45,<2"
COPY generate.py /app/generate.py
ENV OTEL_EXPORTER_OTLP_ENDPOINT=http://alloy:4318 \
    PYTHONUNBUFFERED=1
ENTRYPOINT ["python", "/app/generate.py"]
