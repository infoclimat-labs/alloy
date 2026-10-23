# Builds the forked Alloy binary (without the web UI) and the otelcrypt tool.
# Build context: the root of the repository.

# otelcrypt only depends on the Go standard library: cross-compiled, static.
FROM --platform=$BUILDPLATFORM golang:1.27-bookworm AS otelcrypt-build
ARG TARGETOS
ARG TARGETARCH
WORKDIR /src/alloy
COPY . .
RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg/mod \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -o /out/otelcrypt ./internal/cmd/otelcrypt

FROM golang:1.27-bookworm AS alloy-build
RUN apt-get update \
    && apt-get install -qy --no-install-recommends libsystemd-dev \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src/alloy
COPY . .
RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg/mod \
    cd collector && go build -tags "netgo" -o /out/alloy .

# otelcrypt in a minimal image, with curl and jq for the demo scripts.
FROM debian:bookworm-slim AS otelcrypt
RUN apt-get update \
    && apt-get install -qy --no-install-recommends ca-certificates curl jq \
    && rm -rf /var/lib/apt/lists/*
COPY --from=otelcrypt-build /out/otelcrypt /usr/local/bin/otelcrypt
ENTRYPOINT ["otelcrypt"]

FROM debian:bookworm-slim AS alloy
RUN apt-get update \
    && apt-get install -qy --no-install-recommends ca-certificates curl libsystemd0 tzdata \
    && rm -rf /var/lib/apt/lists/*
COPY --from=alloy-build /out/alloy /bin/alloy
COPY --from=otelcrypt-build /out/otelcrypt /usr/local/bin/otelcrypt
ENTRYPOINT ["/bin/alloy"]
CMD ["run", "--stability.level=experimental", "--server.http.listen-addr=0.0.0.0:12345", "/etc/alloy/config.alloy"]
