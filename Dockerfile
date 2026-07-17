# syntax=docker/dockerfile:1.7

ARG NODE_IMAGE=node:24.13.0-alpine3.23
ARG GO_IMAGE=golang:1.26.5-alpine3.23
ARG RUNTIME_IMAGE=alpine:3.23.3

FROM ${NODE_IMAGE} AS web-build
WORKDIR /src
COPY web/package.json web/package-lock.json ./web/
RUN --mount=type=cache,target=/root/.npm \
    cd web && npm ci --ignore-scripts --no-audit --no-fund
COPY web ./web
RUN mkdir -p internal/webui && cd web && npm run build

FROM ${GO_IMAGE} AS go-build
WORKDIR /src
RUN apk add --no-cache ca-certificates
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY . .
COPY --from=web-build /src/internal/webui/static ./internal/webui/static
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags='-s -w -buildid=' -o /out/aera-cloud ./cmd/aera-cloud && \
    CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags='-s -w -buildid=' -o /out/aera-cloud-admin ./cmd/aera-cloud-admin

FROM ${RUNTIME_IMAGE} AS runtime
RUN apk add --no-cache ca-certificates tzdata && \
    addgroup -S -g 65532 agentera && \
    adduser -S -D -H -u 65532 -G agentera agentera
COPY --from=go-build --chown=65532:65532 /out/aera-cloud /usr/local/bin/aera-cloud
COPY --from=go-build --chown=65532:65532 /out/aera-cloud-admin /usr/local/bin/aera-cloud-admin
USER 65532:65532
EXPOSE 8086
ENTRYPOINT ["/usr/local/bin/aera-cloud"]
