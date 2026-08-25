# syntax=docker/dockerfile:1

# Stage 1 — build the Ionic React management console, so the image serves the
# real UI (not the placeholder). Built fresh here for reproducibility rather than
# relying on a local dist. Pinned to the builder platform: the output is
# architecture-independent, so building it once natively avoids emulating npm
# under QEMU for the arm64 leg of a multi-arch build.
FROM --platform=$BUILDPLATFORM node:22 AS ui
WORKDIR /ui
COPY internal/management/ui/package.json internal/management/ui/package-lock.json ./
RUN npm ci
COPY internal/management/ui/ ./
RUN npm run build # emits /ui/dist

# Stage 2 — compile a static (CGO-free) binary. SQLite is pure Go via
# modernc.org/sqlite, so no cgo is needed. Pinned to the builder platform and
# cross-compiled to TARGETOS/TARGETARCH (BuildKit built-ins), so the arm64 leg
# of a multi-arch build compiles natively instead of running go under QEMU. For
# a local single-arch build these equal the host, so it's a no-op.
FROM --platform=$BUILDPLATFORM golang:1.26 AS build
WORKDIR /src

# Module proxy. Defaults to Go's normal public proxy; override only when needed,
# e.g. `--build-arg GOPROXY=direct` to build behind a network that intercepts
# proxy.golang.org. Not hardcoded to direct so normal/CI builds use the proxy.
ARG GOPROXY=https://proxy.golang.org,direct
ENV GOPROXY=${GOPROXY}

# Cache module downloads separately from the source.
COPY go.mod go.sum ./
RUN go mod download

COPY . .
# Overlay the freshly built console so go:embed bakes it into the binary.
COPY --from=ui /ui/dist ./internal/management/ui/dist

ARG VERSION=docker
ARG COMMIT=none
ARG BUILD_DATE=unknown
ARG TARGETOS
ARG TARGETARCH
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -trimpath \
    -ldflags "-s -w -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.date=${BUILD_DATE}" \
    -o /out/turnstile ./cmd/turnstile
# Create the data dir here so it can be copied with the right ownership below
# (the distroless runtime has no shell to mkdir/chown).
RUN mkdir /data

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/turnstile /usr/local/bin/turnstile
COPY --from=build --chown=nonroot:nonroot /data /data

# SQLite database lives on a volume so it survives container restarts.
ENV DB_PATH=/data/turnstile.db
EXPOSE 8080
VOLUME ["/data"]

# The binary probes its own /health endpoint (distroless has no shell/curl).
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD ["/usr/local/bin/turnstile", "-healthcheck"]

ENTRYPOINT ["/usr/local/bin/turnstile"]
