# syntax=docker/dockerfile:1

# Two ways to get the binary in, selected by the BIN_MODE build-arg:
#   compile  (default) — self-contained `docker build .`; builds the UI + binary
#                        from source.
#   prebuilt           — copies the binary GoReleaser already cross-compiled into
#                        ./dist. CI uses this so a multi-arch release doesn't
#                        recompile what GoReleaser built (compiling modernc.org/
#                        sqlite under buildx+QEMU can run many minutes per arch).
# Either way we cross-compile from $BUILDPLATFORM to TARGETOS/TARGETARCH (BuildKit
# built-ins) so the arm64 leg builds natively instead of under QEMU (CGO off).
ARG BIN_MODE=compile

# UI stage (compile mode only) — build the Ionic React console so go:embed bakes
# the real UI into the binary. $BUILDPLATFORM-pinned: the output is
# architecture-independent, so build it once natively.
FROM --platform=$BUILDPLATFORM node:22 AS ui
WORKDIR /ui
COPY internal/management/ui/package.json internal/management/ui/package-lock.json ./
RUN npm ci
COPY internal/management/ui/ ./
RUN npm run build # emits /ui/dist

# Compile stage — static (CGO-free) binary. SQLite is pure Go via
# modernc.org/sqlite, so no cgo is needed.
FROM --platform=$BUILDPLATFORM golang:1.26 AS compile
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

# Prebuilt stage — pick the matching linux/<arch> binary out of GoReleaser's
# dist/. The glob absorbs GoReleaser's microarch suffix (amd64_v1, arm64_v8.0).
# Assumes exactly ONE build variant per goarch (no goamd64/goarm64 lists in
# .goreleaser.yaml); zero matches hard-errors ("not found") — never silently wrong.
FROM scratch AS prebuilt
ARG TARGETARCH
COPY dist/turnstile_linux_${TARGETARCH}*/turnstile /out/turnstile

# Select the binary source (compile | prebuilt) for the runtime image.
FROM ${BIN_MODE} AS binaries

# Create the writable, nonroot-owned /data dir in a tiny stage so it exists
# regardless of BIN_MODE (the prebuilt stage is FROM scratch — no shell to
# mkdir/chown). $BUILDPLATFORM-pinned: a dir has no arch, so build it natively.
FROM --platform=$BUILDPLATFORM busybox AS datadir
RUN mkdir -p /data

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=binaries /out/turnstile /usr/local/bin/turnstile
COPY --from=datadir --chown=nonroot:nonroot /data /data

# SQLite database lives on a volume so it survives container restarts.
ENV DB_PATH=/data/turnstile.db
EXPOSE 8080
VOLUME ["/data"]

# The binary probes its own /health endpoint (distroless has no shell/curl).
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD ["/usr/local/bin/turnstile", "-healthcheck"]

ENTRYPOINT ["/usr/local/bin/turnstile"]
