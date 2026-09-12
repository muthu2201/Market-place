# syntax=docker/dockerfile:1.7

# Build stage.
#
# The Go version is pinned to the one in go.mod. GOTOOLCHAIN=local refuses to
# download a different compiler mid-build: an image that silently changes
# toolchain is not reproducible, and reproducibility is most of the point of
# building in a container at all.
FROM golang:1.24.0-alpine AS build

ENV CGO_ENABLED=0 GOTOOLCHAIN=local GOFLAGS=-mod=readonly

WORKDIR /src

# Dependencies first, so a source-only change does not re-download them.
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download && go mod verify

COPY . .

# -trimpath strips build-machine paths out of the binary, so panics do not leak
# the layout of the build host and two builds of the same source match.
# -s -w drop the symbol table and DWARF: smaller image, and nothing production
# needs from either, since panics still carry a usable stack.
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    go build -trimpath -ldflags="-s -w" -o /out/api     ./cmd/api && \
    go build -trimpath -ldflags="-s -w" -o /out/worker  ./cmd/worker && \
    go build -trimpath -ldflags="-s -w" -o /out/migrate ./cmd/migrate

# The running version is reported from APP_VERSION, read by the configuration
# loader, rather than stamped in with -ldflags -X. One mechanism, set by the
# deployment that knows the answer, and no build flag pointing at a variable
# that might quietly stop existing.

# The architecture rules are part of the build, not a separate opinion. An image
# cannot be produced from source that violates them.
RUN go run ./cmd/archcheck

# ---------------------------------------------------------------------------
# Runtime stage.
#
# Distroless static: no shell, no package manager, no libc. There is nothing in
# the image for an attacker who achieves code execution to pivot with, and
# nothing to patch on a CVE-treadmill either. The cost is that debugging must
# happen through logs and metrics rather than by exec-ing in — which is the
# right trade for a process that moves money.
# ---------------------------------------------------------------------------
FROM gcr.io/distroless/static-debian12:nonroot AS runtime

# Root certificates, for TLS to the payment provider, object storage and SMTP.
# Distroless ships them; this is stated so a future edit does not remove them
# and discover the consequence in production.
COPY --from=build /out/api /usr/local/bin/api
COPY --from=build /out/worker /usr/local/bin/worker
COPY --from=build /out/migrate /usr/local/bin/migrate

# nonroot (uid 65532) is baked into the base image. Declared explicitly so a
# base-image change that altered it would be a visible diff here.
USER 65532:65532

EXPOSE 8080

# No shell form: the binary is PID 1 and receives SIGTERM directly, which is
# what makes graceful shutdown work. A shell wrapper would swallow it.
ENTRYPOINT ["/usr/local/bin/api"]
