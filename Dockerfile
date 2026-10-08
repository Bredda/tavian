# syntax=docker/dockerfile:1

# Build any binary of the repo: --build-arg CMD=tavian (default) or CMD=mockllm.
FROM golang:1.26 AS build
ARG CMD=tavian
ARG VERSION=dev
ARG COMMIT=
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY . .
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 go build -trimpath \
      -ldflags "-s -w -X github.com/bredda/tavian/internal/version.Version=${VERSION} -X github.com/bredda/tavian/internal/version.Commit=${COMMIT}" \
      -o /out/app ./cmd/${CMD}

# Static binary, no shell, no package manager, non-root.
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/app /app
ENV TAVIAN_CONFIG=/etc/tavian/tavian.yaml
USER 65532:65532
ENTRYPOINT ["/app"]
CMD ["serve"]
