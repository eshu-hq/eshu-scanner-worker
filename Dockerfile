# Scanner component images: ghcr.io/eshu-hq/scanner-{image,sbom,osruntime}.
#
# One pure-Go build stage compiles the three scanner-component binaries
# (CGO_ENABLED=0: the RPM and SQLite readers are pure Go), reproducibly with
# -trimpath and an empty build id. Each final stage carries exactly one
# binary on a base with no shell and no package manager, at the path the
# eshu chart's seed init container executes:
#
#   /usr/local/bin/eshu-scanner-component-<name> seed --dest DIR --image-ref REF
#
# writes DIR/collector (this binary) and DIR/manifest.yaml with REF stamped
# into the artifact; the image cannot embed its own digest, so eshu core
# checks REF against its admission pins. With no arguments the binary serves
# one collector-sdk/v1alpha3 call over stdin and stdout.
#
# The build stage runs on the build platform and cross-compiles with
# GOOS/GOARCH, so multi-platform builds need no emulation.
#
# Base digests copied from the eshu-hq satellites resolved 2026-10-28; re-resolve
# them when bumping either base.
ARG GO_IMAGE=golang:1.26.10-alpine@sha256:a2012b4a1d1f9f7e9f44e0d39b805a901e856b1dd80b4e6ee4338db547050308
ARG RUNTIME_IMAGE=gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab

FROM --platform=$BUILDPLATFORM ${GO_IMAGE} AS build
ARG TARGETOS=linux
ARG TARGETARCH
ARG SCANNER_VERSION=dev
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY go/ ./go/
RUN for name in image sbom osruntime; do \
      CGO_ENABLED=0 GOOS="${TARGETOS}" GOARCH="${TARGETARCH}" go build -trimpath -buildvcs=false \
        -ldflags="-s -w -buildid= -X github.com/eshu-hq/eshu-scanner-worker/go/internal/buildinfo.Version=${SCANNER_VERSION}" \
        -o "/out/eshu-scanner-component-${name}" "./go/cmd/scanner-component-${name}" || exit 1; \
    done

FROM ${RUNTIME_IMAGE} AS scanner-image
COPY --from=build /out/eshu-scanner-component-image /usr/local/bin/eshu-scanner-component-image
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/eshu-scanner-component-image"]

FROM ${RUNTIME_IMAGE} AS scanner-sbom
COPY --from=build /out/eshu-scanner-component-sbom /usr/local/bin/eshu-scanner-component-sbom
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/eshu-scanner-component-sbom"]

FROM ${RUNTIME_IMAGE} AS scanner-osruntime
COPY --from=build /out/eshu-scanner-component-osruntime /usr/local/bin/eshu-scanner-component-osruntime
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/eshu-scanner-component-osruntime"]
