# Scanner component images: ghcr.io/eshu-hq/scanner-{image,sbom,osruntime,go-reachability}.
#
# One pure-Go build stage compiles the four scanner-component binaries
# (CGO_ENABLED=0: the RPM and SQLite readers are pure Go), reproducibly with
# -trimpath and an empty build id. Each final stage carries one component
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
ARG GO_IMAGE=golang:1.26.11-alpine@sha256:ae52b5bc6ed045a9ed26ab03dc19327a802a9cc9aa8b27ed57f5c6b60579b0bb
ARG RUNTIME_IMAGE=gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab

FROM --platform=$BUILDPLATFORM ${GO_IMAGE} AS build
ARG TARGETOS=linux
ARG TARGETARCH
ARG SCANNER_VERSION=dev
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY go/ ./go/
RUN for name in image sbom osruntime go-reachability; do \
      CGO_ENABLED=0 GOOS="${TARGETOS}" GOARCH="${TARGETARCH}" go build -trimpath -buildvcs=false \
        -ldflags="-s -w -buildid= -X github.com/eshu-hq/eshu-scanner-worker/go/internal/buildinfo.Version=${SCANNER_VERSION}" \
        -o "/out/eshu-scanner-component-${name}" "./go/cmd/scanner-component-${name}" || exit 1; \
    done
RUN CGO_ENABLED=0 GOOS="${TARGETOS}" GOARCH="${TARGETARCH}" go build -trimpath -buildvcs=false \
      -ldflags="-s -w -buildid=" -o /out/govulncheck golang.org/x/vuln/cmd/govulncheck

# The Go toolchain go-reachability seeds. It is for the target platform, and with
# no RUN it needs no emulation.
FROM --platform=$TARGETPLATFORM ${GO_IMAGE} AS toolchain

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

# go-reachability also carries one Go toolchain and one govulncheck, both pinned:
# the toolchain by GO_IMAGE, the scanner by go.sum through go.mod's tool directive.
# The seed step copies them to DIR/toolchain beside the collector, which runs them
# as its own children in the Eshu worker container and takes git from that image.
# The GOROOT is trimmed of test, api, doc, and misc; go list needs src, pkg, and lib.
FROM ${RUNTIME_IMAGE} AS scanner-go-reachability
COPY --from=build /out/eshu-scanner-component-go-reachability /usr/local/bin/eshu-scanner-component-go-reachability
COPY --from=build /out/govulncheck /usr/local/bin/govulncheck
COPY --from=toolchain /usr/local/go/VERSION /usr/local/go/VERSION
COPY --from=toolchain /usr/local/go/go.env /usr/local/go/go.env
COPY --from=toolchain /usr/local/go/bin /usr/local/go/bin
COPY --from=toolchain /usr/local/go/src /usr/local/go/src
COPY --from=toolchain /usr/local/go/pkg /usr/local/go/pkg
COPY --from=toolchain /usr/local/go/lib /usr/local/go/lib
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/eshu-scanner-component-go-reachability"]
