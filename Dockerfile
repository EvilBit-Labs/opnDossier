# syntax=docker/dockerfile:1
# ─────────────────────────────────────────────────────────────────────────────
# opnDossier - OPNsense configuration documentation and compliance auditing tool
#
# The binary is compiled with CGO_ENABLED=0 (static), so we can ship a
# minimal scratch image. We install CA certificates and timezone data in a
# build-platform stage so multi-arch buildx runs do not depend on target-arch
# emulation for `RUN` steps.
# ─────────────────────────────────────────────────────────────────────────────
FROM --platform=$BUILDPLATFORM alpine:3.23@sha256:5b10f432ef3da1b8d4c7eb6c487f2f5a8f096bc91145e68878dd4a5019afde11 AS runtime-assets

RUN apk --no-cache add ca-certificates tzdata

FROM scratch

ARG TARGETPLATFORM
COPY --from=runtime-assets /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=runtime-assets /usr/share/zoneinfo /usr/share/zoneinfo
COPY ${TARGETPLATFORM}/opndossier /usr/local/bin/opndossier

# Operate as a non-root user by default without needing a target-arch RUN step.
USER 65532:65532

# Config files are mounted at /data by convention
WORKDIR /data

ENTRYPOINT ["/usr/local/bin/opndossier"]
