# Docker Hub images, pulled through Google's mirror: GitHub's shared runners
# hit Docker Hub's anonymous pull limit (429), which the mirror is not subject
# to. Same images, same digests (checked 2026-10-09).
FROM --platform=$BUILDPLATFORM mirror.gcr.io/lukemathwalker/cargo-chef:latest-rust-slim-trixie@sha256:38dfdbf4fda95c516f873f33032e490baa988b75f7d83c7d12f788f770785b36 AS chef
WORKDIR /build

FROM --platform=$BUILDPLATFORM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path /recipe.json

FROM --platform=$BUILDPLATFORM chef AS builder
ARG TARGETPLATFORM
RUN case "${TARGETPLATFORM}" in \
    "linux/arm64") echo "aarch64-unknown-linux-gnu" > /target.txt && echo "-C linker=aarch64-linux-gnu-gcc" > /flags.txt ;; \
    "linux/amd64") echo "x86_64-unknown-linux-gnu" > /target.txt && echo "-C linker=x86_64-linux-gnu-gcc" > /flags.txt ;; \
    *) exit 1 ;; \
    esac
RUN export DEBIAN_FRONTEND=noninteractive && \
    apt-get update && \
    apt-get install -yq --no-install-recommends build-essential libclang-19-dev \
    g++-aarch64-linux-gnu binutils-aarch64-linux-gnu \
    g++-x86-64-linux-gnu binutils-x86-64-linux-gnu
RUN rustup target add "$(cat /target.txt)"
COPY --from=planner /recipe.json /recipe.json
# inbuxa: [patch.crates-io] points sieve-rs at vendor/, and the recipe only
# carries the workspace's own manifests, so cooking the dependencies needs the
# vendored crate itself (the context allows it since #27; this puts it here).
COPY vendor/ vendor/
RUN RUSTFLAGS="$(cat /flags.txt)" cargo chef cook --target "$(cat /target.txt)" --release --no-default-features --features "sqlite postgres mysql rocks s3 redis azure nats" --recipe-path /recipe.json
COPY . .
# inbuxa: the commit being built, for /.well-known/source. The context has no
# .git, so the release workflow passes it; a build without it serves no
# source document.
ARG INBUXA_REVISION=""
ENV INBUXA_REVISION=${INBUXA_REVISION}
RUN RUSTFLAGS="$(cat /flags.txt)" cargo build --target "$(cat /target.txt)" --release -p inbuxa --no-default-features --features "sqlite postgres mysql rocks s3 redis azure nats"
RUN mv "/build/target/$(cat /target.txt)/release" "/output"

# inbuxa: migrations spec, MG-4: the inbuxa-migrate the server runs, a
# release pinned by its checksums
FROM --platform=$BUILDPLATFORM mirror.gcr.io/library/debian:trixie-slim AS migrate
ARG TARGETPLATFORM
ARG MIGRATE_VERSION=27.1-rc.8
ARG MIGRATE_SHA256_AMD64=a8a880111c583fd190f70852ed64fc2794cbc085ef3623f90193e168d7cbc75d
ARG MIGRATE_SHA256_ARM64=05b7402a61e0203b3bb4a5e967cf3da4d1ace64c8fafe78eaa64157d2abea2c8
RUN export DEBIAN_FRONTEND=noninteractive && \
    apt-get update && \
    apt-get install -yq --no-install-recommends ca-certificates curl && \
    case "${TARGETPLATFORM}" in \
    "linux/arm64") arch=arm64 sum="${MIGRATE_SHA256_ARM64}" ;; \
    "linux/amd64") arch=amd64 sum="${MIGRATE_SHA256_AMD64}" ;; \
    *) exit 1 ;; \
    esac && \
    curl -fsSL -o /migrate.tar.gz "https://github.com/inbuxa/inbuxa-migrate/releases/download/v${MIGRATE_VERSION}/inbuxa-migrate-linux-${arch}.tar.gz" && \
    echo "${sum}  /migrate.tar.gz" | sha256sum -c - && \
    mkdir /migrate && tar -xzf /migrate.tar.gz -C /migrate

FROM mirror.gcr.io/library/debian:trixie-slim
RUN export DEBIAN_FRONTEND=noninteractive && \
    apt-get update && \
    apt-get install -yq --no-install-recommends ca-certificates curl libcap2-bin && \
    rm -rf /var/lib/apt/lists/* && \
    groupadd -r -g 2000 inbuxa && \
    useradd -r -u 2000 -g 2000 -s /usr/sbin/nologin -M inbuxa && \
    mkdir -p /etc/inbuxa /var/lib/inbuxa && \
    chown inbuxa:inbuxa /etc/inbuxa /var/lib/inbuxa
COPY --from=builder --chmod=0755 /output/inbuxa /usr/local/bin/inbuxa
COPY --from=migrate --chmod=0755 /migrate/inbuxa-migrate /usr/local/bin/inbuxa-migrate
COPY --from=migrate /migrate/LICENSES /usr/share/doc/inbuxa-migrate/LICENSES
COPY --from=migrate /migrate/README.md /usr/share/doc/inbuxa-migrate/README.md
RUN setcap 'cap_net_bind_service=+ep' /usr/local/bin/inbuxa
USER inbuxa
WORKDIR /var/lib/inbuxa
VOLUME ["/etc/inbuxa", "/var/lib/inbuxa"]
EXPOSE	443 25 110 587 465 143 993 995 4190 8080
ENV INBUXA_HEALTHCHECK_URL=https://127.0.0.1:443/healthz/live
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
    CMD curl -fsSk -H "X-Forwarded-For: 127.0.0.1" "$INBUXA_HEALTHCHECK_URL" || curl -fsS -H "X-Forwarded-For: 127.0.0.1" http://127.0.0.1:8080/healthz/live || exit 1
ENTRYPOINT ["/usr/local/bin/inbuxa"]
CMD ["--config", "/etc/inbuxa/config.json"]
