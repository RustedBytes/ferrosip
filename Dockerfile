# syntax=docker/dockerfile:1
#
# ferrosip on Alpine: a static musl binary with mimalloc as its allocator
# (musl's own malloc costs ~35-85% more CPU per request on the stateful
# paths; measured with bench/ab.sh, see bin/ferrosip/README.md).
#
#   docker build -t ferrosip .
#   docker run --rm --network host ferrosip              # etc/docker/ferrosip.toml: udp+tcp 0.0.0.0:5060
#   docker compose up -d                                  # docker-compose.yml
#
# Build arguments:
#   FEATURES   cargo features of the ferrosip crate (default: everything + mimalloc)

# ---------------------------------------------------------------- build ---
# Rust 1.100, as rust-toolchain.toml (both change together, by hand).
FROM rust:1.100-alpine AS build
ARG FEATURES="db-sqlite db-mysql db-postgres lua http webui ai prometheus mimalloc"
# gcc and musl-dev, needed for the bundled C code (SQLite, Lua, ring), come
# with the image. No debug info; symbols stay for panic backtraces.
ENV CARGO_PROFILE_RELEASE_DEBUG=0 \
    CARGO_PROFILE_RELEASE_STRIP=debuginfo
WORKDIR /src
COPY . .
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    # Use the image's preinstalled toolchain: rust-toolchain.toml's "1.100"
    # would otherwise make rustup download a second copy.
    RUSTUP_TOOLCHAIN=$(cd / && rustup default | cut -d' ' -f1) \
    cargo build --release --locked -p ferrosip -p ferroctl \
        --no-default-features --features "${FEATURES}" \
 && install -D -m 0755 target/release/ferrosip target/release/ferroctl -t /out/

# -------------------------------------------------------------- runtime ---
# The Alpine release the Rust image is built on.
FROM alpine:3.24
# The base image already carries the CA bundle; nothing else is needed:
# the binaries are static. Run with an init (compose: `init: true`) when
# the script spawns processes (exec module).
RUN adduser -D -H -h /nonexistent -s /sbin/nologin -u 10001 ferrosip \
 && install -d -o ferrosip -g ferrosip -m 0750 /run/ferrosip \
 && install -d -m 0755 /etc/ferrosip
COPY --from=build /out/ferrosip /out/ferroctl /usr/local/bin/
COPY etc/docker /etc/ferrosip
USER ferrosip
EXPOSE 5060/udp 5060/tcp
STOPSIGNAL SIGTERM
HEALTHCHECK --interval=15s --timeout=3s --start-period=5s --retries=3 \
    CMD ["ferroctl", "-s", "/run/ferrosip/rpc.sock", "core.uptime"]
ENTRYPOINT ["ferrosip"]
# Listeners, the RPC socket and the routing come from the TOML.
CMD ["--config", "/etc/ferrosip/ferrosip.toml"]
