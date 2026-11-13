# agentslam container image (linux/amd64 and linux/arm64).
# The build stage runs natively on the build host and cross-compiles a static
# musl binary for the target platform, so no Rust compiles under QEMU. reqwest
# uses rustls with webpki roots and rusqlite is bundled: no OpenSSL, no libc,
# no CA files needed at runtime. BuildKit builds only the stage TARGETARCH needs.
FROM --platform=$BUILDPLATFORM ghcr.io/rust-cross/rust-musl-cross:x86_64-musl AS build-amd64
ENV RUST_TARGET=x86_64-unknown-linux-musl

FROM --platform=$BUILDPLATFORM ghcr.io/rust-cross/rust-musl-cross:aarch64-musl AS build-arm64
ENV RUST_TARGET=aarch64-unknown-linux-musl

FROM build-${TARGETARCH} AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY web ./web
COPY migrations ./migrations
RUN cargo build --release --locked --target "$RUST_TARGET" \
 && cp "target/$RUST_TARGET/release/agentslam" /agentslam

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /agentslam /usr/local/bin/agentslam
USER nonroot
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/agentslam"]
CMD ["serve", "--config", "/etc/agentslam/agentslam.toml"]
