FROM docker.io/library/rust:1.90-bookworm AS build
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY templates ./templates
COPY static ./static
RUN cargo build --release --locked && mkdir /empty-data

FROM gcr.io/distroless/cc-debian12:nonroot
LABEL org.opencontainers.image.title="Wispdeck" \
      org.opencontainers.image.description="Self-hosted authenticated Wisp proxy and administration interface" \
      org.opencontainers.image.source="https://github.com/OWNER/wispdeck" \
      org.opencontainers.image.licenses="AGPL-3.0-only"
COPY --from=build --chown=65532:65532 /build/target/release/wispdeck /usr/local/bin/wispdeck
COPY --from=build --chown=65532:65532 /empty-data /data
ENV WISPDECK_DATA_DIR=/data
ENV WISPDECK_LISTEN=0.0.0.0:8080
USER 65532:65532
VOLUME ["/data"]
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/wispdeck"]
CMD ["serve"]
