FROM gcr.io/distroless/static-debian12:nonroot

ARG TARGETARCH

COPY --chmod=0755 dist/${TARGETARCH}/ntfy-rs /usr/local/bin/ntfy-rs

WORKDIR /data

EXPOSE 2586

ENTRYPOINT ["/usr/local/bin/ntfy-rs"]
CMD ["serve", "--config", "/data/server.toml"]
