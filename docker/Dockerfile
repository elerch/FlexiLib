FROM debian:bookworm

RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates && \
    rm -rf /var/lib/apt/lists/*

COPY flexilib /usr/local/bin/flexilib

ENTRYPOINT ["/usr/local/bin/flexilib"]
